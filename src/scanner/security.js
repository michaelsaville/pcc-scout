const { execFile } = require('child_process');

const KEY_PORTS = [21, 22, 23, 80, 443, 445, 3389, 5900];

// NSE scripts run on the same port sweep — nmap auto-matches each script to
// the appropriate port(s) it cares about. Any script nmap doesn't recognize
// is skipped with a warning, not a scan failure. Keeping this list narrow
// to avoid fingerprinting delays from heavier scripts.
const NSE_SCRIPTS = [
  'smb-os-discovery',        // 445 — OS + domain details even without creds
  'smb-enum-shares',         // 445 — anonymous-reachable shares
  'smb-vuln-ms17-010',       // 445 — EternalBlue (WannaCry) vuln check
  'snmp-info',               // 161/udp — community 'public' default
  'ssl-enum-ciphers',        // 443 — weak ciphers + protocol versions
  'http-security-headers',   // 80/443 — HSTS/CSP/X-Frame-Options etc.
  'rdp-ntlm-info',           // 3389 — leaks Windows version + domain
];

const NSE_SCRIPT_TIMEOUT = '60s';

const EOL_OS_PATTERNS = [
  /windows xp/i,
  /windows 7(?!\.\d)/i,  // Windows 7 but not Windows 7x something
  /windows server 2003/i,
  /windows server 2008(?! r2)/i,
  /windows server 2008 r2/i,
];

const FLAG_RULES = [
  { port: 23, flag: 'Telnet enabled' },
  { port: 3389, flag: 'RDP exposed' },
  { port: 5900, flag: 'VNC exposed' },
];

/**
 * Run security flag analysis on discovered devices.
 * @param {Array} devices - device array from network scanner
 * @param {Function} onProgress - callback
 * @returns {Promise<Array>} devices with flags[] attached
 */
async function analyzeDevices(devices, onProgress) {
  const aliveDevices = devices.filter(d => d.is_alive);

  if (aliveDevices.length === 0) return devices;

  onProgress({
    phase: 'Checking security flags...',
    message: `Scanning ${aliveDevices.length} devices for security issues`,
    percent: 55,
  });

  const ips = aliveDevices.map(d => d.ip);
  const { ports: portResults, nse: nseResults } = await scanPorts(ips, onProgress);

  // Apply flags to each device
  let processed = 0;
  for (const device of aliveDevices) {
    device.flags = [];
    device.open_ports = [];
    device.nse = nseResults[device.ip] || {};

    const ports = portResults[device.ip] || [];
    device.open_ports = ports;

    // Port-based flags
    for (const rule of FLAG_RULES) {
      if (ports.includes(rule.port)) {
        device.flags.push(rule.flag);
      }
    }

    // SMB + no hostname = potentially anonymous
    if (ports.includes(445) && !device.hostname) {
      device.flags.push('Anonymous SMB potentially exposed');
    }

    // EOL OS check
    if (device.os_guess) {
      for (const pattern of EOL_OS_PATTERNS) {
        if (pattern.test(device.os_guess)) {
          device.flags.push('End of life OS detected');
          break;
        }
      }
    }

    // NSE-derived flags — parse the raw output strings we captured.
    for (const nseFlag of deriveNseFlags(device.nse)) {
      device.flags.push(nseFlag);
    }

    processed++;
    if (device.flags.length > 0) {
      onProgress({
        phase: 'Checking security flags...',
        message: `Flags on ${device.ip}: ${device.flags.join(', ')}`,
        percent: 55 + Math.round((processed / aliveDevices.length) * 35),
      });
    } else {
      onProgress({
        phase: 'Checking security flags...',
        message: `${device.ip} — no flags`,
        percent: 55 + Math.round((processed / aliveDevices.length) * 35),
      });
    }
  }

  return devices;
}

/**
 * Port scan + NSE script sweep for a batch of IPs.
 * @returns {Promise<{ports: Object, nse: Object}>}
 *   ports: { ip: [openPorts] }
 *   nse:   { ip: { scriptId: output } }   (merged host + per-port script output)
 */
function scanPorts(ips, onProgress) {
  return new Promise((resolve, reject) => {
    const portList = KEY_PORTS.join(',');
    // -sT = TCP connect (no root required), -p = specific ports,
    // --script = run the NSE depth scripts, --script-timeout caps each
    // script so a single slow host doesn't stall the whole report.
    const args = [
      '-sT',
      '-p', portList,
      '--script', NSE_SCRIPTS.join(','),
      '--script-timeout', NSE_SCRIPT_TIMEOUT,
      '-oX', '-',
      '--open',
      ...ips,
    ];

    onProgress({
      phase: 'Port + NSE scanning...',
      message: `Scanning ports ${portList} + ${NSE_SCRIPTS.length} NSE scripts on ${ips.length} hosts`,
      percent: 58,
    });

    execFile('nmap', args, { maxBuffer: 20 * 1024 * 1024, timeout: 600000 }, (err, stdout /* , stderr */) => {
      if (err && !stdout) {
        reject(new Error(`Port scan failed: ${err.message}`));
        return;
      }
      resolve(parsePortScanXML(stdout));
    });
  });
}

/**
 * Parse nmap XML to extract open ports + NSE script output per host.
 * Script output can appear in two places:
 *   <hostscript><script id="..." output="..."/></hostscript>   (host-level)
 *   <port ...><script id="..." output="..."/></port>           (per-port)
 * We merge both into a flat { scriptId: output } dict per host.
 */
function parsePortScanXML(xml) {
  const ports = {};
  const nse = {};
  const hostRegex = /<host\b[^>]*>[\s\S]*?<\/host>/g;
  let match;

  while ((match = hostRegex.exec(xml)) !== null) {
    const block = match[0];

    const ipMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/);
    if (!ipMatch) continue;

    const ip = ipMatch[1];
    ports[ip] = [];
    nse[ip] = {};

    // Match <port ...> ... </port> fully; open-state check is after.
    const portRegex = /<port\s+protocol="tcp"\s+portid="(\d+)"[\s\S]*?<\/port>/g;
    let portMatch;
    while ((portMatch = portRegex.exec(block)) !== null) {
      // Only keep open-state ports; nmap emits filtered/closed too when
      // --open isn't in effect for all flavors of the scan.
      if (!/<state\s+state="open"/.test(portMatch[0])) continue;
      ports[ip].push(parseInt(portMatch[1], 10));
      for (const [scriptId, output] of extractScripts(portMatch[0])) {
        nse[ip][scriptId] = output;
      }
    }

    // Host-level scripts (smb-*, snmp-*, etc. may live here)
    const hostScriptBlockMatch = block.match(/<hostscript>[\s\S]*?<\/hostscript>/);
    if (hostScriptBlockMatch) {
      for (const [scriptId, output] of extractScripts(hostScriptBlockMatch[0])) {
        nse[ip][scriptId] = output;
      }
    }
  }

  return { ports, nse };
}

/**
 * Pull every <script id="..." output="..."> out of an XML fragment.
 * Returns an array of [id, decodedOutput] pairs.
 */
function extractScripts(xmlFragment) {
  const out = [];
  const scriptRegex = /<script\s+id="([^"]+)"\s+output="([^"]*)"/g;
  let m;
  while ((m = scriptRegex.exec(xmlFragment)) !== null) {
    out.push([m[1], decodeXmlAttr(m[2])]);
  }
  return out;
}

function decodeXmlAttr(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * Derive human-readable flag strings from NSE output.
 * Conservative — only fires on clearly-bad signals; leaves raw output
 * intact on device.nse for the PDF renderer to do anything fancier.
 */
function deriveNseFlags(nse) {
  const flags = [];
  if (!nse) return flags;

  // EternalBlue / MS17-010 — nmap prints "VULNERABLE" in the output
  // block when the host is missing the patch.
  const ms17 = nse['smb-vuln-ms17-010'];
  if (ms17 && /\bVULNERABLE\b/i.test(ms17) && !/NOT VULNERABLE/i.test(ms17)) {
    flags.push('SMB MS17-010 (EternalBlue) vulnerable');
  }

  // Anonymous / guest-readable SMB shares
  const shares = nse['smb-enum-shares'];
  if (shares && /Anonymous access:\s*READ/i.test(shares)) {
    flags.push('Anonymous-readable SMB share(s) detected');
  }

  // Weak SSL/TLS — any SSLv2/SSLv3 offered, or overall grade < B
  const ssl = nse['ssl-enum-ciphers'];
  if (ssl) {
    if (/SSLv2|SSLv3/.test(ssl)) flags.push('SSLv2/SSLv3 still enabled');
    const gradeMatch = ssl.match(/least strength:\s*([A-F])/i);
    if (gradeMatch && /[CDEF]/i.test(gradeMatch[1])) {
      flags.push(`Weak TLS cipher suite (grade ${gradeMatch[1]})`);
    }
  }

  // Missing HTTP security headers — http-security-headers lists missing
  // ones; a long "Missing" list is a soft flag.
  const headers = nse['http-security-headers'];
  if (headers) {
    const missing = [];
    for (const h of ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']) {
      const escaped = h.replace(/[-]/g, '[-]');
      if (new RegExp(`${escaped}[^:]*:?\\s*(not set|missing)`, 'i').test(headers)) {
        missing.push(h);
      }
    }
    if (missing.length >= 2) {
      flags.push(`HTTP security headers missing: ${missing.join(', ')}`);
    }
  }

  // SNMP default community
  const snmp = nse['snmp-info'];
  if (snmp && /community:\s*public/i.test(snmp)) {
    flags.push('SNMP "public" community string accepted (default credential)');
  }

  return flags;
}

module.exports = { analyzeDevices };
