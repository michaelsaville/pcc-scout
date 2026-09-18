const { execFile } = require('child_process');
const os = require('os');

/**
 * Discover devices on a subnet using nmap.
 * @param {string} subnet - e.g. "192.168.1.0/24"
 * @param {Function} onProgress - callback({ phase, message, percent })
 * @returns {Promise<Array>} Array of device objects
 */
async function discoverDevices(subnet, onProgress) {
  // First check if nmap is installed
  await checkNmap();

  onProgress({
    phase: 'Discovering devices...',
    message: `Running nmap host discovery on ${subnet}`,
    percent: 5,
  });

  // Phase 1: Ping sweep to find alive hosts
  const aliveHosts = await runNmapDiscovery(subnet, onProgress);

  if (aliveHosts.length === 0) {
    onProgress({
      phase: 'Discovery complete',
      message: 'No devices found on this subnet',
      percent: 40,
    });
    return [];
  }

  onProgress({
    phase: 'Fingerprinting...',
    message: `Found ${aliveHosts.length} alive hosts, running OS detection`,
    percent: 30,
  });

  // Phase 2: OS detection on alive hosts
  const devices = await runNmapOSDetect(aliveHosts, subnet, onProgress);
  return devices;
}

function checkNmap() {
  return new Promise((resolve, reject) => {
    execFile('nmap', ['--version'], (err) => {
      if (err) {
        const platform = os.platform();
        let installHint = '';
        if (platform === 'darwin') {
          installHint = 'Install with: brew install nmap';
        } else if (platform === 'win32') {
          installHint = 'Install with: choco install nmap\nOr download from https://nmap.org/download.html';
        } else {
          installHint = 'Install with: sudo apt install nmap (Debian/Ubuntu) or sudo yum install nmap (RHEL/CentOS)';
        }
        reject(new Error(`nmap is not installed or not in PATH.\n${installHint}`));
      } else {
        resolve();
      }
    });
  });
}

function runNmapDiscovery(subnet, onProgress) {
  return new Promise((resolve, reject) => {
    // -sn = ping scan (no port scan), -oX - = XML output to stdout
    const args = ['-sn', '-oX', '-', subnet];

    const child = execFile('nmap', args, { maxBuffer: 10 * 1024 * 1024, timeout: 120000 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`nmap discovery failed: ${err.message}\n${stderr || ''}`));
        return;
      }
      const hosts = parseNmapXML(stdout);
      resolve(hosts);
    });
  });
}

function runNmapOSDetect(hosts, subnet, onProgress) {
  return new Promise((resolve, reject) => {
    const ips = hosts.map(h => h.ip).join(' ');
    // -O = OS detection, --osscan-guess = aggressive OS guessing, -oX - = XML output
    const args = ['-O', '--osscan-guess', '-oX', '-', ...hosts.map(h => h.ip)];

    onProgress({
      phase: 'Fingerprinting...',
      message: `Running OS detection on ${hosts.length} hosts`,
      percent: 35,
    });

    const child = execFile('nmap', args, { maxBuffer: 10 * 1024 * 1024, timeout: 300000 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        // nmap often exits non-zero for OS detection when not root — try to parse anyway
        reject(new Error(`nmap OS detection failed: ${err.message}\n${stderr || ''}`));
        return;
      }

      const devices = parseNmapXML(stdout);

      // Merge with original discovery data
      const merged = hosts.map(h => {
        const osData = devices.find(d => d.ip === h.ip);
        return {
          ...h,
          ...(osData || {}),
          is_alive: true,
        };
      });

      let count = 0;
      for (const d of merged) {
        count++;
        onProgress({
          phase: 'Fingerprinting...',
          message: `Found device: ${d.ip}${d.hostname ? ' (' + d.hostname + ')' : ''}${d.os_guess ? ' — ' + d.os_guess : ''}`,
          percent: 35 + Math.round((count / merged.length) * 15),
        });
      }

      resolve(merged);
    });
  });
}

/**
 * Parse nmap XML output into device objects.
 */
function parseNmapXML(xml) {
  const devices = [];
  // Match each <host> block
  const hostRegex = /<host\b[^>]*>[\s\S]*?<\/host>/g;
  let match;

  while ((match = hostRegex.exec(xml)) !== null) {
    const block = match[0];

    // Skip hosts that are down
    if (/<status\s+state="down"/.test(block)) continue;

    const device = {
      ip: null,
      hostname: null,
      mac: null,
      vendor: null,
      os_guess: null,
      os_confidence: null,
      is_alive: true,
    };

    // IP address
    const ipMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/);
    if (ipMatch) device.ip = ipMatch[1];

    // MAC address
    const macMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="mac"(?:\s+vendor="([^"]*)")?/);
    if (macMatch) {
      device.mac = macMatch[1];
      device.vendor = macMatch[2] || null;
    }

    // Hostname
    const hostMatch = block.match(/<hostname\s+name="([^"]+)"/);
    if (hostMatch) device.hostname = hostMatch[1];

    // OS match (best guess)
    const osMatch = block.match(/<osmatch\s+name="([^"]+)"\s+accuracy="(\d+)"/);
    if (osMatch) {
      device.os_guess = osMatch[1];
      device.os_confidence = parseInt(osMatch[2], 10);
    }

    if (device.ip) {
      devices.push(device);
    }
  }

  return devices;
}

/**
 * Auto-detect the local subnet.
 */
function detectSubnet() {
  const interfaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        // Simple /24 assumption from the IP
        const parts = addr.address.split('.');
        parts[3] = '0';
        return `${parts.join('.')}/24`;
      }
    }
  }
  return '192.168.1.0/24';
}

module.exports = { discoverDevices, detectSubnet };
