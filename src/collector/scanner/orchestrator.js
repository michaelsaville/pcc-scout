const net = require('net');
const { probeTls } = require('./probes/tls');
const { probeSsh } = require('./probes/ssh');
const { probeHttp } = require('./probes/http');
const { annotate: ouiAnnotate } = require('./probes/oui');

// Fast TCP open-port check (no nmap). Resolves true if the connect
// completes before the timeout.
function tcpPortOpen(host, port, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: timeoutMs });
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; socket.destroy(); resolve(v); } };
    socket.on('connect', () => done(true));
    socket.on('error', () => done(false));
    socket.on('timeout', () => done(false));
  });
}

// For each discovered neighbor, probe the ports relevant to identifying
// the device AND to scoring its exposure. Results are sparse — most hosts
// respond on a subset. Ports fall into two buckets:
//   - fingerprint ports (ssh/http/https) run a protocol-specific probe
//     that yields a banner (SSH software, HTTP server/title, TLS cert).
//   - exposure ports (telnet/smb/rdp/ftp/vnc/db/netbios) have no banner
//     probe; a successful TCP connect alone is the finding. The server's
//     risk scorer (scoreNetwork) keys on these port numbers — 23, 445,
//     3389 — so capturing "open" is what makes the Network grade real
//     instead of the old "no port data" fallback.
// All are plain TCP connect() checks — no nmap, no raw sockets, nothing
// that trips EDR. UDP-only services (SNMP/161) are out of scope here.
const PROBE_PORTS = [
  { port: 21,   protocol: 'ftp'         },
  { port: 22,   protocol: 'ssh'         },
  { port: 23,   protocol: 'telnet'      },
  { port: 80,   protocol: 'http'        },
  { port: 135,  protocol: 'msrpc'       },
  { port: 139,  protocol: 'netbios-ssn' },
  { port: 443,  protocol: 'https'       },
  { port: 445,  protocol: 'smb'         },
  { port: 1433, protocol: 'ms-sql'      },
  { port: 3306, protocol: 'mysql'       },
  { port: 3389, protocol: 'rdp'         },
  { port: 5432, protocol: 'postgresql'  },
  { port: 5900, protocol: 'vnc'         },
  { port: 8080, protocol: 'http'        },
  { port: 8443, protocol: 'https'       },
];

async function probeHost(ip, onProgress) {
  const evidence = [];

  // Parallel port checks with short timeout.
  const openPorts = [];
  await Promise.all(PROBE_PORTS.map(async (p) => {
    const open = await tcpPortOpen(ip, p.port, 800);
    if (open) openPorts.push(p);
  }));

  if (openPorts.length === 0) return { ip, evidence };

  // Run protocol-specific probes in parallel.
  const probeJobs = openPorts.map(async ({ port, protocol }) => {
    if (protocol === 'ssh') {
      const r = await probeSsh(ip, port);
      // Spread first, then pin protocol — probeSsh returns its own
      // `protocol` field (the SSH version, e.g. "2.0") which would
      // otherwise clobber the service label the fusion layer expects.
      if (r) evidence.push({ port, ...r, protocol: 'ssh' });
    } else if (protocol === 'http') {
      const r = await probeHttp(ip, port, false);
      if (r) evidence.push({ port, ...r, protocol: 'http' });
    } else if (protocol === 'https') {
      const [httpR, tlsR] = await Promise.all([probeHttp(ip, port, true), probeTls(ip, port)]);
      if (httpR) evidence.push({ port, ...httpR, protocol: 'https' });
      if (tlsR) evidence.push({ port, ...tlsR, protocol: 'tls' });
    }
  });
  await Promise.all(probeJobs);

  return { ip, openPorts: openPorts.map(p => p.port), evidence };
}

// Concurrency-limited map. Prevents us from opening 500 sockets at once
// when scanning a /24.
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let index = 0;
  async function worker() {
    while (true) {
      const i = index++;
      if (i >= items.length) break;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// Given the neighbor table from native.js, probe each IP and annotate with
// OUI vendor info. Returns an array of neighbor + evidence records.
async function probeNeighbors(neighbors, onProgress) {
  if (!Array.isArray(neighbors) || neighbors.length === 0) return [];

  const list = neighbors
    .filter(n => n && n.IPAddress)
    .map(n => ({
      ip: n.IPAddress,
      mac: n.LinkLayerAddress || null,
      state: n.State || null,
    }));

  let done = 0;
  const enriched = await mapLimit(list, 12, async (n) => {
    const probeResult = await probeHost(n.ip);
    const ouiAnnotation = n.mac ? ouiAnnotate(n.mac) : { vendor: null, mac_age: null };
    done++;
    if (onProgress && done % 5 === 0) {
      onProgress({ phase: `Probing hosts…`, percent: 45 + Math.round((done / list.length) * 15) });
    }
    return {
      ...n,
      vendor: ouiAnnotation.vendor,
      mac_age: ouiAnnotation.mac_age,
      openPorts: probeResult.openPorts || [],
      evidence: probeResult.evidence || [],
    };
  });

  return enriched;
}

module.exports = { probeNeighbors, probeHost };
