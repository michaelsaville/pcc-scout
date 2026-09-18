const net = require('net');

// Read the SSH server's identification string. SSH hands this over before
// any negotiation — just open a socket, read a line. Format:
//   SSH-<proto>-<software>\r\n
// Example: "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.4"
//
// Matching on the software field gives us distro hints (Ubuntu build,
// Debian, Dropbear=embedded, Cisco SSH, etc.).
function probeSsh(host, port = 22, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    const done = (val) => {
      if (!settled) { settled = true; resolve(val); }
    };

    const socket = net.createConnection({ host, port, timeout: timeoutMs });

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a); // LF
      if (nl !== -1) {
        const line = buf.slice(0, nl).toString('utf-8').replace(/\r$/, '').trim();
        socket.destroy();
        if (line.startsWith('SSH-')) {
          const parts = line.split('-', 3);
          done({
            banner: line,
            protocol: parts[1] || null,
            software: parts.slice(2).join('-') || null,
          });
        } else {
          done({ banner: line, unknownFormat: true });
        }
      }
      if (buf.length > 2048) { socket.destroy(); done({ error: 'banner too long' }); }
    });

    socket.on('error', (e) => done({ error: e.message || 'ssh error' }));
    socket.on('timeout', () => { socket.destroy(); done({ error: 'timeout' }); });
    socket.on('close', () => { if (buf.length === 0) done(null); });
  });
}

module.exports = { probeSsh };
