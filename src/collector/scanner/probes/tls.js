const tls = require('tls');
const crypto = require('crypto');

// Grab the TLS certificate from a host:port. runZero pattern — the cert
// SHA is a stable identity across IP changes (same physical device ⇒
// same cert unless it rotates), making it a great dedupe key for asset
// fusion across scans.
//
// Uses only Node built-ins; no new dependencies.
function probeTls(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (val) => {
      if (!settled) { settled = true; resolve(val); }
    };

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false, // we want to see self-signed + expired
      timeout: timeoutMs,
      ALPNProtocols: ['h2', 'http/1.1'],
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !cert.raw) {
          done(null);
          return;
        }
        const fingerprintSha256 = crypto.createHash('sha256').update(cert.raw).digest('hex');
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const alpn = socket.alpnProtocol || null;

        done({
          subject: cert.subject?.CN || null,
          subjectAlt: cert.subjectaltname || null,
          issuer: cert.issuer?.CN || cert.issuer?.O || null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          serialNumber: cert.serialNumber || null,
          selfSigned: cert.issuer?.CN === cert.subject?.CN,
          fingerprintSha256,
          protocol,       // "TLSv1.3" etc — flags weak TLS
          cipherName: cipher?.name || null,
          alpn,
        });
      } catch (e) {
        done({ error: e.message });
      } finally {
        socket.end();
      }
    });

    socket.on('error', (e) => done({ error: e.message || 'tls error' }));
    socket.on('timeout', () => { socket.destroy(); done({ error: 'timeout' }); });
  });
}

module.exports = { probeTls };
