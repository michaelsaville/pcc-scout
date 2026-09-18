const http = require('http');
const https = require('https');
const crypto = require('crypto');

// HTTP(S) fingerprint — hit GET / and extract:
//   - status code
//   - Server header (e.g. "Microsoft-IIS/10.0", "nginx/1.24.0", "Apache/2.4")
//   - WWW-Authenticate realm (e.g. "Ubiquiti Router UI")
//   - <title> from HTML body
//   - X-Powered-By (e.g. "ASP.NET")
//   - Favicon SHA256 — runZero pattern; one hash identifies most web UIs
//
// Node built-ins only.
function requestOnce(host, port, secure, path = '/', timeoutMs = 4000) {
  return new Promise((resolve) => {
    const lib = secure ? https : http;
    const req = lib.request({
      host,
      port,
      path,
      method: 'GET',
      timeout: timeoutMs,
      rejectUnauthorized: false,
      headers: { 'User-Agent': 'PCC-Scout-Collector/1.0' },
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size <= 256 * 1024) chunks.push(c); // cap body at 256 KB
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function extractTitle(body) {
  if (!body || !body.length) return null;
  const text = body.toString('utf-8', 0, Math.min(body.length, 65536));
  const m = text.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
  return m ? m[1].trim().replace(/\s+/g, ' ') : null;
}

async function probeHttp(host, port, secure, timeoutMs = 4000) {
  const res = await requestOnce(host, port, secure, '/', timeoutMs);
  if (!res) return null;

  const favRes = await requestOnce(host, port, secure, '/favicon.ico', timeoutMs);
  const faviconSha256 = favRes && favRes.statusCode >= 200 && favRes.statusCode < 300 && favRes.body.length > 0
    ? crypto.createHash('sha256').update(favRes.body).digest('hex')
    : null;

  return {
    scheme: secure ? 'https' : 'http',
    statusCode: res.statusCode,
    server: res.headers['server'] || null,
    poweredBy: res.headers['x-powered-by'] || null,
    wwwAuthenticate: res.headers['www-authenticate'] || null,
    title: extractTitle(res.body),
    faviconSha256,
    contentLength: res.headers['content-length'] ? parseInt(res.headers['content-length'], 10) : null,
  };
}

module.exports = { probeHttp };
