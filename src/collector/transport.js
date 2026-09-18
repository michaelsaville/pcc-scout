const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const os = require('os');
const { URL } = require('url');

// Push the scan result to the cloud receiver. Resolves on 2xx, rejects
// otherwise. Body is gzipped JSON — typical scan is 50-500 KB so gzip is
// a free ~70% reduction.
function pushToCloud(result, config) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(config.cloud_url);
    } catch (e) {
      reject(new Error(`Invalid cloud_url: ${config.cloud_url}`));
      return;
    }

    const lib = target.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(result));
    const req = lib.request({
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: target.pathname + target.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length,
        'Authorization': `Bearer ${config.token}`,
        'X-Prospect-Id': config.prospect_id,
        'User-Agent': 'PCC-Scout-Collector/1.0',
      },
      timeout: 30000,
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode, body });
        } else {
          reject(new Error(`Cloud receiver returned ${res.statusCode}: ${body.slice(0, 300)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Cloud push timed out after 30s'));
    });

    req.write(payload);
    req.end();
  });
}

// Write the result to the user's Desktop as a .pccscan file so they can
// email it back. Returns the written path.
function writeToDesktop(result, config) {
  const desktop = path.join(os.homedir(), 'Desktop');
  const safeProspect = (config.prospect_name || 'prospect')
    .replace(/[^a-zA-Z0-9_\- ]/g, '')
    .replace(/\s+/g, '_')
    .slice(0, 40);
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `pcc-scan-${safeProspect}-${ts}.pccscan`;
  const fullPath = path.join(fs.existsSync(desktop) ? desktop : os.homedir(), filename);
  const envelope = {
    version: 1,
    prospect_id: config.prospect_id,
    prospect_name: config.prospect_name,
    msp_name: config.msp_name,
    generated_at: new Date().toISOString(),
    result,
  };
  fs.writeFileSync(fullPath, JSON.stringify(envelope, null, 2));
  return fullPath;
}

function buildMailto(config, attachmentPath) {
  const subject = encodeURIComponent(`PCC Scout results — ${config.prospect_name}`);
  const body = encodeURIComponent(
    `Hi ${config.msp_name},\n\n` +
    `PCC Scout couldn't upload automatically — likely an outbound firewall. ` +
    `The results file is attached to this email.\n\n` +
    `File location on this machine: ${attachmentPath}\n\n` +
    `— Sent from PCC Scout`
  );
  return `mailto:${config.tech_email}?subject=${subject}&body=${body}`;
}

// mode: 'push' (default) tries cloud, falls back to file on error.
// mode: 'file' skips cloud entirely.
async function deliver(result, config, mode = 'push') {
  if (mode === 'file') {
    const filePath = writeToDesktop(result, config);
    return { delivery: 'file', filePath, mailto: buildMailto(config, filePath) };
  }

  try {
    const resp = await pushToCloud(result, config);
    return { delivery: 'push', cloudResponse: resp };
  } catch (pushErr) {
    const filePath = writeToDesktop(result, config);
    return {
      delivery: 'fallback-file',
      pushError: pushErr.message,
      filePath,
      mailto: buildMailto(config, filePath),
    };
  }
}

module.exports = { deliver, pushToCloud, writeToDesktop, buildMailto };
