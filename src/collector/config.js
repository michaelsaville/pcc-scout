const fs = require('fs');
const path = require('path');

// Per-prospect config is baked into the build at packaging time by the tech
// portal. Each prospect gets their own EXE with a unique token and cloud URL.
// During development, fall back to config/collector.dev.json.
const BAKED_PATH = path.join(__dirname, '..', '..', 'config', 'collector.json');
const DEV_PATH = path.join(__dirname, '..', '..', 'config', 'collector.dev.json');

function loadConfig() {
  const source = fs.existsSync(BAKED_PATH) ? BAKED_PATH : DEV_PATH;
  if (!fs.existsSync(source)) {
    return {
      prospect_id: 'dev-prospect',
      prospect_name: 'Development Prospect',
      msp_name: 'Precision Computers & Consulting',
      tech_email: 'tech@pcc2k.com',
      cloud_url: 'https://scout-api.pcc2k.com/v1/scan',
      token: 'dev-token-not-for-production',
      fingerprint: 'DEV-0000',
    };
  }
  return JSON.parse(fs.readFileSync(source, 'utf-8'));
}

module.exports = { loadConfig };
