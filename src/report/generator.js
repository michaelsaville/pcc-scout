const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const TEMPLATE_PATH = path.join(__dirname, 'template.html');
const OUTPUT_DIR = path.join(__dirname, '..', '..', 'output');

/**
 * Generate a branded PDF report from scan results.
 * @param {Object} scanResult - unified scan result JSON
 * @param {Object} branding - { company_name, primary_color, logo_path }
 * @returns {Promise<string>} path to generated PDF
 */
async function generateReport(scanResult, branding) {
  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  // Read template
  let html = fs.readFileSync(TEMPLATE_PATH, 'utf-8');

  // Prepare branding with base64 logo
  const brandingData = { ...branding };
  if (branding.logo_path && fs.existsSync(branding.logo_path)) {
    const logoBuffer = fs.readFileSync(branding.logo_path);
    const ext = path.extname(branding.logo_path).slice(1).replace('jpg', 'jpeg');
    const mimeType = ext === 'svg' ? 'image/svg+xml' : `image/${ext}`;
    brandingData.logo_base64 = `data:${mimeType};base64,${logoBuffer.toString('base64')}`;
  }

  // Inject data into template
  html = html.replace('__SCAN_DATA__', JSON.stringify(scanResult));
  html = html.replace('__BRANDING_DATA__', JSON.stringify(brandingData));

  // Build output filename
  const safeLabel = (scanResult.scan_label || 'scan')
    .replace(/[^a-zA-Z0-9_\- ]/g, '')
    .replace(/\s+/g, '_')
    .slice(0, 60);
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `${safeLabel}-${ts}.pdf`;
  const outputPath = path.join(OUTPUT_DIR, filename);

  // Launch puppeteer and render
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });

    await page.pdf({
      path: outputPath,
      format: 'Letter',
      printBackground: true,
      margin: {
        top: '0.5in',
        bottom: '0.75in',
        left: '0.5in',
        right: '0.5in',
      },
    });
  } finally {
    await browser.close();
  }

  return outputPath;
}

module.exports = { generateReport };
