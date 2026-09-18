/* === PCC Scout — Renderer Logic === */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentConfig = null;
let lastScanResult = null;

// --- Screen Navigation ---

function showScreen(name) {
  $$('.screen').forEach(s => s.classList.add('hidden'));
  $(`#screen-${name}`).classList.remove('hidden');
}

// --- Init ---

async function init() {
  currentConfig = await window.api.configLoad();
  if (currentConfig) {
    showScreen('main');
  } else {
    showScreen('setup');
  }
  bindEvents();
}

// --- Event Binding ---

function bindEvents() {
  // Setup screen
  $('#setup-color').addEventListener('input', (e) => {
    $('#setup-color-hex').textContent = e.target.value;
  });

  $('#setup-logo-btn').addEventListener('click', async () => {
    const logoPath = await window.api.dialogOpenFile();
    if (logoPath) {
      $('#setup-logo-img').src = logoPath;
      $('#setup-logo-preview').classList.remove('hidden');
      $('#setup-logo-btn').dataset.logoPath = logoPath;
    }
  });

  $('#setup-save-btn').addEventListener('click', async () => {
    const company = $('#setup-company').value.trim() || 'Precision Computers & Consulting';
    const color = $('#setup-color').value;
    const logoPath = $('#setup-logo-btn').dataset.logoPath || null;

    currentConfig = {
      company_name: company,
      primary_color: color,
      logo_path: logoPath,
    };

    const result = await window.api.configSave(currentConfig);
    if (result.success) {
      showScreen('main');
    } else {
      alert('Failed to save config: ' + result.error);
    }
  });

  // Main screen — settings
  $('#main-settings-btn').addEventListener('click', () => {
    if (currentConfig) {
      $('#setup-company').value = currentConfig.company_name || '';
      $('#setup-color').value = currentConfig.primary_color || '#2196f3';
      $('#setup-color-hex').textContent = currentConfig.primary_color || '#2196f3';
      if (currentConfig.logo_path) {
        $('#setup-logo-img').src = currentConfig.logo_path;
        $('#setup-logo-preview').classList.remove('hidden');
        $('#setup-logo-btn').dataset.logoPath = currentConfig.logo_path;
      }
    }
    showScreen('setup');
  });

  // Auto-detect subnet
  $('#scan-autodetect').addEventListener('click', () => {
    // Use a common default — the main process could do this smarter,
    // but for phase 1 we parse common private subnets
    const guesses = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/24'];
    $('#scan-subnet').value = guesses[0];
    appendLog('Auto-detected subnet: 192.168.1.0/24 (default — adjust if needed)', 'info');
  });

  // Start scan
  $('#scan-start-btn').addEventListener('click', startScan);

  // Results actions
  $('#result-report-btn').addEventListener('click', generateReport);
  $('#result-json-btn').addEventListener('click', exportJSON);
  $('#result-open-btn').addEventListener('click', () => window.api.shellOpenPath());

  // IPC listeners
  window.api.onScannerProgress(onProgress);
  window.api.onScannerComplete(onScanComplete);
  window.api.onScannerError(onScanError);
}

// --- Scanning ---

async function startScan() {
  const subnet = $('#scan-subnet').value.trim();
  const scan_label = $('#scan-label').value.trim();
  const scan_type = $('#scan-type').value;

  if (!subnet) {
    alert('Please enter a target subnet');
    return;
  }

  if (!scan_label) {
    alert('Please enter a scan label / site name');
    return;
  }

  // Reset UI
  clearLog();
  lastScanResult = null;
  $('#results-placeholder').classList.remove('hidden');
  $('#results-content').classList.add('hidden');
  $('#progress-phase').textContent = 'Starting scan...';
  $('#progress-percent').textContent = '0%';
  $('#progress-bar').style.width = '0%';
  $('#scan-start-btn').disabled = true;
  $('#scan-start-btn').textContent = 'Scanning...';

  appendLog(`Starting ${scan_type} scan on ${subnet}`, 'info');

  try {
    await window.api.scannerStart({ subnet, scan_label, scan_type });
  } catch (err) {
    // Error handled by onScanError
  }
}

function onProgress({ phase, message, percent }) {
  $('#progress-phase').textContent = phase || 'Scanning...';
  if (percent != null) {
    $('#progress-percent').textContent = `${Math.round(percent)}%`;
    $('#progress-bar').style.width = `${percent}%`;
  }
  if (message) {
    const type = message.toLowerCase().includes('flag') ? 'flag'
      : message.toLowerCase().includes('found') || message.toLowerCase().includes('device') ? 'device'
      : 'info';
    appendLog(message, type);
  }
}

function onScanComplete(result) {
  lastScanResult = result;
  $('#scan-start-btn').disabled = false;
  $('#scan-start-btn').textContent = 'Start Scan';
  $('#progress-phase').textContent = 'Scan complete';
  $('#progress-percent').textContent = '100%';
  $('#progress-bar').style.width = '100%';

  appendLog(`Scan complete: ${result.summary.total_devices} devices, ${result.summary.total_flags} flags`, 'info');

  // Show results
  $('#results-placeholder').classList.add('hidden');
  $('#results-content').classList.remove('hidden');

  $('#result-devices').textContent = result.summary.total_devices;
  $('#result-flags').textContent = result.summary.total_flags;

  // Color code flags
  const flagsCard = $('#result-flags-card');
  flagsCard.className = 'stat-card';
  if (result.summary.total_flags === 0) {
    flagsCard.classList.add('severity-clear');
  } else if (result.summary.total_flags <= 3) {
    flagsCard.classList.add('severity-amber');
  } else {
    flagsCard.classList.add('severity-red');
  }

  // Flag breakdown
  const breakdown = result.summary.flag_breakdown;
  const keys = Object.keys(breakdown);
  if (keys.length > 0) {
    $('#results-breakdown').classList.remove('hidden');
    const list = $('#results-breakdown-list');
    list.innerHTML = '';
    for (const key of keys) {
      const li = document.createElement('li');
      li.innerHTML = `<span>${key}</span><span>${breakdown[key]}</span>`;
      list.appendChild(li);
    }
  } else {
    $('#results-breakdown').classList.add('hidden');
  }
}

function onScanError(msg) {
  $('#scan-start-btn').disabled = false;
  $('#scan-start-btn').textContent = 'Start Scan';
  $('#progress-phase').textContent = 'Scan failed';
  appendLog(`ERROR: ${msg}`, 'error');
}

// --- Report ---

async function generateReport() {
  if (!lastScanResult || !currentConfig) return;

  $('#result-report-btn').disabled = true;
  $('#result-report-btn').textContent = 'Generating...';

  try {
    const result = await window.api.reportGenerate({
      scan_result: lastScanResult,
      branding: currentConfig,
    });
    appendLog(`Report saved: ${result.filepath}`, 'info');
    alert(`Report generated!\n${result.filepath}`);
  } catch (err) {
    appendLog(`Report error: ${err.message}`, 'error');
    alert(`Failed to generate report: ${err.message}\n\nUse Export JSON as a fallback.`);
  } finally {
    $('#result-report-btn').disabled = false;
    $('#result-report-btn').textContent = 'Generate Report';
  }
}

function exportJSON() {
  if (!lastScanResult) return;
  const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${lastScanResult.scan_label || 'scan'}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// --- Log ---

function appendLog(text, type = 'info') {
  const log = $('#progress-log');
  const placeholder = log.querySelector('.log-placeholder');
  if (placeholder) placeholder.remove();

  const entry = document.createElement('div');
  entry.className = `log-entry log-${type}`;
  const ts = new Date().toLocaleTimeString();
  entry.textContent = `[${ts}] ${text}`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

function clearLog() {
  $('#progress-log').innerHTML = '';
}

// --- Boot ---

document.addEventListener('DOMContentLoaded', init);
