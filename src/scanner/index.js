const { v4: uuidv4 } = require('uuid');
const { discoverDevices } = require('./network');
const { analyzeDevices } = require('./security');

/**
 * Orchestrate a full scan: discovery → security analysis.
 * @param {Object} opts - { subnet, scan_label, scan_type }
 * @param {Function} onProgress - IPC progress callback
 * @returns {Promise<Object>} Unified scan result
 */
async function runScan({ subnet, scan_label, scan_type }, onProgress) {
  const scan_id = uuidv4();
  const timestamp = new Date().toISOString();

  onProgress({
    phase: 'Initializing...',
    message: `Scan ${scan_id.slice(0, 8)} started`,
    percent: 0,
  });

  // Phase 1: Network discovery
  let devices = await discoverDevices(subnet, onProgress);

  // Phase 2: Security flag analysis
  devices = await analyzeDevices(devices, onProgress);

  // Build summary
  const flaggedDevices = devices.filter(d => d.flags && d.flags.length > 0);
  const flag_breakdown = {};
  for (const device of flaggedDevices) {
    for (const flag of device.flags) {
      flag_breakdown[flag] = (flag_breakdown[flag] || 0) + 1;
    }
  }

  const result = {
    scan_id,
    scan_label,
    scan_type,
    timestamp,
    subnet,
    devices,
    summary: {
      total_devices: devices.length,
      flagged_devices: flaggedDevices.length,
      total_flags: Object.values(flag_breakdown).reduce((a, b) => a + b, 0),
      flag_breakdown,
    },
  };

  onProgress({
    phase: 'Complete',
    message: `Scan complete: ${result.summary.total_devices} devices, ${result.summary.total_flags} flags`,
    percent: 100,
  });

  return result;
}

module.exports = { runScan };
