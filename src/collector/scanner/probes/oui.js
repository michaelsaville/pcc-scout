const path = require('path');
const fs = require('fs');

// MAC OUI → vendor lookup. The IEEE publishes the full list at
// https://standards-oui.ieee.org/oui/oui.csv (~4MB). For MVP we bundle a
// seed list of common vendors in oui-data.json; swap in the full file
// later without changing this API.
//
// mac_age is runZero's trick — the year-range a given OUI was first
// issued is a proxy for how old the device likely is. IEEE doesn't
// publish that directly; we approximate with a manually-curated vintage
// table below. Numbers are approximate "first-issued year".

let _prefixMap = null;
function loadPrefixMap() {
  if (_prefixMap) return _prefixMap;
  try {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'oui-data.json'), 'utf-8'));
    _prefixMap = {};
    for (const [prefix, vendor] of Object.entries(data.prefixes || {})) {
      _prefixMap[prefix.toUpperCase().replace(/[-:]/g, '').slice(0, 6)] = vendor;
    }
  } catch {
    _prefixMap = {};
  }
  return _prefixMap;
}

// Rough "first-issued year" per vendor. When we don't have a direct OUI
// vintage we can at least say "this vendor's hardware from this line is
// ~this old". Values picked from public knowledge; replace with real data
// later. Only used as a fallback when specific OUI vintage not known.
const VENDOR_VINTAGE_YEAR = {
  'VMware': 2005,
  'Oracle VirtualBox': 2008,
  'Microsoft Hyper-V': 2008,
  'QEMU / KVM': 2006,
  'Raspberry Pi': 2012,
  'Espressif (ESP32)': 2016,
  'Apple': 2005,
  'Dell': 2000,
  'HP': 2000,
  'Cisco': 1995,
  'Cisco Meraki': 2010,
  'Ubiquiti': 2008,
  'Netgear': 2000,
  'Aruba Networks': 2005,
  'Fortinet': 2005,
  'SonicWall': 2000,
  'Juniper': 2005,
  'Synology': 2010,
  'Hangzhou Hikvision': 2012,
  'Dahua': 2012,
};

function normalizeMac(mac) {
  if (!mac || typeof mac !== 'string') return null;
  return mac.toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, 12);
}

function lookupVendor(mac) {
  const norm = normalizeMac(mac);
  if (!norm || norm.length < 6) return null;
  const map = loadPrefixMap();
  return map[norm.slice(0, 6)] || null;
}

function estimateMacAge(mac, thisYear = new Date().getFullYear()) {
  const vendor = lookupVendor(mac);
  if (!vendor) return null;
  const issued = VENDOR_VINTAGE_YEAR[vendor];
  if (!issued) return null;
  return {
    vendorEarliestYear: issued,
    approximateAgeYears: Math.max(0, thisYear - issued),
  };
}

function annotate(mac) {
  const vendor = lookupVendor(mac);
  const age = estimateMacAge(mac);
  return { vendor, mac_age: age };
}

module.exports = { lookupVendor, estimateMacAge, annotate };
