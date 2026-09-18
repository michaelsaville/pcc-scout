// SNMP v2c probe — TODO.
//
// Implementation plan: add `net-snmp` npm dep. Walk these OIDs against
// configurable community strings ('public', 'private' as defaults,
// with a UI toggle to disable this probe entirely in sensitive envs):
//
//   1.3.6.1.2.1.1.1.0        sysDescr    → OS/hardware fingerprint
//   1.3.6.1.2.1.1.2.0        sysObjectID → vendor enterprise OID
//   1.3.6.1.2.1.1.5.0        sysName
//   1.3.6.1.2.1.2.2          ifTable     → all interfaces
//   1.0.8802.1.1.2.1.4.1.1   lldpRemTable → neighbor discovery (!!)
//                                           → this is THE topology source
//   1.3.6.1.2.1.25.6.3.1.2   hrSWInstalled → installed software on host
//
// lldpRemTable is the gold — one SNMP walk of a managed switch yields
// the full layer-2 topology (this switch's ports and who's plugged in
// to each). Per the runZero research this is how we drive the Switch
// Topology Report later.
//
// net-snmp requires a native build step for raw sockets on some
// platforms; test Electron packaging with it before committing to the
// dep.
async function probeSnmp(/* host, community = 'public' */) {
  return { error: 'not implemented' };
}

module.exports = { probeSnmp };
