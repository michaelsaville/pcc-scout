// mDNS / Bonjour passive listener — TODO.
//
// Implementation plan: use `multicast-dns` npm dep, join 224.0.0.251:5353
// on every interface, listen for 30-60 seconds, record _services._dns-sd._udp
// PTR records to enumerate service types offered on the LAN. Per-service
// records then yield device names + ports.
//
// High yield on typical office LANs:
//   _printer._tcp  → every printer
//   _airplay._tcp  → Apple TVs
//   _googlecast._tcp → Chromecasts
//   _ipp._tcp      → IPP printers
//   _ssh._tcp      → Macs advertising remote login
//   _smb._tcp      → file servers
//   _companion-link._tcp → Apple devices (Continuity)
//
// Fires passively — no packets to targets, just join and listen. Great
// "nothing weird in the logs" probe.
async function probeMdns(/* durationMs = 30000 */) {
  return { error: 'not implemented' };
}

module.exports = { probeMdns };
