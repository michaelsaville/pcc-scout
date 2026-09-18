// SSDP / UPnP discovery — TODO.
//
// Implementation plan: send M-SEARCH * HTTP/1.1 over UDP multicast to
// 239.255.255.250:1900 with ST:ssdp:all. Collect NOTIFY/UPnP responses
// for 5-10 seconds. Each response gives a LOCATION URL pointing at an
// XML device description: manufacturer, model, serial, services.
//
// Pairs with mDNS — SSDP catches IoT (smart TVs, printers, NAS,
// routers, IP cams, sonos/media players) that don't do mDNS. Between
// the two we cover ~90% of consumer/prosumer devices passively.
//
// Active M-SEARCH sends one UDP packet (totally safe); no native deps
// needed — can be implemented with Node's dgram module.
async function probeSsdp(/* durationMs = 5000 */) {
  return { error: 'not implemented' };
}

module.exports = { probeSsdp };
