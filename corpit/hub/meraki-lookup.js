const { enrichClients } = require('./user-enrich');
'use strict';
/**
 * meraki-lookup.js
 * Meraki Dashboard API integration for IT Command NOC dashboard.
 *
 * Org ID:    181393  (Auction.com)
 * Networks:
 *   SNA01 Irvine  — N_582090251837658123
 *   DFW02 Plano   — N_832040031156699632
 */

const https = require('https');

const ORG_ID   = '181393';
const NETWORKS = {
  SNA01: { id: 'N_582090251837658123', name: 'Irvine',  site: 'SNA01', tz: 'America/Los_Angeles' },
  DFW02: { id: 'N_832040031156699632', name: 'Plano TX', site: 'DFW02', tz: 'US/Central' }
};

// SSIDs we care about — filter out "Unconfigured SSID X"
const KNOWN_SSIDS = ['Auction.com [SECURE]', 'Auction.com GUEST', 'Auction.com', 'IoT'];

// ── HTTP helper ───────────────────────────────────────────────────────────────

function merakiGet(path, options = {}) {
  const token = process.env.MERAKI_API_KEY;
  if (!token) return Promise.reject(new Error('MERAKI_API_KEY not set in .env'));

  return new Promise((resolve, reject) => {
    const url = new URL('https://api.meraki.com/api/v1' + path);
    const req = https.request(url, {
      method:  'GET',
      headers: {
        'X-Cisco-Meraki-API-Key': token,
        'Accept': 'application/json'
      }
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; if (options.maxBytes && Buffer.byteLength(data) > options.maxBytes) req.destroy(new Error('Meraki response exceeded the read limit')); });
      res.on('end',   () => {
        if (res.statusCode === 204 || !data.trim()) {
          resolve({ status: res.statusCode, body: [] });
          return;
        }
        const pagination = {};
        if (options.pagination) {
          for (const match of (res.headers.link || '').matchAll(/<([^>]+)>;\s*rel="?([^",;\s]+)"?/g)) pagination[match[2]] = match[1];
          pagination.retryAfter = res.headers['retry-after'] || null;
        }
        try   { resolve({ status: res.statusCode, body: JSON.parse(data), hasMore: /rel="?next(?:"|\s|,|$)/.test(res.headers.link || ''), ...(options.pagination ? {pagination} : {}) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(Math.min(20000, Math.max(1, options.timeoutMs || 20000)), () => { req.destroy(); reject(new Error(`Meraki request timed out: ${path}`)); });
    req.end();
  });
}

// ── Data fetchers ─────────────────────────────────────────────────────────────

/**
 * Get all AP statuses for both networks in one call.
 * Returns array of { name, serial, model, status, lanIp, networkId, lastReportedAt }
 */
async function getDeviceStatuses() {
  const networkIds = Object.values(NETWORKS).map(n => n.id);
  const qs = networkIds.map(id => `networkIds[]=${id}`).join('&');
  const res = await merakiGet(`/organizations/${ORG_ID}/devices/statuses?${qs}&productTypes[]=wireless`);
  if (res.status !== 200 || !Array.isArray(res.body)) return [];
  return res.body;
}

/**
 * Get all clients for a network in the last 5 minutes (active clients).
 */
async function getNetworkClients(networkId, timespanSec = 300) {
  const res = await merakiGet(`/networks/${networkId}/clients?timespan=${timespanSec}&perPage=1000`);
  if (res.status !== 200 || !Array.isArray(res.body)) return [];
  return res.body;
}

/**
 * Get wireless radio status for a single AP.
 * Returns active bands and channels — filters out unconfigured SSIDs.
 */
async function getApWirelessStatus(serial) {
  const res = await merakiGet(`/devices/${serial}/wireless/status`);
  if (res.status !== 200 || !res.body || !Array.isArray(res.body.basicServiceSets)) {
    return null;
  }

  // Only keep broadcasting SSIDs we know about
  const active = res.body.basicServiceSets.filter(b =>
    b.broadcasting && KNOWN_SSIDS.includes(b.ssidName)
  );

  // Summarise unique broadcasting bands
  const bands = [...new Set(active.map(b => b.band))].sort();

  // Get channel info per band (pick first match per band)
  const channelInfo = {};
  active.forEach(b => {
    if (!channelInfo[b.band]) {
      channelInfo[b.band] = { channel: b.channel, width: b.channelWidth, power: b.power };
    }
  });

  return { bands, channelInfo, activeSsids: [...new Set(active.map(b => b.ssidName))] };
}

// ── Main NOC data builder ─────────────────────────────────────────────────────

/**
 * getNocData()
 * Builds the full NOC dashboard payload in one call.
 * Fetches: device statuses + clients for both networks in parallel.
 * Per-AP wireless status is fetched lazily (separate endpoint per AP).
 */
async function getNocData() {
  try {
    // Fetch device statuses + clients for both networks in parallel
    const [devices, snClients, dfwClients] = await Promise.all([
      getDeviceStatuses(),
      getNetworkClients(NETWORKS.SNA01.id),
      getNetworkClients(NETWORKS.DFW02.id)
    ]);

    // Build client lookup: recentDeviceSerial → client list
    const clientsByAp = {};
    [...snClients, ...dfwClients].forEach(c => {
      const serial = c.recentDeviceSerial;
      if (!serial) return;
      if (!clientsByAp[serial]) clientsByAp[serial] = [];
      clientsByAp[serial].push(c);
    });

    // SSID breakdowns per network
    const ssidCount = (clients) => {
      const out = {};
      clients.forEach(c => {
        const s = c.ssid || 'Unknown';
        if (!KNOWN_SSIDS.includes(s) && s !== 'Unknown') return;
        out[s] = (out[s] || 0) + 1;
      });
      return out;
    };

    // Build AP list per site
    const buildSite = (networkKey) => {
      const net     = NETWORKS[networkKey];
      const clients = networkKey === 'SNA01' ? snClients : dfwClients;
      const aps     = devices
        .filter(d => d.networkId === net.id)
        .sort((a, b) => {
          // Sort by AP number (WAP01 before WAP02)
          const numA = parseInt((a.name || '').replace(/\D/g, '')) || 0;
          const numB = parseInt((b.name || '').replace(/\D/g, '')) || 0;
          return numA - numB;
        })
        .map(d => ({
          name:          d.name,
          serial:        d.serial,
          model:         d.model,
          status:        d.status,
          lanIp:         d.lanIp,
          lastReported:  d.lastReportedAt,
          clientCount:   (clientsByAp[d.serial] || []).length,
          clients:       (clientsByAp[d.serial] || []).map(c => ({
            description: c.description,
            mac:         c.mac,
            ip:          c.ip,
            ssid:        c.ssid,
            os:          c.os,
            manufacturer: c.manufacturer,
            status:      c.status,
            lastSeen:    c.lastSeen
          }))
        }));

      const onlineCount  = aps.filter(a => a.status === 'online').length;
      const offlineCount = aps.filter(a => a.status !== 'online').length;

      return {
        networkId:    net.id,
        site:         net.site,
        name:         net.name,
        apCount:      aps.length,
        onlineCount,
        offlineCount,
        clientCount:  clients.length,
        ssidBreakdown: ssidCount(clients),
        aps
      };
    };

    const sna01 = buildSite('SNA01');
    const dfw02 = buildSite('DFW02');

    const totalAps     = sna01.apCount     + dfw02.apCount;
    const totalOnline  = sna01.onlineCount + dfw02.onlineCount;
    const totalOffline = sna01.offlineCount + dfw02.offlineCount;
    const totalClients = sna01.clientCount + dfw02.clientCount;

    return {
      success:      true,
      fetchedAt:    new Date().toISOString(),
      org:          'Auction.com',
      summary: {
        totalAps,
        totalOnline,
        totalOffline,
        totalClients
      },
      sites: { SNA01: sna01, DFW02: dfw02 }
    };

  } catch (e) {
    return { success: false, error: e.message };
  }
}

/**
 * getApDetail(serial)
 * Returns wireless radio status for a specific AP (channel, bands, SSIDs).
 * Called on-demand when a tech clicks an AP card.
 */
async function getApDetail(serial) {
  try {
    // Fetch device info (for networkId) + wireless status in parallel
    const [deviceRes, wirelessStatus] = await Promise.all([
      merakiGet(`/devices/${serial}`),
      getApWirelessStatus(serial)
    ]);

    const networkId = (deviceRes.status === 200 && deviceRes.body) ? deviceRes.body.networkId : null;
    let clients = [];

    if (networkId) {
      // /networks/{id}/clients returns full client records (ssid, user, manufacturer, os).
      // Filter by recentDeviceSerial so we only show clients connected to THIS AP.
      const clientsRes = await merakiGet(
        `/networks/${networkId}/clients?perPage=1000&timespan=300`
      );
      if (clientsRes.status === 200 && Array.isArray(clientsRes.body)) {
        clients = clientsRes.body.filter(c => c.recentDeviceSerial === serial);
      }
    } else {
      // Fallback: old minimal endpoint if device lookup failed
      const fallback = await merakiGet(`/devices/${serial}/clients?timespan=300`);
      if (fallback.status === 200 && Array.isArray(fallback.body)) {
        clients = fallback.body;
      }
    }

    await enrichClients(clients);
    return { success: true, serial, wirelessStatus, clients };
  } catch (e) {
    return { success: false, serial, error: e.message };
  }
}


/**
 * getClientByMac(mac)
 * Two-step lookup for full Meraki client data:
 *   Step 1: Org-level search → finds which network + clientId
 *   Step 2: Network-level client endpoint → full record (AP, SSID, status, etc.)
 *
 * The org search endpoint returns minimal data (no AP name, no status).
 * The network-level endpoint returns the complete client record.
 */
async function getClientByMac(mac) {
  if (!mac) return { found: false, error: 'No MAC address provided' };

  // Normalize MAC: Windows DHCP uses dashes (00-ce-39-d3-a3-f0)
  // Meraki API expects colons (00:ce:39:d3:a3:f0)
  const normalizedMac = mac.toLowerCase().replace(/-/g, ':');

  try {
    // ── Step 1: Org search to find network ID ─────────────────────────────
    const searchRes = await merakiGet(
      `/organizations/${ORG_ID}/clients/search?mac=${encodeURIComponent(normalizedMac)}&timespan=3600`
    );

    if (searchRes.status === 204) {
      return { found: false, note: 'Device not seen on Meraki WiFi in the last hour' };
    }
    if (searchRes.status !== 200 || !searchRes.body) {
      return { found: false, error: `Meraki org search returned HTTP ${searchRes.status}` };
    }

    // Response shape: { mac, manufacturer, clientId, records: [...] }
    const body      = searchRes.body;
    const records   = body.records || [];
    if (records.length === 0) {
      return { found: false, note: 'Device not seen on Meraki WiFi in the last hour' };
    }

    // Pick the most recently seen record
    const record    = records.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))[0];
    const networkId = record.network && record.network.id;
    const clientId  = body.clientId;

    if (!networkId || !clientId) {
      return { found: false, error: 'Could not determine network or client ID from org search' };
    }

    // ── Step 2: Network-level client detail (full record) ─────────────────
    const detailRes = await merakiGet(`/networks/${networkId}/clients/${clientId}`);

    if (detailRes.status !== 200 || !detailRes.body) {
      return { found: false, error: `Network client detail returned HTTP ${detailRes.status}` };
    }

    const c = detailRes.body;

    // Determine site from AP name
    const apName = c.recentDeviceName || '';
    const site   = apName.startsWith('SNA01') ? 'SNA01 — Irvine'  :
                   apName.startsWith('DFW02') ? 'DFW02 — Plano TX' : 'Unknown';

    // Convert epoch timestamps to ISO if needed
    const toIso = (ts) => {
      if (!ts) return null;
      if (typeof ts === 'number') return new Date(ts * 1000).toISOString();
      return ts;
    };

    // Fetch signal quality + latency history in parallel (non-blocking)
    let signalQuality = null;
    let latency = null;
    try {
      const [sigRes, latRes] = await Promise.all([
        merakiGet(`/networks/${networkId}/wireless/signalQualityHistory?clientId=${clientId}&timespan=3600&resolution=300`),
        merakiGet(`/networks/${networkId}/wireless/latencyHistory?clientId=${clientId}&timespan=3600&resolution=300`)
      ]);

      // Get most recent non-null RSSI/SNR reading
      if (sigRes.status === 200 && Array.isArray(sigRes.body)) {
        const readings = sigRes.body.filter(r => r.rssi !== null || r.snr !== null);
        if (readings.length > 0) {
          const latest = readings[readings.length - 1];
          signalQuality = {
            rssi:    latest.rssi,
            snr:     latest.snr,
            startTs: latest.startTs,
            endTs:   latest.endTs
          };
        }
      }

      // Get most recent non-null latency reading
      if (latRes.status === 200 && Array.isArray(latRes.body)) {
        const latReadings = latRes.body.filter(r => r.avgLatencyMs !== null);
        if (latReadings.length > 0) {
          latency = latReadings[latReadings.length - 1].avgLatencyMs;
        }
      }
    } catch (e) {
      // Signal quality is optional — don't fail the whole lookup
    }

    return {
      found:         true,
      id:            c.id,
      mac:           c.mac,
      description:   c.description,
      ip:            c.ip,
      ssid:          c.ssid,
      vlan:          c.vlan          || null,
      status:        c.status,
      lastSeen:      toIso(c.lastSeen),
      firstSeen:     toIso(c.firstSeen),
      apName,
      apSerial:      c.recentDeviceSerial   || null,
      site,
      manufacturer:  c.manufacturer         || body.manufacturer || null,
      os:            c.os                   || null,
      user:          c.user                 || null,
      wirelessCaps:  c.wirelessCapabilities  || null,
      connection:    c.recentDeviceConnection || null,
      usage:         c.usage                || null,
      signalQuality,   // { rssi, snr, startTs, endTs } | null
      latencyMs:     latency                // avg latency in ms | null
    };

  } catch (e) {
    return { found: false, error: `Meraki client lookup failed: ${e.message}` };
  }
}


// ─── WiFi connection history (Phase 2) ───────────────────────────────────────
// 802.11 disassociation reason codes (IEEE 802.11-2020 §9.4.1.7)
// Common codes only — unknown codes fall through to "Reason N"
function decodeDisassocReason(code) {
  const map = {
    '1':  'Unspecified',
    '2':  'Prior auth invalid',
    '3':  'Deauth - leaving network',
    '4':  'Inactivity timeout',
    '5':  'AP unable to handle stations',
    '6':  'Class 2 frame from non-auth station',
    '7':  'Class 3 frame from non-assoc station',
    '8':  'Disassoc - leaving BSS',
    '9':  'Station not authenticated',
    '15': '4-way handshake timeout',
    '16': 'Group key handshake timeout',
    '23': '802.1X auth failed',
    '34': 'Low ACK - poor signal'
  };
  return map[String(code)] || ('Reason ' + code);
}

/**
 * getWifiConnectionHistory(mac, hours)
 * Fetches wireless connectivity events from Meraki and returns a cleaned
 * connect/disconnect/fail timeline. Detects roams (disassoc+assoc within
 * 2s across different APs) and tags them as 'roam' instead of connect+disconnect.
 *
 * Returns: {
 *   found: bool,
 *   site: string,
 *   networkId: string,
 *   eventCount: int,
 *   truncated: bool,
 *   events: [{ timestamp, type, ssid, ap, band, details, reason }]
 * }
 */
async function getWifiConnectionHistory(mac, hours) {
  // eap-fix-v1
  if (!mac) return { found: false, error: 'No MAC address provided' };

  // Clamp hours to Meraki's 1hr-7day range
  const h = Math.max(1, Math.min(168, parseInt(hours, 10) || 24));
  const timespanSec = h * 3600;

  const normalizedMac = mac.toLowerCase().replace(/-/g, ':');

  try {
    // Step 1: Find networkId via org search (same pattern as getClientByMac)
    const searchRes = await merakiGet(
      `/organizations/${ORG_ID}/clients/search?mac=${encodeURIComponent(normalizedMac)}&timespan=${timespanSec}`
    );

    if (searchRes.status === 204 || !searchRes.body || !(searchRes.body.records || []).length) {
      return { found: false, note: `No WiFi activity for this device in the last ${h}h` };
    }

    const record = (searchRes.body.records || [])
      .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))[0];
    const networkId = record.network && record.network.id;
    if (!networkId) return { found: false, error: 'Could not determine networkId' };

    const site = networkId === NETWORKS.SNA01.id ? 'SNA01 Irvine'
               : networkId === NETWORKS.DFW02.id ? 'DFW02 Plano'
               : 'Unknown';

    // Step 2: Pull wireless events for this MAC, using Meraki's native timespan filter
    const eventsRes = await merakiGet(
      `/networks/${networkId}/events?productType=wireless&clientMac=${encodeURIComponent(normalizedMac)}&timespan=${timespanSec}&perPage=1000`
    );

    if (eventsRes.status !== 200) {
      return { found: false, error: `Meraki events returned HTTP ${eventsRes.status}` };
    }

    const rawEvents = (eventsRes.body && eventsRes.body.events) || [];
    if (rawEvents.length === 0) {
      return { found: true, site, networkId, eventCount: 0, truncated: false, events: [] };
    }

    // Sort oldest→newest for roam and dedup logic
    rawEvents.sort((a, b) => new Date(a.occurredAt) - new Date(b.occurredAt));

    // Classify + detect roams + dedup eap_success/association pairs
    const processed = [];
    for (let i = 0; i < rawEvents.length; i++) {
      const e = rawEvents[i];
      const t = e.type;

      const isAssoc    = t === 'association';
      const isEapOk    = t === '8021x_eap_success';
      const isDisassoc = t === 'disassociation';
      const isDeauth   = t === 'deauthentication';
      const isFail     = t && (t.includes('fail') || t.includes('denied') || t.includes('reject'));

      // Connect-type: either 802.11 association OR successful 802.1X EAP
      const isConnect = isAssoc || isEapOk;

      if (!isConnect && !isDisassoc && !isDeauth && !isFail) continue;

      // Dedup: if this is a connect event and previous processed event is ALSO a
      // connect within 5s on same AP, skip (avoid double-counting eap+assoc pair).
      if (isConnect && processed.length > 0) {
        const prev = processed[processed.length - 1];
        if (prev.type === 'connect' && prev.ap === e.deviceName) {
          const gap = new Date(e.occurredAt) - new Date(prev.timestamp);
          if (gap >= 0 && gap <= 5000) {
            continue; // already counted
          }
        }
      }

      // Roam detection: disassoc immediately followed by a connect within 2s on different AP
      if (isDisassoc && i + 1 < rawEvents.length) {
        const next = rawEvents[i + 1];
        const nextIsConnect = next.type === 'association' || next.type === '8021x_eap_success';
        const gap = new Date(next.occurredAt) - new Date(e.occurredAt);
        if (nextIsConnect && gap >= 0 && gap <= 2000
            && next.deviceName !== e.deviceName) {
          processed.push({
            timestamp: next.occurredAt,
            type: 'roam',
            ssid: next.ssidName || e.ssidName || null,
            ap: `${e.deviceName} → ${next.deviceName}`,
            band: (next.eventData && next.eventData.band) || null,
            details: `Roamed in ${gap}ms`,
            reason: null
          });
          i++;
          continue;
        }
      }

      let type, details = null, reason = null;
      if (isConnect) {
        type = 'connect';
        if (isEapOk) details = 'via 802.1X auth';
      } else if (isDisassoc || isDeauth) {
        type = 'disconnect';
        const rc = e.eventData && e.eventData.reason;
        if (rc) reason = decodeDisassocReason(rc);
        const dur = e.eventData && e.eventData.duration;
        if (dur) details = `Session ${Math.round(parseFloat(dur))}s`;
      } else if (isFail) {
        type = 'fail';
        details = e.description || t;
      }

      processed.push({
        timestamp: e.occurredAt,
        type,
        ssid: e.ssidName || null,
        ap: e.deviceName || null,
        band: (e.eventData && e.eventData.band) || null,
        details, reason
      });
    }

    processed.reverse();
    const CAP = 50;
    const truncated = processed.length > CAP;
    return {
      found: true, site, networkId,
      eventCount: processed.length,
      truncated,
      events: processed.slice(0, CAP)
    };

  } catch (e) {
    return { found: false, error: e.message };
  }
}

module.exports = { getNocData, getApDetail, getClientByMac, getWifiConnectionHistory, merakiGet, ORG_ID, NETWORKS };
