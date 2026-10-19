'use strict';
/**
 * fortinet-lookup.js  (v3)
 *
 * Device resolution strategy:
 *
 *   Windows devices (Intune / ManageEngine / endpoints):
 *     device_name → Windows DHCP (both servers, parallel) → IP
 *
 *   MacBooks (Kandji — NOT in Intune):
 *     serial → Kandji /devices/?serial_number= → device_id
 *           → Kandji /devices/{id}/details    → network.mac_address
 *           → FortiGate /monitor/network/arp  → MAC → IP
 *
 * Source priority for device resolution:
 *   1. active_employees.device_laptop  (Windows)
 *   2. active_employees.device_macbook (MacBook serial — Kandji path)
 *   3. intune_devices                  (Windows fallback)
 *   4. macbooks / Kandji               (MacBook fallback)
 *   5. endpoints / ManageEngine        (Windows fallback)
 */

const https      = require('https');
const http       = require('http');
const { execFile } = require('child_process');
const path       = require('path');
const mysql      = require('mysql2/promise');

// ── Subnet definitions ────────────────────────────────────────────────────────

const IRVINE_PREFIXES = [
  '10.20.21.', '10.20.22.', '10.20.23.', '10.20.24.',
  '10.20.27.', '10.20.28.', '10.20.29.', '10.20.40.',
  '10.20.10.', '10.8.23.'
];

const PLANO_PREFIXES = [
  '10.19.20.', '10.19.21.', '10.19.25.', '10.19.40.'
];

const DHCP_SERVERS = {
  primary:   '10.20.10.52',
  secondary: '10.9.65.56'
};

// CR-2: a device name handed to dhcp-lookup.py is interpolated into a PowerShell
// -like filter on the DHCP server. Only hostname-safe characters may pass.
const HOSTNAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

function detectSite(ip) {
  if (!ip) return 'remote';
  if (IRVINE_PREFIXES.some(p => ip.startsWith(p))) return 'irvine';
  if (PLANO_PREFIXES.some(p => ip.startsWith(p)))  return 'plano';
  return 'remote';
}

// ── Database helpers ──────────────────────────────────────────────────────────

async function getDbConnection() {
  return mysql.createConnection({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME     || 'corpit_hub',
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });
}

async function getUserRecord(username) {
  const db = await getDbConnection();
  try {
    const [rows] = await db.execute(
      `SELECT first_last, location_name, device_laptop, device_macbook
       FROM active_employees WHERE LOWER(username) = LOWER(?) LIMIT 1`,
      [username]
    );
    return rows[0] || null;
  } finally {
    await db.end();
  }
}

/**
 * Fallback device lookup — checks Intune, Kandji macbooks, ManageEngine.
 * Returns { device, source, isMac } or null.
 */
async function getFallbackDevice(username, fullName) {
  const db = await getDbConnection();
  try {
    // 1. Intune — Windows laptops only
    // NOTE: uses it_inventory (not beta) — that DB has the correct Windows device records
    // Exclude NUC/mini-PC/desktop devices — we only want portable devices
    const [intune] = await db.execute(
      `SELECT device_name FROM it_inventory.intune_devices
       WHERE (primary_user_upn LIKE ? OR primary_user_name LIKE ?)
       AND os = 'Windows'
       AND device_name NOT LIKE 'NUC%'
       AND device_name NOT LIKE 'PLANO-NUC%'
       AND device_name NOT LIKE 'DESKTOP%'
       AND device_name NOT LIKE 'prtg%'
       AND device_name NOT LIKE 'adcore%'
       ORDER BY last_checkin DESC LIMIT 1`,
      [`%${username}%`, `%${username}%`]
    );
    if (intune.length > 0 && intune[0].device_name) {
      return { device: intune[0].device_name, source: 'Intune', isMac: false };
    }

    // 2. Macbooks — Kandji (MacBooks are NOT in Intune)
    // macbooks table is in it_inventory (not beta) and stores full name e.g. "Jeramy Riggs"
    // Search by full name first, fall back to username
    const nameTerm = fullName ? `%${fullName}%` : `%${username}%`;
    const [mac] = await db.execute(
      `SELECT device_name, checked_in FROM it_inventory.macbooks
       WHERE user_name LIKE ? OR user_name LIKE ?
       ORDER BY checked_in DESC LIMIT 1`,
      [nameTerm, `%${username}%`]
    );
    if (mac.length > 0 && mac[0].device_name) {
      return { device: mac[0].device_name, source: 'Kandji', isMac: true };
    }

    // 3. ManageEngine endpoints — remaining Windows devices
    const [ep] = await db.execute(
      `SELECT computer_name FROM endpoints
       WHERE logged_on_user LIKE ? OR first_last LIKE ?
       ORDER BY updated_at DESC LIMIT 1`,
      [`%${username}%`, `%${username}%`]
    );
    if (ep.length > 0 && ep[0].computer_name) {
      return { device: ep[0].computer_name, source: 'ManageEngine', isMac: false };
    }

    return null;
  } finally {
    await db.end();
  }
}

// ── Kandji API helpers ────────────────────────────────────────────────────────

function kandjiRequest(endpoint) {
  const base  = (process.env.KANDJI_BASE_URL || 'https://auction.api.kandji.io').replace(/\/$/, '');
  const token = process.env.KANDJI_TOKEN;
  if (!token) return Promise.reject(new Error('KANDJI_TOKEN not in .env'));

  return new Promise((resolve, reject) => {
    const url = new URL(base + endpoint);
    const req = https.request(url, {
      method:  'GET',
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
    }, (res) => {
      let data = '';
      res.on('data',  c => data += c);
      res.on('end',   () => {
        try   { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Kandji request timed out')); });
    req.end();
  });
}

/**
 * Look up MAC address for a MacBook via Kandji.
 * Steps: serial → device_id → /details → network.mac_address
 * Returns { mac, device_id, device_name } or { error }
 */
async function getMacFromKandji(serial) {
  try {
    // Step 1: Find device by serial number
    const listRes = await kandjiRequest(`/api/v1/devices/?serial_number=${encodeURIComponent(serial)}`);
    if (listRes.status !== 200 || !Array.isArray(listRes.body) || listRes.body.length === 0) {
      return { error: `Kandji: device not found for serial ${serial}` };
    }
    const device = listRes.body[0];
    const deviceId   = device.device_id;
    const deviceName = device.device_name;

    // Step 2: Fetch device details to get MAC address
    const detailRes = await kandjiRequest(`/api/v1/devices/${deviceId}/details`);
    if (detailRes.status !== 200 || !detailRes.body) {
      return { error: `Kandji: could not fetch details for device ${deviceId}` };
    }

    const mac = detailRes.body.network && detailRes.body.network.mac_address;
    if (!mac) {
      return { error: `Kandji: no MAC address in device details for ${serial}` };
    }

    return { mac: mac.toLowerCase(), device_id: deviceId, device_name: deviceName };

  } catch (e) {
    return { error: `Kandji lookup failed: ${e.message}` };
  }
}

// ── FortiGate ARP lookup ──────────────────────────────────────────────────────

/**
 * Get the current IP for a MAC address from the FortiGate ARP table.
 * Returns { ip, interface } or { error }
 */
async function getIpFromArp(macAddress) {
  try {
    const res = await fortigateRequest('/api/v2/monitor/network/arp');
    if (res.status !== 200 || !res.body || !Array.isArray(res.body.results)) {
      return { error: `FortiGate ARP table returned HTTP ${res.status}` };
    }

    const normalise = m => (m || '').toLowerCase().replace(/-/g, ':');
    const targetMac = normalise(macAddress);

    const entry = res.body.results.find(r => normalise(r.mac) === targetMac);
    if (!entry) {
      return {
        error: `MAC ${macAddress} not found in FortiGate ARP table — ` +
               `device may be off-network or connected through a switch not visible to FortiGate`
      };
    }

    return { ip: entry.ip, interface: entry.interface };

  } catch (e) {
    return { error: `ARP lookup failed: ${e.message}` };
  }
}

// ── Windows DHCP lookup via Python/WinRM ─────────────────────────────────────

function dhcpLookupOne(deviceName, dhcpServer) {
  return new Promise((resolve) => {
    if (typeof deviceName !== 'string' || !HOSTNAME_RE.test(deviceName)) {
      resolve({ error: `DHCP (${dhcpServer}): device name is not a valid hostname` }); return;
    }
    const script = path.join(__dirname, 'dhcp-lookup.py');
    execFile(
      'python3',
      [script, '--device', deviceName, '--server', dhcpServer],
      { env: process.env, timeout: 45000 },
      (err, stdout) => {
        if (err) { resolve({ error: `DHCP (${dhcpServer}): ${err.message}` }); return; }
        const raw = (stdout || '').trim();
        if (!raw) { resolve({ error: `No output from DHCP ${dhcpServer}` }); return; }
        try   { resolve({ ...JSON.parse(raw), server: dhcpServer }); }
        catch { resolve({ error: `Parse error from ${dhcpServer}` }); }
      }
    );
  });
}

async function dhcpLookupBoth(deviceName) {
  const [primary, secondary] = await Promise.all([
    dhcpLookupOne(deviceName, DHCP_SERVERS.primary),
    dhcpLookupOne(deviceName, DHCP_SERVERS.secondary)
  ]);
  if (primary.ip)   return primary;
  if (secondary.ip) return secondary;
  return {
    error:          primary.error   || 'No DHCP lease found on either server',
    secondaryError: secondary.error || null
  };
}

// ── FortiGate API helpers ─────────────────────────────────────────────────────

function fortigateRequest(endpoint) {
  const host  = (process.env.FORTIGATE_HOST || '').replace(/\/$/, '');
  const token = process.env.FORTIGATE_API_TOKEN;
  if (!host || !token) return Promise.reject(new Error('FortiGate credentials not in .env'));

  return new Promise((resolve, reject) => {
    const url = new URL(host + endpoint);
    const req = https.request(url, {
      method:  'GET',
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      rejectUnauthorized: false
    }, (res) => {
      let data = '';
      res.on('data',  c => data += c);
      res.on('end',   () => {
        try   { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('FortiGate timed out')); });
    req.end();
  });
}

async function getActiveSessions(srcIp) {
  try {
    const res = await fortigateRequest('/api/v2/monitor/firewall/session?count=1000');
    if (res.status !== 200 || !res.body || !res.body.results) {
      return { success: false, count: 0, sessions: [],
               note: `FortiGate returned HTTP ${res.status}` };
    }
    const details = res.body.results.details || [];
    const matched = details.filter(s => s.saddr === srcIp);
    return { success: true, count: matched.length, sessions: matched.slice(0, 20) };
  } catch (e) {
    return { success: false, count: 0, sessions: [], error: e.message };
  }
}

async function getFortiViewStats(srcIp) {
  try {
    const res = await fortigateRequest(
      '/api/v2/monitor/fortiview/statistics?report-by=source&timeframe=hour&count=500'
    );
    if (res.status !== 200 || !res.body || !res.body.results) {
      return { success: false, note: `FortiView returned HTTP ${res.status}` };
    }
    const details = res.body.results.details || [];
    const match   = details.find(s => s.srcip === srcIp || s.srcaddr === srcIp);

    if (!match) {
      return { success: true, found: false, session_allow: 0, session_block: 0, bytes: 0,
               note: 'IP not in FortiView top sources for this hour — device may be idle' };
    }
    return {
      success:       true,
      found:         true,
      srcip:         match.srcip   || srcIp,
      srcmac:        match.srcmac  || null,
      user:          match.user    || null,
      session_allow: match.session_allow || 0,
      session_block: match.session_block || 0,
      bytes:         match.bytes         || 0,
      sentbyte:      match.sentbyte      || 0,
      rcvdbyte:      match.rcvdbyte      || 0
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ── Main exported function ────────────────────────────────────────────────────

async function checkUserFirewall(username) {
  const result = {
    username,
    user:         null,
    site:         null,
    device:       null,
    deviceSource: null,
    isMac:        false,
    ipMethod:     null,   // 'dhcp' | 'arp' — how the IP was resolved
    dhcp:         null,
    sessions:     null,
    fortiview:    null,
    resolvedIp:   null,
    error:        null
  };

  try {
    // ── Step 1: Employee record ─────────────────────────────────────────────
    const user = await getUserRecord(username);
    if (!user) {
      result.error = `No active employee record found for username: ${username}`;
      return result;
    }
    result.user = { name: user.first_last, location: user.location_name };

    // ── Step 2: Site detection ──────────────────────────────────────────────
    const loc = (user.location_name || '').toLowerCase();
    if (loc.includes('irvine')) {
      result.site = 'irvine';
    } else if (loc.includes('plano') || loc.includes('dfw')) {
      result.site = 'plano';
      result.error = 'Plano office FortiGate integration coming soon';
      return result;
    } else {
      result.site = 'remote';
      result.error = 'User appears to be remote — traffic is handled by Zscaler, not FortiGate';
      return result;
    }

    // ── Step 3: Resolve device ──────────────────────────────────────────────
    let deviceName   = null;
    let deviceSource = null;
    let isMac        = false;

    // Check active_employees first.
    // device_macbook must look like a real Apple serial (8-14 alphanumeric, no spaces).
    // Model names like "MacBook Pro (16-inch, 2021)" are NOT serials — skip them.
    // device_laptop must not be a known placeholder value.
    const laptopVal  = (user.device_laptop  || '').trim();
    const macbookVal = (user.device_macbook || '').trim();

    const isAppleSerial = (s) => /^[A-Z0-9]{8,14}$/i.test(s);
    const PLACEHOLDERS  = ['LAPTOP','PC','COMPUTER','DEVICE','N/A','NA','NONE','TBD'];
    const isPlaceholder = (s) => PLACEHOLDERS.includes(s.toUpperCase());

    if (macbookVal && isAppleSerial(macbookVal)) {
      deviceName   = macbookVal;
      deviceSource = 'Employee Record';
      isMac        = true;
    } else if (laptopVal && !isPlaceholder(laptopVal) && laptopVal.length > 3) {
      deviceName   = laptopVal;
      deviceSource = 'Employee Record';
      isMac        = false;
    } else {
      // Fallback chain
      const fallback = await getFallbackDevice(username, result.user.name);
      if (fallback) {
        deviceName   = fallback.device;
        deviceSource = fallback.source;
        isMac        = fallback.isMac;
      }
    }

    if (!deviceName) {
      result.error = 'No device found for this user in Employee Records, Intune, Kandji, or ManageEngine';
      return result;
    }

    result.device       = deviceName;
    result.deviceSource = deviceSource;
    result.isMac        = isMac;

    // ── Step 4: Resolve IP ──────────────────────────────────────────────────
    let resolvedIp = null;

    if (isMac) {
      // MacBook path: Kandji → MAC address
      // ARP lookup is attempted for FortiGate session data but not required —
      // Meraki WiFi lookup uses MAC directly so we don't need the IP.
      const kandjiResult = await getMacFromKandji(deviceName);
      if (kandjiResult.error) {
        result.error = kandjiResult.error;
        return result;
      }
      result.kandji = {
        mac:         kandjiResult.mac,
        device_id:   kandjiResult.device_id,
        device_name: kandjiResult.device_name
      };

      // Try ARP for IP (needed for FortiGate session/FortiView data)
      // If ARP fails, we still have the MAC for Meraki WiFi lookup
      const arpResult = await getIpFromArp(kandjiResult.mac);
      if (arpResult.ip) {
        resolvedIp      = arpResult.ip;
        result.ipMethod = 'arp';
        result.dhcp     = { ip: resolvedIp, mac: kandjiResult.mac,
                            interface: arpResult.interface, server: 'FortiGate ARP' };
      } else {
        // ARP miss — MacBook is on WiFi subnet not directly visible to FortiGate ARP
        // Still store MAC so Meraki WiFi lookup can proceed
        result.ipMethod = 'mac-only';
        result.dhcp     = { mac: kandjiResult.mac, ip: null,
                            server: 'Kandji (ARP miss — WiFi device)' };
        result.error    = null; // clear error — MAC is enough for WiFi card
      }

    } else {
      // Windows path: DHCP lookup by device name (both servers in parallel)
      const dhcp = await dhcpLookupBoth(deviceName);
      result.dhcp = dhcp;

      if (!dhcp.ip) {
        result.error = dhcp.error || `No active DHCP lease found for "${deviceName}"`;
        return result;
      }

      resolvedIp      = dhcp.ip;
      result.ipMethod = 'dhcp';
    }

    result.resolvedIp = resolvedIp;

    // ── Step 5: Confirm IP is on an Irvine subnet (skip for MAC-only) ────────
    if (result.ipMethod === 'mac-only') {
      // MacBook on WiFi — no IP from ARP, skip FortiGate queries
      // WiFi card will use MAC directly via Meraki
      result.sessions  = null;
      result.fortiview = null;
    } else {
      if (detectSite(resolvedIp) !== 'irvine') {
        result.error = `Device IP ${resolvedIp} is not on an Irvine subnet — ` +
                       `user may be remote or on a guest network`;
        return result;
      }

      // ── Step 6: FortiGate queries in parallel ─────────────────────────────
      const [sessions, fortiview] = await Promise.all([
        getActiveSessions(resolvedIp),
        getFortiViewStats(resolvedIp)
      ]);

      result.sessions  = sessions;
      result.fortiview = fortiview;
    }

  } catch (e) {
    result.error = `Unexpected error: ${e.message}`;
  }

  return result;
}

module.exports = { checkUserFirewall, detectSite };
