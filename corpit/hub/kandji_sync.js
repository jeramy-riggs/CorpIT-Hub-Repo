const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');

const pool = mysql.createPool({
  host:            process.env.DB_HOST,
  port:            parseInt(process.env.DB_PORT) || 3306,
  database:        'it_inventory',
  user:            process.env.DB_USER,
  password:        process.env.DB_PASSWORD,
  connectionLimit: 5,
  charset:         'utf8mb4',
});

// Network identity from /devices/{id}/details — the only place Kandji exposes a
// Mac's MAC address, current LAN IP and its real local hostname. Without these a
// Mac cannot be found on the switch fabric (Macs are not in AD DNS).
function extractNetwork(details) {
  const n = (details && (details.network || details.Network)) || {};
  return {
    mac_address:    n.mac_address || null,
    ip_address:     n.ip_address || null,
    local_hostname: n.local_hostname || null,
  };
}

async function kandjiGet(path) {
  const res = await fetch(`${process.env.KANDJI_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${process.env.KANDJI_TOKEN}`,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) throw new Error(`Kandji API ${res.status}: ${path}`);
  return res.json();
}

async function kandjiGetDetails(deviceId) {
  try { return await kandjiGet(`/api/v1/devices/${deviceId}/details`); }
  catch (e) { return null; }
}
function extractChip(details) {
  const raw = details?.hardware_overview?.processor_name || '';
  if (!raw) return null;
  return raw.replace(/^Apple\s+/i, '').trim() || null;
}

// Kandji reports booleans in /details as real booleans, but agent_installed
// comes back as the STRING "True"/"False" — normalise both shapes.
function asBool(v) {
  if (v === true || v === false) return v ? 1 : 0;
  if (typeof v === 'string') {
    if (/^true$/i.test(v)) return 1;
    if (/^false$/i.test(v)) return 0;
  }
  return null;
}

// Everything we keep from /devices/{id}/details beyond the chip. FileVault
// state is what feeds the "Devices unencrypted" KPI; prk_escrowed flags Macs
// we could not recover if the user forgot their password.
function extractPosture(details) {
  const fv = details?.filevault || {};
  const ag = details?.kandji_agent || {};
  return {
    filevault_enabled:      asBool(fv.filevault_enabled),
    filevault_prk_escrowed: asBool(fv.filevault_prk_escrowed),
    agent_version:          ag.agent_version || null,
  };
}

router.get('/status', async (req, res) => {
  try {
    const [[macs]]  = await pool.query('SELECT MAX(updated_at) as last_synced, COUNT(*) as total FROM macbooks');
    const [[ipads]] = await pool.query('SELECT COUNT(*) as total FROM ipad_devices');
    res.json({ last_synced: macs.last_synced, macs: macs.total, ipads: ipads.total });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/sync', async (req, res) => {
  try {
    const devices = await kandjiGet('/api/v1/devices');
    const active  = devices.filter(d => !d.is_removed);
    const macs    = active.filter(d => d.platform === 'Mac');
    const ipads   = active.filter(d => d.platform === 'iPad');

    let macSynced = 0, ipadSynced = 0, removed = 0, errors = 0;

    const [chipRows] = await pool.query('SELECT serial FROM macbooks WHERE chip IS NOT NULL AND serial IS NOT NULL');
    const chipHave = new Set(chipRows.map(r => r.serial));

    const fmt = (dt) => dt
      ? new Date(dt).toLocaleDateString('en-US', {
          year:'numeric', month:'short', day:'numeric',
          hour:'2-digit', minute:'2-digit'
        })
      : '--';

    // /details is now fetched for every Mac each run (was: only when `chip` was
    // missing). It is the only source of FileVault state, and posture has to be
    // current to be worth anything. ~1 extra call per Mac on a daily 04:00 cron.
    let detailFetches = 0, detailErrors = 0;
    for (const d of macs) {
      try {
        let chip = null;
        let posture = { filevault_enabled: null, filevault_prk_escrowed: null, agent_version: null };
        let net = { mac_address: null, ip_address: null, local_hostname: null };
        let gotDetails = false;
        if (d.device_id) {
          const details = await kandjiGetDetails(d.device_id);
          detailFetches++;
          if (details) {
            gotDetails = true;
            net = extractNetwork(details);
            posture = extractPosture(details);
            if (!chipHave.has(d.serial_number)) chip = extractChip(details);
          } else {
            detailErrors++;
          }
        }
        await pool.query(`
          INSERT INTO macbooks (device_name, model, chip, os_version, serial, blueprint, user_name, checked_in,
                                filevault_enabled, filevault_prk_escrowed, agent_version, details_synced_at,
                                mac_address, ip_address, local_hostname)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            device_name=VALUES(device_name), model=VALUES(model),
            chip=COALESCE(macbooks.chip, VALUES(chip)),
            os_version=VALUES(os_version), blueprint=VALUES(blueprint),
            user_name=VALUES(user_name), checked_in=VALUES(checked_in),
            filevault_enabled=COALESCE(VALUES(filevault_enabled), macbooks.filevault_enabled),
            filevault_prk_escrowed=COALESCE(VALUES(filevault_prk_escrowed), macbooks.filevault_prk_escrowed),
            agent_version=COALESCE(VALUES(agent_version), macbooks.agent_version),
            details_synced_at=COALESCE(VALUES(details_synced_at), macbooks.details_synced_at),
            mac_address=COALESCE(VALUES(mac_address), macbooks.mac_address),
            ip_address=COALESCE(VALUES(ip_address), macbooks.ip_address),
            local_hostname=COALESCE(VALUES(local_hostname), macbooks.local_hostname),
            updated_at=NOW()
        `, [
          d.device_name || '--', d.model || '--', chip,
          d.os_version || '--', d.serial_number || '--', d.blueprint_name || '--',
          (d.user?.name || d.user?.email || '--'), fmt(d.last_check_in),
          posture.filevault_enabled, posture.filevault_prk_escrowed, posture.agent_version,
          gotDetails ? new Date() : null,
          net.mac_address, net.ip_address, net.local_hostname,
        ]);
        macSynced++;
      } catch(e) { errors++; }
    }

    for (const d of ipads) {
      try {
        await pool.query(`
          INSERT INTO ipad_devices (device_id, device_name, model, os_version, serial, blueprint, user_name, checked_in, is_missing, mdm_enabled)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            device_name=VALUES(device_name), model=VALUES(model),
            os_version=VALUES(os_version), blueprint=VALUES(blueprint),
            user_name=VALUES(user_name), checked_in=VALUES(checked_in),
            is_missing=VALUES(is_missing), mdm_enabled=VALUES(mdm_enabled), updated_at=NOW()
        `, [
          d.device_id || null, d.device_name || '--', d.model || '--',
          d.os_version || '--', d.serial_number || '--', d.blueprint_name || '--',
          (d.user?.name || d.user?.email || '--'), fmt(d.last_check_in),
          d.is_missing ? 1 : 0, d.mdm_enabled ? 1 : 0,
        ]);
        ipadSynced++;
      } catch(e) { errors++; }
    }

    const macSerials = new Set(macs.map(d => d.serial_number).filter(Boolean));
    const [existingMacs] = await pool.query('SELECT id, serial FROM macbooks');
    for (const row of existingMacs) {
      if (row.serial && row.serial !== '--' && !macSerials.has(row.serial)) {
        await pool.query('DELETE FROM macbooks WHERE id = ?', [row.id]);
        removed++;
      }
    }

    const ipadSerials = new Set(ipads.map(d => d.serial_number).filter(Boolean));
    const [existingIpads] = await pool.query('SELECT id, serial FROM ipad_devices');
    for (const row of existingIpads) {
      if (row.serial && row.serial !== '--' && !ipadSerials.has(row.serial)) {
        await pool.query('DELETE FROM ipad_devices WHERE id = ?', [row.id]);
        removed++;
      }
    }

    res.json({ success: true, total: active.length, macs: macSynced, ipads: ipadSynced, removed, errors,
               detailFetches, detailErrors });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
