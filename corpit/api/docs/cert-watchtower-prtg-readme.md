# Cert Watchtower — PRTG Sensor Setup Guide

How to configure PRTG sensors so they correctly receive and display data from
cert-watchtower's daily cron pushes.

---

## What gets pushed

Each push from `cert-watchtower-cron.js` (or the manual UI test) sends an
**HTTP Push Data Advanced** payload to PRTG over HTTP POST. There are two
sensor shapes:

### Per-cert sensors (one per monitor or finding)

Four numeric channels, pushed every cron run:

| Channel name | Source | Unit | Notes |
|---|---|---|---|
| `Days Until Expiry`  | `cert_current.days_remaining`         | days | Negative if expired |
| `Cert Status`        | enum -> int (see lookup table below)   | (lookup) | Use `cert-status-lookup.ovl` |
| `Handshake Time`     | `cert_checks.handshake_ms`            | ms (TimeResponse) | TLS connect + cert verify |
| `Days Since Issue`   | derived from `not_before`             | days | Identifies recent re-issuance |

Plus a status text: `<subject_cn> — <N> days remaining — status: <state>`

### Summary sensor (one global, optional)

Five count channels, pushed once per cron run if `prtg_summary_sensor_token`
is set in `cert_config`:

| Channel name | Source | Unit |
|---|---|---|
| `Total Certs Watched`  | `COUNT(*) FROM cert_monitors WHERE enabled=1`   | count |
| `Expiring < 30 days`   | `COUNT(*)` of `days_remaining BETWEEN 0..30`    | count |
| `Expiring < 7 days`    | `COUNT(*)` of `days_remaining BETWEEN 0..7`     | count |
| `Expired`              | `COUNT(*)` of `status='expired'`                | count |
| `Unreachable`          | `COUNT(*)` of `status='unreachable'`            | count |

Plus a status text: `Fleet: N watched · X <30d · Y <7d · Z expired · W unreachable`

---

## Status code lookup table

The "Cert Status" channel pushes integers 0-6. To make PRTG dashboards show
human labels instead of raw numbers, install `cert-status-lookup.ovl`.

| Integer | Label | PRTG state |
|---|---|---|
| 0 | OK | Ok |
| 1 | Info | Warning |
| 2 | Warning | Warning |
| 3 | Critical | Error |
| 4 | Expired | Error |
| 5 | Unreachable | Error |
| 6 | Error / Unknown | Warning |

Without the .ovl, PRTG will display "3" instead of "Critical" and won't
color-code the sensor by status. Everything still works, it's just less readable.

---

## One-time PRTG setup

### 1. Install the lookup file (one-time per PRTG core)

On the PRTG server (`prtg01awsw2us.nrpi.local`):

1. Copy `cert-status-lookup.ovl` to:
   ```
   C:\Program Files (x86)\PRTG Network Monitor\lookups\custom\
   ```
2. In PRTG web UI:
   ```
   Setup > System Administration > Administrative Tools
   Click "Load Lookups and File Lists"
   ```
3. Verify by checking `Setup > System Administration > Lookup Files` — you
   should see `oid.cert-watchtower.cert-status` in the list.

### 2. Create a sensor template (recommended — for repeatability)

You can either configure each sensor's channels manually, or create one
"reference" sensor with the right channels and clone it for each cert.

To configure the channels on a sensor:

1. **Add Sensor** > **HTTP Push Data Advanced** > set port 5050, POST, etc.
   (Same setup we used for `cert-watchtower-test`.)
2. After the FIRST push arrives, the four channels appear automatically.
   Then edit each:

**Channel: Days Until Expiry**
- Unit String: `days`
- Value Type: Integer
- Lower error limit: `0` (alert when negative — cert expired)
- Lower warning limit: `7` (alert when ≤ 7 days)
- (Optionally add `30` as info — but per our agreed design, the "Cert Status"
  channel handles severity transitions, so the warning at 7 here is just a
  PRTG-side belt-and-braces alert)

**Channel: Cert Status**
- Value Type: **Lookup**
- Lookup file: `oid.cert-watchtower.cert-status`
- (No upper/lower limits needed — the .ovl file controls colors)

**Channel: Handshake Time**
- Unit: TimeResponse (already set by the push payload)
- Upper warning limit: `5000` (5s — slow handshake suggests a problem)
- Upper error limit: `10000` (10s — matches our `CHECK_TIMEOUT_MS`)

**Channel: Days Since Issue**
- Unit String: `days`
- No alerting — purely informational. Useful for spotting "this cert was
  re-issued yesterday" events.

### 3. Per-cert sensor creation

For each cert you want to monitor in PRTG (in addition to cert-watchtower's
own dashboard):

1. Add an **HTTP Push Data Advanced** sensor under the appropriate device.
2. Configure as in step 2 above (or clone the template sensor).
3. Copy the new sensor's **Identification Token** from its Settings tab.
4. In Cert Watchtower's UI:
   - Open the cert's detail view (Step 8 — coming soon, will add a per-cert
     PRTG section there)
   - Until Step 8: directly UPDATE `cert_monitors`:
     ```sql
     UPDATE cert_monitors
        SET prtg_push_enabled = 1,
            prtg_token = '<identtoken-from-prtg>'
      WHERE id = <monitor_id>;
     ```
5. Wait for the next cron run (06:00 UTC), or trigger one manually:
   ```bash
   sudo node /var/www/api/cert-watchtower-cron.js
   ```
6. Verify in PRTG that the sensor received its first push.

### 4. Summary sensor (optional)

1. Create one more **HTTP Push Data Advanced** sensor on a sensible device
   (e.g. the `Cert Watchtower` device under `AWS-WEST`).
2. Copy its identtoken into `cert_config`:
   - In the cert-watchtower UI's **Settings** tab > PRTG Integration card >
     Summary sensor token field, paste it and Save.
3. The summary sensor's first push happens on the next cron run.

---

## Verifying the integration

After the first cron run with PRTG enabled:

```bash
# Confirm pushes happened
sudo grep "prtg push phase" /var/log/cert-watchtower/cron.log | tail -5

# Per-monitor outcomes recorded in DB
sudo mysql it_inventory -e "
  SELECT id, hostname, prtg_last_push_at, prtg_last_push_status
    FROM cert_monitors
   WHERE prtg_push_enabled = 1
   ORDER BY prtg_last_push_at DESC;
"

# Status endpoint
curl -s http://localhost:3000/api/prtg/status | python3 -m json.tool
```

The "Last monitor push" timestamp in the UI's Status display will start
showing real values too.

---

## Failure modes & where to look

| Symptom | Likely cause | Where to look |
|---|---|---|
| `prtg_last_push_status='mismatch'` | Token wrong, sensor deleted, sensor paused | PRTG UI: is the sensor green? |
| `prtg_last_push_status='timeout'` | Network blip or PRTG core slow | `/var/log/cert-watchtower/cron.log` |
| `prtg_last_push_status='validation'` | Code bug or bad config (host/port empty) | `cert_config` rows; check for empty strings |
| Sensor shows "no data" but DB says push ok | PRTG sensor configured for "ignore stale data" | Sensor's "No Incoming Data" setting |
| All pushes failing | `prtg_enabled='0'` or master switch off | `cert_config.prtg_enabled` |

---

## File locations

- Helper module: `/var/www/api/cert-watchtower-prtg-helper.js`
- Routes: `/var/www/api/cert-watchtower-prtg-routes.js`
- Cron (this file): `/var/www/api/cert-watchtower-cron.js` (system cron at 06:00 UTC)
- Config: rows in `cert_config` table where `config_key LIKE 'prtg_%'`
- Per-monitor PRTG state: columns in `cert_monitors` matching `prtg_*`
- Logs: `/var/log/cert-watchtower/cron.log`
