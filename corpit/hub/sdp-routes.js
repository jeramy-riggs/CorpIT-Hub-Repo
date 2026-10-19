// sdp-routes.js
// Express router for ServiceDesk Plus OnDemand API
// Mounted at /api/sdp in server.js

const express = require('express');
const router  = express.Router();
// ---- RBAC enforcement (Slice 12: SDP tickets — identity-diag) ----
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);
// ---------------------------------------------------------------------
const sdp     = require('./sdp-lookup');

// -------------------------------------------------------
// GET /api/sdp/health
// -------------------------------------------------------
router.get('/health', async (req, res) => {
  try {
    const data = await sdp.healthCheck();
    res.json({ success: true, message: 'SDP connection OK', responseKeys: Object.keys(data) });
  } catch (err) {
    console.error('[SDP] health check error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------
// GET /api/sdp/tickets?email=user@auction.com
// -------------------------------------------------------
router.get('/tickets', rbac.requirePage('identity-diag','read'), async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: 'email query parameter is required' });
  }
  try {
    const tickets = await sdp.getTicketsByEmail(email);
    res.json({ success: true, tickets });
  } catch (err) {
    console.error('[SDP] getTicketsByEmail error:', err.message);
    res.status(500).json({ error: 'Failed to fetch tickets', detail: err.message });
  }
});

// -------------------------------------------------------
// POST /api/sdp/tickets/:id/note
// Body: { noteText: "...", isPublic: false }
// -------------------------------------------------------
router.post('/tickets/:id/note', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  const ticketId = req.params.id;
  const { noteText, isPublic } = req.body;
  if (!noteText) {
    return res.status(400).json({ error: 'noteText is required' });
  }
  try {
    const result = await sdp.addNoteToTicket(ticketId, noteText, isPublic === true);
    res.json({ success: true, result });
  } catch (err) {
    console.error('[SDP] addNoteToTicket error:', err.message);
    res.status(500).json({ error: 'Failed to add note', detail: err.message });
  }
});

// -------------------------------------------------------
// POST /api/sdp/tickets/create
// Body: { subject, description, requesterEmail, requesterName }
// -------------------------------------------------------
router.post('/tickets/create', rbac.requirePage('identity-diag','admin'), async (req, res) => {
  const { subject, description, requesterEmail, requesterName } = req.body;
  if (!subject || !requesterEmail) {
    return res.status(400).json({ error: 'subject and requesterEmail are required' });
  }
  try {
    const ticket = await sdp.createTicket({ subject, description, requesterEmail, requesterName });
    res.json({ success: true, ticket });
  } catch (err) {
    console.error('[SDP] createTicket error:', err.message);
    res.status(500).json({ error: 'Failed to create ticket', detail: err.message });
  }
});

// -------------------------------------------------------
// Changes (CAB) — requires SDPOnDemand.changes scope on the
// Zoho refresh token. SDP answers a scope miss with an HTML
// 401, which we map to a stable code the modal can act on.
// -------------------------------------------------------
function sdpScopeMiss(err) {
  return err.response && err.response.status === 401;
}

// GET /api/sdp/changes/health — modal probes this before showing the form
router.get('/changes/health', rbac.requirePage('identity-diag', 'read'), async (req, res) => {
  try {
    const data = await sdp.changesHealth();
    res.json({ success: true, ...data });
  } catch (err) {
    if (sdpScopeMiss(err)) {
      return res.status(502).json({ success: false, code: 'SDP_SCOPE',
        error: 'SDP OAuth token lacks the changes scope' });
    }
    console.error('[SDP] changesHealth error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/sdp/changes/create
// Body: { title, description, changeType?, scheduledStart?, scheduledEnd? }
// Times are epoch milliseconds. Requester is the signed-in technician.
router.post('/changes/create', rbac.requirePage('identity-diag', 'admin'), async (req, res) => {
  const { title, description, changeType, scheduledStart, scheduledEnd } = req.body;
  if (!title || String(title).trim().length < 5) {
    return res.status(400).json({ error: 'title of at least 5 characters is required' });
  }
  const toMs = (v) => {
    if (v == null || v === '') return null;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : NaN;
  };
  const startMs = toMs(scheduledStart), endMs = toMs(scheduledEnd);
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) {
    return res.status(400).json({ error: 'scheduledStart/scheduledEnd must be epoch milliseconds' });
  }
  if (startMs && endMs && endMs <= startMs) {
    return res.status(400).json({ error: 'scheduledEnd must be after scheduledStart' });
  }
  try {
    const who = req.user || {};
    const change = await sdp.createChange({
      title: String(title).trim(),
      description: description || '',
      changeType: changeType || undefined,
      scheduledStart: startMs || undefined,
      scheduledEnd: endMs || undefined,
      requesterEmail: who.email || undefined,
      requesterName: who.displayName || who.email || undefined
    });
    res.json({ success: true, change });
  } catch (err) {
    if (sdpScopeMiss(err)) {
      return res.status(502).json({ success: false, code: 'SDP_SCOPE',
        error: 'SDP OAuth token lacks the changes scope' });
    }
    const detail = err.response && err.response.data
      ? JSON.stringify(err.response.data).slice(0, 400) : err.message;
    console.error('[SDP] createChange error:', detail);
    res.status(500).json({ error: 'Failed to create change', detail });
  }
});

module.exports = router;
