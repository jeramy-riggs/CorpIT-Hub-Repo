// sdp-lookup.js
// ServiceDesk Plus OnDemand integration for IT Command
// Uses Zoho OAuth 2.0 with auto-refresh token management

const axios = require('axios');
const qs = require('querystring');

// --- Token cache (in-memory, lives as long as the process runs) ---
let tokenCache = {
  access_token: null,
  expires_at: null
};

// --- Get a valid access token, refreshing if needed ---
async function getAccessToken() {
  const now = Date.now();

  if (tokenCache.access_token && tokenCache.expires_at && (tokenCache.expires_at - now) > 5 * 60 * 1000) {
    return tokenCache.access_token;
  }

  const params = qs.stringify({
    grant_type:    'refresh_token',
    client_id:     process.env.SDP_CLIENT_ID,
    client_secret: process.env.SDP_CLIENT_SECRET,
    refresh_token: process.env.SDP_REFRESH_TOKEN
  });

  const response = await axios.post(
    'https://accounts.zoho.com/oauth/v2/token',
    params,
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  if (!response.data.access_token) {
    throw new Error('Zoho token refresh failed: ' + JSON.stringify(response.data));
  }

  tokenCache.access_token = response.data.access_token;
  tokenCache.expires_at   = now + (response.data.expires_in * 1000);

  return tokenCache.access_token;
}

// --- Build the base API URL ---
function sdpBase() {
  return `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/api/v3`;
}

// --- SDP GET helper — never sends Content-Type (SDP rejects it with 415) ---
async function sdpGet(path, inputData) {
  const token = await getAccessToken();
  const url = `${sdpBase()}${path}`;

  const response = await axios.get(url, {
    headers: {
      'Authorization': `Zoho-oauthtoken ${token}`,
      'Accept': 'application/vnd.manageengine.sdp.v3+json'
    },
    params: inputData != null ? { input_data: JSON.stringify(inputData) } : {}
  });

  return response.data;
}

// --- SDP POST helper ---
async function sdpPost(path, inputData) {
  const token = await getAccessToken();
  const url = `${sdpBase()}${path}`;

  const response = await axios.post(
    url,
    qs.stringify({ input_data: JSON.stringify(inputData) }),
    {
      headers: {
        'Authorization':  `Zoho-oauthtoken ${token}`,
        'Content-Type':   'application/x-www-form-urlencoded',
        'Accept':         'application/vnd.manageengine.sdp.v3+json'
      }
    }
  );

  return response.data;
}

// --- Health check — just list 1 request to confirm connectivity ---
async function healthCheck() {
  const data = await sdpGet('/requests', {
    list_info: { row_count: 1, start_index: 1 }
  });
  return data;
}

// --- Fetch tickets for a user by email ---
async function getTicketsByEmail(email) {
  const data = await sdpGet('/requests', {
    list_info: {
      row_count: 20,
      start_index: 1,
      sort_field: 'created_time',
      sort_order: 'desc',
      search_criteria: [
        {
          field: 'requester.email_id',
          condition: 'is',
          value: email,
          logical_operator: 'AND'
        }
      ]
    }
  });

  const requests = data.requests || [];

  return requests.map(r => ({
    id:         r.id,
    subject:    r.subject,
    status:     r.status?.name || 'Unknown',
    priority:   r.priority?.name || 'None',
    created:    r.created_time?.display_value || '',
    updated:    r.last_updated_time?.display_value || '',
    technician: r.technician?.name || 'Unassigned',
    url:        `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.id}`
  }));
}

// --- Add a note to an existing ticket ---
// SDP v3 wraps a note as request_note; "note" is refused (EXTRA_KEY_FOUND_IN_JSON, 2026-09-25).
async function addNoteToTicket(ticketId, noteText, isPublic = false) {
  const data = await sdpPost(`/requests/${ticketId}/notes`, {
    request_note: {
      description:              noteText,
      show_to_requester:        isPublic,
      notify_technician:        false,
      add_to_linked_requests:   false
    }
  });
  return data;
}

// --- Create a new ticket ---
// mode/category/subcategory became mandatory on the SDP request form (Aug 2026).
// Defaults target automated security alerts; override via env without code changes.
async function createTicket(payload) {
  const data = await sdpPost('/requests', {
    request: {
      subject:     payload.subject,
      description: payload.description,
      requester: {
        name:     payload.requesterName || payload.requesterEmail,
        email_id: payload.requesterEmail
      },
      priority:    { name: payload.priority || 'Normal' },
      mode:        { name: payload.mode        || process.env.SDP_DEFAULT_MODE        || 'E-Mail' },
      category:    { name: payload.category    || process.env.SDP_DEFAULT_CATEGORY    || 'System Notifications' },
      subcategory: { name: payload.subcategory || process.env.SDP_DEFAULT_SUBCATEGORY || 'Security Tool Alert' }
    }
  });

  const r = data.request;
  return {
    id:         r.id,
    display_id: r.display_id || r.id,
    url: `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.id}`
  };
}

// --- Fetch all requests (all statuses) for the Requests module ---
// Stale Tickets is computed later via a SQL view over this same table
// (status NOT IN ('Resolved','Closed') AND last_updated_at < 3 business
// days ago) — not a separate SDP call.
async function getAllRequests({ page = 1, rowCount = 100 } = {}) {
  const sixMonthsAgoMs = Date.now() - (180 * 24 * 60 * 60 * 1000);
  const data = await sdpGet('/requests', {
    list_info: {
      row_count: rowCount,
      start_index: ((page - 1) * rowCount) + 1,
      sort_field: 'created_time',
      sort_order: 'desc',
      search_criteria: [ { field: 'created_time', condition: 'greater than', value: sixMonthsAgoMs, logical_operator: 'AND' } ],
      fields_required: [
        'id', 'priority', 'category', 'subcategory', 'department', 'status',
        'requester', 'technician', 'due_by_time', 'created_time',
        'last_updated_time', 'completed_time', 'subject', 'display_id', 'mode', 'created_by', 'site'
      ]
    }
  });

  const requests = data.requests || [];

  return {
    hasMoreRows: data.list_info?.has_more_rows ?? false,
    rows: requests.map(r => ({
      id: r.display_id,
      sdp_internal_id: r.id,
      subject: r.subject,
      requester: r.requester?.name ?? null,
      requester_email: r.requester?.email_id ?? null,
      technician: r.technician?.name ?? 'Unassigned',
      // The SSO ticket queue keys off this, never off the display name — two
      // staff can share a name, and that would leak one person's queue to another.
      technician_email: r.technician?.email_id ? String(r.technician.email_id).trim().toLowerCase() : null,
      priority: r.priority?.name ?? 'None',
      status: r.status?.name ?? 'Unknown',
      department: r.department ?? null,
      category: r.category?.name ?? null,
      subcategory: r.subcategory?.name ?? null,
      mode: r.mode?.name ?? null,
      site: r.site?.name ?? null,
      site_id: r.site?.id ?? null,
      created_by_technician: (r.created_by && r.created_by.is_technician === true) ? 1 : 0,
      created_by_name: r.created_by?.name ?? null,
      created_at: r.created_time?.value ? new Date(+r.created_time.value) : null,
      due_by: r.due_by_time?.value ? new Date(+r.due_by_time.value) : null,
      last_updated_at: r.last_updated_time?.value ? new Date(+r.last_updated_time.value) : null,
      resolved_at: ['Resolved','Closed'].includes(r.status?.name) && r.completed_time?.value ? new Date(+r.completed_time.value) : null,
    }))
  };
}


// Confirm whether a request (by display_id) still exists in SDP.
// Used by the collector's reconcile step to safely detect merged/deleted tickets.
// Returns { absent: true } only on an explicit empty result; { absent: false }
// if it still exists. Throws on transient/HTTP errors so the caller can skip.
async function getRequestByDisplayId(displayId) {
  const data = await sdpGet('/requests', {
    list_info: {
      row_count: 1,
      start_index: 1,
      search_criteria: [{ field: 'display_id', condition: 'is', value: String(displayId) }],
      fields_required: ['id', 'display_id', 'status']
    }
  });
  const reqs = data.requests || [];
  return { absent: reqs.length === 0, request: reqs[0] || null };
}

// --- Fetch a single request by internal ID (used by Sign-In Watch pause) ---
// Returns null if SDP responds without a request object; throws on HTTP errors.
async function getRequestById(requestId) {
  let data;
  try {
    data = await sdpGet(`/requests/${encodeURIComponent(String(requestId))}`, null);
  } catch (e) {
    if (e.response && e.response.status === 404) return null; // ticket deleted/closed → resume
    throw e;
  }
  const r = data.request;
  if (!r) return null;
  return {
    id:         r.id,
    display_id: r.display_id || r.id,
    subject:    r.subject || null,
    status:     r.status?.name || 'Unknown',
    url:        `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.id}`
  };
}

// --- SDP PUT helper (2026-09-25, My Profile Claude limit approvals) ---
// Same form-encoded input_data shape as sdpPost; SDP v3 takes PUT for edits and closure.
async function sdpPut(path, inputData) {
  const token = await getAccessToken();
  const url = `${sdpBase()}${path}`;

  const response = await axios.put(
    url,
    qs.stringify({ input_data: JSON.stringify(inputData) }),
    {
      headers: {
        'Authorization':  `Zoho-oauthtoken ${token}`,
        'Content-Type':   'application/x-www-form-urlencoded',
        'Accept':         'application/vnd.manageengine.sdp.v3+json'
      }
    }
  );

  return response.data;
}

// SDP's own words for a refusal, never the token or the request body.
function sdpErrorText(e) {
  const st = e && e.response && e.response.status;
  const rs = e && e.response && e.response.data && e.response.data.response_status;
  const msgs = [];
  (Array.isArray(rs) ? rs : (rs ? [rs] : [])).forEach(r => (r.messages || []).forEach(m => {
    msgs.push([m.field, m.message || m.status_code].filter(Boolean).join(': '));
  }));
  return (st ? 'HTTP ' + st : (e && e.message) || 'error') + (msgs.length ? ' - ' + msgs.join('; ').slice(0, 300) : '');
}

// --- Set the resolution text on a request ---
async function setResolution(requestId, text) {
  return sdpPut(`/requests/${encodeURIComponent(String(requestId))}`, {
    request: { resolution: { content: text } }
  });
}

// --- Close a request, then read it back ---
// Resolves { ok, status, via, error }. ok is true ONLY when a fresh GET reads the
// request as Closed: a 200 from the close call is not taken as proof, so a caller
// can never record "closed" for a ticket SDP left open.
//   1. PUT /requests/{id}/close with closure_info (the documented close call)
//   2. if that is refused, PUT /requests/{id} with status Closed
async function closeTicket(requestId, comments) {
  const id = encodeURIComponent(String(requestId));
  // The closure comments are plain text on one line, at most 250 characters (SDP v3; a longer
  // requester_ack_comments was refused 2026-09-25). The full text goes in the note and the resolution.
  const line = String(comments || 'Closed automatically by CorpIT Hub.').replace(/\s+/g, ' ').trim();
  const text = line.length > 250 ? line.slice(0, 247) + '...' : line;
  const errors = [];
  let via = null;
  try {
    await sdpPut(`/requests/${id}/close`, {
      request: { closure_info: { requester_ack_resolution: true, requester_ack_comments: text, closure_comments: text } }
    });
    via = 'close';
  } catch (e) {
    errors.push('close: ' + sdpErrorText(e));
    try {
      await sdpPut(`/requests/${id}`, { request: { status: { name: 'Closed' } } });
      via = 'status';
    } catch (e2) {
      errors.push('status: ' + sdpErrorText(e2));
    }
  }
  let status = null;
  try {
    const r = await getRequestById(requestId);
    status = r ? r.status : null;
  } catch (e) {
    errors.push('verify: ' + sdpErrorText(e));
  }
  const ok = status === 'Closed';
  return { ok, status, via, error: ok ? null : (errors.join(' | ') || ('SDP reads the ticket as ' + (status || 'unknown'))) };
}

// --- Change (CAB) helpers — ported from ITAM api-beta 2026-09-08 ---
// Requires a refresh token carrying SDPOnDemand.changes.ALL; a requests-only
// token makes /changes answer 401, which the route surfaces as SDP_SCOPE.

// --- Changes reachability probe ---
async function changesHealth() {
  const data = await sdpGet('/changes', {
    list_info: { row_count: 1, start_index: 1 }
  });
  return { reachable: true, count: (data.changes || []).length };
}

// --- Create a change (CAB) request ---
async function createChange(payload) {
  const change = {
    title:       payload.title,
    description: payload.description || ''
  };

  if (payload.changeType)     change.change_type          = { name: payload.changeType };
  if (payload.scheduledStart) change.scheduled_start_time = { value: String(payload.scheduledStart) };
  if (payload.scheduledEnd)   change.scheduled_end_time   = { value: String(payload.scheduledEnd) };
  if (payload.requesterEmail) {
    // NB: the changes API rejects a `requester` key (EXTRA_KEY_FOUND_IN_JSON)
    change.change_requester = {
      email_id: payload.requesterEmail,
      name:     payload.requesterName || payload.requesterEmail
    };
  }

  const data = await sdpPost('/changes', { change });
  const c = data.change;

  return {
    id:         c.id,
    // changes return display_id as an OBJECT, unlike requests
    display_id: (c.display_id && c.display_id.display_value) || c.id,
    url:        `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/ui/changes/${c.id}/details`
  };
}

module.exports = {
  sdpGet,             // shared read helper (My Profile live ticket/change reads, 2026-09-05)
  getRequestById,
  getRequestByDisplayId,
  healthCheck,
  getTicketsByEmail,
  addNoteToTicket,
  createTicket,
  getAllRequests,
  changesHealth,
  createChange,
  setResolution,      // My Profile Claude limit approvals (2026-09-25)
  closeTicket,
  sdpErrorText
};
