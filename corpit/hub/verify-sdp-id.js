// verify-sdp-id.js
// One-off check: compares SDP's internal `id` vs `display_id` for a known
// ticket, to confirm which one the WorkOrder.do?woID= URL parameter expects.
// Run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node verify-sdp-id.js 22687

const axios = require('axios');
const qs = require('querystring');

const DISPLAY_ID = process.argv[2] || '22687';

async function getToken() {
  const params = qs.stringify({
    grant_type: 'refresh_token',
    client_id: process.env.SDP_CLIENT_ID,
    client_secret: process.env.SDP_CLIENT_SECRET,
    refresh_token: process.env.SDP_REFRESH_TOKEN,
  });
  const res = await axios.post('https://accounts.zoho.com/oauth/v2/token', params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (!res.data.access_token) throw new Error('Token refresh failed: ' + JSON.stringify(res.data));
  return res.data.access_token;
}

(async () => {
  try {
    const token = await getToken();
    const base = `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/api/v3`;
    const input_data = JSON.stringify({
      list_info: {
        row_count: 5,
        start_index: 1,
        sort_field: 'created_time',
        sort_order: 'desc',
      },
    });
    const res = await axios.get(`${base}/requests`, {
      params: { input_data },
      headers: {
        'Authorization': `Zoho-oauthtoken ${token}`,
        'Accept': 'application/vnd.manageengine.sdp.v3+json',
      },
    });
    const all = res.data.requests || [];
    console.log(JSON.stringify(all.map(x => ({ id: x.id, display_id: x.display_id, subject: x.subject })), null, 2));
    const r = all.find(x => String(x.display_id) === String(DISPLAY_ID));
    if (!r) {
      console.log(`(display_id=${DISPLAY_ID} not among these 5 most recent — that's fine, just checking id vs display_id shape)`);
      return;
    }
    console.log(JSON.stringify({ id: r.id, display_id: r.display_id, subject: r.subject }, null, 2));
    console.log(r.id === r.display_id ? 'SAME — id equals display_id' : 'DIFFERENT — id and display_id do not match');
  } catch (err) {
    console.error('ERROR:', err.response ? JSON.stringify(err.response.data) : err.message);
  }
})();
