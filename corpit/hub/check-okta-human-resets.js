const axios = require('axios');
(async () => {
  const since = new Date(Date.now() - 30*24*3600*1000).toISOString();
  const filter = encodeURIComponent('eventType eq "user.account.reset_password"');
  const url = process.env.OKTA_BASE_URL + '/api/v1/logs?since=' + since + '&filter=' + filter + '&limit=200';
  const resp = await axios.get(url, { headers: { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN } });
  const human = resp.data.filter(e => {
    const actorId = e.actor && e.actor.id;
    const targetUserId = (e.target || []).find(t => t.type === 'User');
    const isSystem = e.actor && (e.actor.type !== 'User' || e.actor.displayName === 'Okta System');
    return targetUserId && actorId !== targetUserId.id && !isSystem;
  });
  console.log('genuinely human-initiated, actor != target:', human.length);
  human.slice(0,10).forEach(e => console.log(' tech:', e.actor.displayName, '(' + e.actor.alternateId + ')', '-> user:', (e.target.find(t=>t.type==='User')||{}).displayName, '|', e.outcome.result, '|', e.published));
})();
