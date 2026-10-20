'use strict';

const MAX_AGE_MS = 24 * 60 * 60 * 1000;
function failure(code, message) { const error = new Error(message); error.code = code; return error; }
function readList(response, keys, label) {
  if (!response || response.status !== 200) {
    const status = Number(response && response.status);
    throw failure('ZDX_UPSTREAM', label + ' HTTP ' + (Number.isInteger(status) ? status : 'unavailable') + '; previous evidence retained');
  }
  const body = response.body;
  if (!body || typeof body !== 'object' || body.error || body.ok === false || body.success === false) throw failure('ZDX_SHAPE', label + ' returned invalid data; previous evidence retained');
  const items = Array.isArray(body) ? body : keys.map(key => body[key]).find(Array.isArray);
  if (!items || items.some(item => !item || typeof item !== 'object' || Array.isArray(item))) throw failure('ZDX_SHAPE', label + ' did not return a valid list; previous evidence retained');
  if (body.truncated || body.partial || ((body.has_more === true || body.hasMore === true) && !(body.next_offset ?? body.nextOffset))) throw failure('ZDX_PARTIAL', label + ' returned incomplete data; previous evidence retained');
  return items;
}
async function fetchList(get, path, keys, { maxPages = 25, maxRows = 10000 } = {}) {
  const rows = [], offsets = new Set();
  let offset,expectedTotal=null;
  for (let page = 0; page < maxPages; page++) {
    const result = await get(path + (offset == null ? '' : '&offset=' + encodeURIComponent(offset)));
    const chunk = readList(result, keys, path.split('?')[0]); rows.push(...chunk);
    const total=result.body.total_count ?? result.body.totalCount ?? result.body.total;
    if(total!=null){
      if(!Number.isInteger(Number(total)) || Number(total)<0 || (expectedTotal!=null && expectedTotal!==Number(total))) throw failure('ZDX_PARTIAL','ZDX pagination totals changed or are invalid; previous evidence retained');
      expectedTotal=Number(total);
    }
    if (rows.length > maxRows) throw failure('ZDX_PARTIAL', 'ZDX list exceeded its row limit; previous evidence retained');
    const next = result.body.next_offset ?? result.body.nextOffset;
    if (next == null || next === '' || next === false) {
      if (expectedTotal != null && expectedTotal!==rows.length) throw failure('ZDX_PARTIAL','ZDX list total differs from returned rows; previous evidence retained');
      return rows;
    }
    if (!['string','number'].includes(typeof next) || !chunk.length || offsets.has(String(next))) throw failure('ZDX_PARTIAL', 'ZDX pagination did not advance; previous evidence retained');
    offsets.add(String(next)); offset = next;
  }
  throw failure('ZDX_PARTIAL', 'ZDX list exceeded its page limit; previous evidence retained');
}
function evidenceCutoff(now = new Date()) {
  const date = new Date(now);
  if (!Number.isFinite(date.getTime())) throw failure('ZDX_TIME', 'Invalid collection time');
  // The existing MySQL columns are DATETIME(0); align bounds and writes so
  // fractional-second rounding cannot exclude the row just collected.
  date.setUTCMilliseconds(0);
  return { oldest: new Date(date.getTime() - MAX_AGE_MS), newest: date };
}
async function replaceUserIsp(connection, cutoff) {
  // DELETE is transactional in InnoDB; TRUNCATE would implicitly commit.
  await connection.query('DELETE FROM zdx_user_isp');
  await connection.query(
    `INSERT INTO zdx_user_isp (userid,home_isp,home_city,home_country,device_count,updated_at)
     SELECT userid,SUBSTRING_INDEX(GROUP_CONCAT(isp ORDER BY isp),',',1),
       SUBSTRING_INDEX(GROUP_CONCAT(city ORDER BY city),',',1),
       SUBSTRING_INDEX(GROUP_CONCAT(country_code ORDER BY country_code),',',1),COUNT(*),MIN(crawled_at)
     FROM zdx_device_geo WHERE userid IS NOT NULL AND isp IS NOT NULL AND crawl_status='ok'
       AND crawled_at BETWEEN ? AND ? GROUP BY userid`, [cutoff.oldest,cutoff.newest]);
}
async function readRollupEvidence(pool, key, maxAgeH = 24) {
  const table = { zdx_presence_geo:'zdx_presence_geo',zdx_user_isp:'zdx_user_isp' }[key];
  if (!table) throw failure('ZDX_TABLE','Unsupported evidence source');
  const filter = key === 'zdx_user_isp' ? 'userid IS NOT NULL AND isp IS NOT NULL' : 'country_code IS NOT NULL';
  const [rows] = await pool.query(
    `SELECT r.n,r.stored_updated_at,s.source_oldest_at,s.source_newest_at,
       s.source_newest_at > UTC_TIMESTAMP() + INTERVAL 30 SECOND AS source_future,
       LEAST(r.oldest_stored_at,s.source_newest_at) AS evidence_at,
       TIMESTAMPDIFF(SECOND,LEAST(r.oldest_stored_at,s.source_newest_at),UTC_TIMESTAMP()) AS age_seconds
     FROM (SELECT COUNT(*) AS n,MIN(updated_at) AS oldest_stored_at,MAX(updated_at) AS stored_updated_at FROM ${table}) r
     CROSS JOIN (SELECT MIN(crawled_at) AS source_oldest_at,MAX(crawled_at) AS source_newest_at
       FROM zdx_device_geo WHERE crawl_status='ok' AND ${filter}) s`);
  const row = rows[0] || {}, n = Number(row.n || 0);
  const seconds = row.age_seconds == null ? NaN : Number(row.age_seconds);
  const result = { rows:n,newest:row.evidence_at || null,storedUpdatedAt:row.stored_updated_at || null,
    sourceOldestAt:row.source_oldest_at || null,sourceNewestAt:row.source_newest_at || null,
    freshnessBasis:'Device observations, capped by stored rollup evidence; rebuilding a rollup does not refresh observations',
    ageHours:Number.isFinite(seconds) && seconds >= 0 ? Math.round(seconds / 360) / 10 : null,
    state:n === 0 ? 'empty' : !row.evidence_at || row.source_future || !Number.isFinite(seconds) || seconds < 0 ? 'unknown' : seconds > maxAgeH * 3600 ? 'stale' : 'ok' };
  if (result.state === 'unknown') result.error = 'Underlying device observation time is missing or invalid';
  return result;
}
module.exports = { failure,readList,fetchList,evidenceCutoff,replaceUserIsp,readRollupEvidence };
