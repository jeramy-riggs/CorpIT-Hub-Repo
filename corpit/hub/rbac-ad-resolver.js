// =====================================================================
// rbac-ad-resolver.js  (v1.0.0)
//
// RBAC v3: resolves a user's platform roles from Active Directory at login.
//
//   resolveRoles(pool, email)  ->  {
//     ok: true,  roles: ['tier2','superadmin', ...], dn, displayName
//   }  or  {
//     ok: false, code: 'USER_NOT_FOUND' | 'AMBIGUOUS_USER' | 'DIRECTORY_UNAVAILABLE',
//     message
//   }
//
// Design:
//   - One short-lived LDAP connection per resolution. Resolution happens at
//     most once per user per 24h (staleness window enforced by the caller),
//     so connection reuse is not worth the state.
//   - DIRECT membership only (memberOf attribute). Entra app assignment also
//     evaluates direct membership only, so nesting would diverge the two
//     gates. Keep groups flat.
//   - Tight timeouts (5s connect / 5s op): a dead DC must fail a login fast,
//     not hang it.
//   - Uses the same env vars as the rest of the platform:
//       LDAP_URL, LDAP_BASE_DN, LDAP_BIND_USER, LDAP_BIND_PASS
//   - Writes rbac_user_roles + stamps rbac_users.roles_resolved_at in one
//     transaction. Creates the rbac_users row on first login.
// =====================================================================

'use strict';

const ldap = require('ldapjs');

const LDAP_URL     = process.env.LDAP_URL;
const LDAP_BASE_DN = process.env.LDAP_BASE_DN;
const LDAP_BIND    = process.env.LDAP_BIND_USER;
const LDAP_PASS    = process.env.LDAP_BIND_PASS;

if (!LDAP_URL || !LDAP_BASE_DN || !LDAP_BIND || !LDAP_PASS) {
  console.error('[rbac-ad-resolver] FATAL: LDAP_URL / LDAP_BASE_DN / LDAP_BIND_USER / LDAP_BIND_PASS missing in env');
}

// ---------- low-level helpers -----------------------------------------

function connectAndBind() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_URL,
      connectTimeout: 5000,
      timeout: 5000,
    });
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { client.destroy(); } catch (e) { /* ignore */ }
      reject(err);
    };
    client.on('error', fail);
    client.on('connectError', fail);
    client.bind(LDAP_BIND, LDAP_PASS, (err) => {
      if (err) return fail(err);
      if (settled) return;
      settled = true;
      resolve(client);
    });
  });
}

function searchOnce(client, base, filter, attributes) {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { scope: 'sub', filter, attributes }, (err, res) => {
      if (err) return reject(err);
      res.on('searchEntry', (entry) => {
        const obj = { dn: entry.dn ? entry.dn.toString() : null };
        const attrs = entry.attributes || [];
        for (const a of attrs) {
          const vals = a.values || a.vals || [];
          obj[a.type] = vals.length === 1 ? vals[0] : vals.slice();
        }
        entries.push(obj);
      });
      res.on('error', reject);
      res.on('end', () => resolve(entries));
    });
  });
}

function closeQuietly(client) {
  try { client.unbind(() => {}); } catch (e) { /* ignore */ }
  try { client.destroy(); } catch (e) { /* ignore */ }
}

// Escape special characters for use inside an LDAP filter (RFC 4515)
function escapeFilterValue(v) {
  return String(v)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

function normDn(dn) {
  // DN comparison: case-insensitive, whitespace around commas ignored.
  return String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',').trim();
}

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

// ---------- main entry -------------------------------------------------

/**
 * Resolve a user's roles from AD and persist them.
 *
 * @param {object} pool   mysql2/promise pool
 * @param {string} email  validated, lowercased email from the JWT
 * @returns {Promise<object>} see header comment
 */
async function resolveRoles(pool, email) {
  // 1. Load the role -> AD group DN map from the database first, so a DB
  //    problem is reported as such rather than blamed on the directory.
  let roleMap; // [{ role_key, dnNorm }]
  try {
    const [rows] = await pool.query(
      'SELECT role_key, ad_group_dn FROM rbac_roles WHERE ad_group_dn IS NOT NULL'
    );
    roleMap = rows.map(r => ({ role_key: r.role_key, dnNorm: normDn(r.ad_group_dn) }));
  } catch (err) {
    console.error('[rbac-ad-resolver] role map query failed:', err.message);
    return { ok: false, code: 'DIRECTORY_UNAVAILABLE', message: 'Role configuration unavailable' };
  }

  // 2. Find the user in AD by mail, falling back to userPrincipalName.
  let client;
  try {
    client = await connectAndBind();
  } catch (err) {
    console.error('[rbac-ad-resolver] LDAP connect/bind failed:', err.message);
    return { ok: false, code: 'DIRECTORY_UNAVAILABLE', message: 'Directory services unreachable' };
  }

  let entries;
  try {
    const esc = escapeFilterValue(email);
    const attrs = ['distinguishedName', 'memberOf', 'displayName', 'mail', 'userPrincipalName', 'userAccountControl'];

    entries = await searchOnce(
      client, LDAP_BASE_DN,
      `(&(objectClass=user)(objectCategory=person)(mail=${esc}))`,
      attrs
    );
    if (entries.length === 0) {
      entries = await searchOnce(
        client, LDAP_BASE_DN,
        `(&(objectClass=user)(objectCategory=person)(userPrincipalName=${esc}))`,
        attrs
      );
    }
  } catch (err) {
    closeQuietly(client);
    console.error('[rbac-ad-resolver] LDAP search failed:', err.message);
    return { ok: false, code: 'DIRECTORY_UNAVAILABLE', message: 'Directory search failed' };
  }
  closeQuietly(client);

  if (entries.length === 0) {
    return { ok: false, code: 'USER_NOT_FOUND', message: 'No AD account matches this sign-in address' };
  }
  if (entries.length > 1) {
    console.warn('[rbac-ad-resolver] ambiguous match for', email, '->', entries.map(e => e.dn).join(' | '));
    return { ok: false, code: 'AMBIGUOUS_USER', message: 'Multiple AD accounts match this sign-in address' };
  }

  const user = entries[0];
  if ((Number(user.userAccountControl) || 0) & 2) {
    return {ok:false,code:'ACCOUNT_DISABLED',message:'This AD account is disabled'};
  }
  const memberDns = asArray(user.memberOf).map(normDn);
  const roles = roleMap
    .filter(r => memberDns.includes(r.dnNorm))
    .map(r => r.role_key);

  // 3. Persist: rewrite this user's role rows + stamp resolution, atomically.
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    await conn.query(
      `INSERT INTO rbac_users (email, display_name, is_active, roles_resolved_at)
         VALUES (?, ?, 1, NOW())
       ON DUPLICATE KEY UPDATE
         display_name      = COALESCE(VALUES(display_name), display_name),
         roles_resolved_at = NOW()`,
      [email, user.displayName || null]
    );

    await conn.query('DELETE FROM rbac_user_roles WHERE email = ?', [email]);
    if (roles.length > 0) {
      const values = roles.map(r => [email, r]);
      await conn.query('INSERT INTO rbac_user_roles (email, role_key) VALUES ?', [values]);
    }

    await conn.commit();
  } catch (err) {
    try { await conn.rollback(); } catch (e) { /* ignore */ }
    conn.release();
    console.error('[rbac-ad-resolver] persist failed:', err.message);
    return { ok: false, code: 'DIRECTORY_UNAVAILABLE', message: 'Could not record resolved roles' };
  }
  conn.release();

  return {
    ok: true,
    roles,
    dn: user.dn,
    displayName: user.displayName || null,
  };
}

module.exports = { resolveRoles };
