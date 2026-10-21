'use strict';
const ldap = require('ldapjs');
const ldapSecure = require('./ldap-secure'); // ldapjs client with StartTLS before every bind
const { escapeFilterValue } = require('./identity-ldap');

function getLdapClient() {
  return new Promise((resolve, reject) => {
    const client = ldapSecure.createClient({
      url: process.env.LDAP_URL || 'ldap://10.9.64.80:389',
      connectTimeout: 10000,
      timeout: 15000,
    });
    client.on('error', (err) => reject(err));
    client.bind(
      process.env.LDAP_BIND_USER,
      process.env.LDAP_BIND_PASS,
      (err) => {
        if (err) return reject(new Error('LDAP bind failed: ' + err.message));
        resolve(client);
      }
    );
  });
}

function findUserDN(client, identity) {
  return new Promise((resolve, reject) => {
    const baseDN = process.env.LDAP_BASE_DN || 'DC=nrpi,DC=local';
    const escaped = escapeFilterValue(identity);
    const filter = '(|(sAMAccountName=' + escaped + ')(userPrincipalName=' + escaped + ')(mail=' + escaped + '))';
    client.search(baseDN, {
      filter: filter,
      scope: 'sub',
      attributes: ['dn', 'sAMAccountName', 'displayName'],
      sizeLimit: 1,
    }, (err, res) => {
      if (err) return reject(err);
      let found = null;
      res.on('searchEntry', (entry) => {
        found = {
          dn: entry.dn.toString(),
          sam: entry.ppiAttributes ? entry.attributes.find(a => a.type === 'sAMAccountName') : null,
        };
        // ldapjs v3 uses entry.pojo or entry.attributes
        if (entry.pojo) {
          found.dn = entry.pojo.objectName;
          var samAttr = entry.pojo.attributes.find(function(a) { return a.type === 'sAMAccountName'; });
          found.sam = samAttr ? samAttr.values[0] : identity;
          var dnAttr = entry.pojo.attributes.find(function(a) { return a.type === 'displayName'; });
          found.displayName = dnAttr ? dnAttr.values[0] : '';
        }
      });
      res.on('error', (err) => reject(err));
      res.on('end', () => {
        if (!found) return reject(new Error('User not found: ' + identity));
        resolve(found);
      });
    });
  });
}

/**
 * Unlock a locked AD account by setting lockoutTime to 0
 */
async function unlockAccount(identity) {
  const client = await getLdapClient();
  try {
    const user = await findUserDN(client, identity);
    return new Promise((resolve, reject) => {
      const change = new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({
          type: 'lockoutTime',
          values: ['0'],
        }),
      });
      client.modify(user.dn, change, (err) => {
        client.unbind();
        if (err) return reject(new Error('Unlock failed: ' + err.message));
        console.log('[identity-actions] Unlocked account:', identity, 'DN:', user.dn);
        resolve({ success: true, action: 'unlock', identity: identity, dn: user.dn });
      });
    });
  } catch (err) {
    try { client.unbind(); } catch (e) {}
    throw err;
  }
}

/**
 * Force password change at next logon by setting pwdLastSet to 0
 */
async function forcePasswordReset(identity) {
  const client = await getLdapClient();
  try {
    const user = await findUserDN(client, identity);
    return new Promise((resolve, reject) => {
      const change = new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({
          type: 'pwdLastSet',
          values: ['0'],
        }),
      });
      client.modify(user.dn, change, (err) => {
        client.unbind();
        if (err) return reject(new Error('Password reset failed: ' + err.message));
        console.log('[identity-actions] Forced password reset:', identity, 'DN:', user.dn);
        resolve({ success: true, action: 'force-password-reset', identity: identity, dn: user.dn });
      });
    });
  } catch (err) {
    try { client.unbind(); } catch (e) {}
    throw err;
  }
}

module.exports = { unlockAccount, forcePasswordReset };
