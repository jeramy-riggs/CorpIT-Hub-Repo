// it-profile.js (v1.0.0) — tiny shared client for the My Profile API on corpit.
//
//   itProfile.record({verb, object_type, object_id, label, url, meta})  fire-and-forget activity event
//   itProfile.open(link)         record an app open from a hub tile {id, name, href}
//   itProfile.pins()             -> Promise<{pins:[], links:[], fallback:[]}>
//   itProfile.togglePin(id)      -> Promise<{pinned, pins, links}>
//   itProfile.saveSearch({name, kind, query, params})
//
// Every call is self-scoped server-side; nothing here carries an identity. Errors are
// swallowed on purpose: recording activity must never break the page that records it.
(function () {
  'use strict';
  if (window.itProfile) return;
  var BASE = '/api/profile';
  var page = (document.body && document.body.getAttribute('data-profile-source')) ||
             (location.pathname === '/' || /\/landing\.html$/.test(location.pathname) ? 'landing' :
              /IT_Inventory_App/.test(location.pathname) ? 'it-inventory' :
              /my-profile/.test(location.pathname) ? 'my-profile' : location.pathname.replace(/^\//, '').slice(0, 40));

  function post(path, body, keepalive) {
    try {
      return fetch(BASE + path, {
        method: 'POST', credentials: 'same-origin', keepalive: !!keepalive,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {})
      }).then(function (r) { return r.ok ? (r.status === 204 ? null : r.json()) : Promise.reject(new Error('HTTP ' + r.status)); });
    } catch (e) { return Promise.reject(e); }
  }
  function get(path) {
    return fetch(BASE + path, { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)); });
  }

  window.itProfile = {
    source: page,
    record: function (ev) {
      var body = Object.assign({ source: page }, ev || {});
      return post('/events', body, true).catch(function () {});
    },
    open: function (link) {
      if (!link) return;
      return window.itProfile.record({ verb: 'open', object_type: 'app', object_id: link.id, label: 'Opened ' + (link.name || link.title || link.id), url: link.href || link.url });
    },
    view: function (type, id, label, url, meta) {
      return window.itProfile.record({ verb: 'view', object_type: type, object_id: id, label: label, url: url, meta: meta });
    },
    pins: function () { return get('/pins'); },
    setPins: function (pins) {
      return fetch(BASE + '/pins', { method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pins: pins, source: page }) })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)); });
    },
    togglePin: function (id) { return post('/pins/toggle', { id: id, source: page }); },
    saveSearch: function (s) { return post('/saved-searches', Object.assign({ source: page }, s || {})); },
    recent: function () { return get('/recent'); }
  };
})();
