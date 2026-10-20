/* my-profile.js — corpit.nrpi.local My Profile (2026-09-05)
   Plain ES2018, no framework. Everything rendered here comes from /api/profile/*,
   which is self-scoped server-side. View switches are instant (no motion): they are a
   keyboard-frequency action. Cards animate once, on first paint of the Overview. */
(function () {
  'use strict';

  /* ───────────── icons (lucide-style, 24px viewBox) ───────────── */
  var ICONS = {
    home: '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    headset: '<path d="M3 11h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H3z"/><path d="M21 11h-3a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h3z"/><path d="M3 11v-1a9 9 0 0 1 18 0v1"/><path d="M21 16v1a3 3 0 0 1-3 3h-4"/>',
    clipboard: '<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/>',
    laptop: '<path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9"/><path d="M2 20h20"/><path d="M2 16h20"/>',
    settings: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    ticket: '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M13 5v2M13 17v2M13 11v2"/>',
    sparkle: '<path d="M12 3l1.9 5.6L19.5 10l-5.6 1.9L12 17.5l-1.9-5.6L4.5 10l5.6-1.4z"/><path d="M19 17l.8 2.2L22 20l-2.2.8L19 23l-.8-2.2L16 20l2.2-.8z"/>',
    star: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    'bar-chart': '<line x1="12" x2="12" y1="20" y2="10"/><line x1="18" x2="18" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="16"/>',
    bulb: '<path d="M9 18h6"/><path d="M10 22h4"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>',
    'arrow-left-right': '<polyline points="17 11 21 7 17 3"/><line x1="21" y1="7" x2="9" y2="7"/><polyline points="7 21 3 17 7 13"/><line x1="15" y1="17" x2="3" y2="17"/>',
    'arrow-left': '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4Z"/>',
    clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    palette: '<circle cx="13.5" cy="6.5" r=".5"/><circle cx="17.5" cy="10.5" r=".5"/><circle cx="8.5" cy="7.5" r=".5"/><circle cx="6.5" cy="12.5" r=".5"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/>',
    grid: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    lock: '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    refresh: '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>',
    activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M9 2v2M15 20v2M9 20v2M2 15h2M2 9h2M20 15h2M20 9h2"/>',
    eye: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
    mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    pin: '<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    'check-circle': '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    'chevron-right': '<polyline points="9 18 15 12 9 6"/>',
    external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    left: '<polyline points="15 18 9 12 15 6"/>', right: '<polyline points="9 18 15 12 9 6"/>',
    alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    'log-in': '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" x2="3" y1="12" y2="12"/>',
    key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    monitor: '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    up: '<polyline points="18 15 12 9 6 15"/>',
    book: '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/>',
    calendar: '<rect width="18" height="18" x="3" y="4" rx="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/>',
    thumb: '<path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2h0a3.13 3.13 0 0 1 3 3.88Z"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
    graduation: '<path d="M22 10v6M2 10l10-5 10 5-10 5z"/><path d="M6 12v5c3 3 9 3 12 0v-5"/>',
    compass: '<circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>',
    dollar: '<line x1="12" x2="12" y1="2" y2="22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
    /* Office conditions in the greeting banner. Byte-for-byte the same paths as
     * landing.html so the two heroes cannot drift into drawing different weather.
     *
     * ALL EIGHT keys the /api/weather route can emit are here, deliberately.
     * icon() returns an empty string for a name it does not know -- silently, no
     * console warning -- so a missing key is invisible until the sky does the
     * thing that emits it. landing.html shipped without rain, snow and storm and
     * the gap did not surface until the first wet day. */
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
    moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/>',
    cloud: '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
    'cloud-sun': '<path d="M12 2v2M4.9 4.9l1.4 1.4M2 12h2M19.1 4.9l-1.4 1.4M22 12h-2"/><path d="M9.6 8.5a4 4 0 1 1 5.9 4.5"/><path d="M16 19H8a4 4 0 1 1 .9-7.9"/><path d="M16 19a3 3 0 0 0 0-6h-.5"/>',
    rain: '<path d="M17.5 15H9a5 5 0 1 1 4.8-6.4h1.2a3.5 3.5 0 1 1 0 7Z"/><path d="M8 19v2M12 18v3M16 19v2"/>',
    snow: '<path d="M17.5 15H9a5 5 0 1 1 4.8-6.4h1.2a3.5 3.5 0 1 1 0 7Z"/><path d="M8 19h.01M8 22h.01M12 18h.01M12 21h.01M16 19h.01M16 22h.01"/>',
    fog: '<path d="M4 9h16M6 13h12M8 17h8"/>',
  };
  /* The route's condition vocabulary is sun / moon / cloud-sun / cloud / fog /
   * rain / snow / storm. 'storm' has no glyph of its own; alias rather than
   * rename, because that key belongs to weather-routes.js, not to this file. */
  ICONS.storm = ICONS.zap;
  function icon(n) { var d = ICONS[n]; return d ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">' + d + '</svg>' : ''; }
  function hydrate(root) { (root || document).querySelectorAll('[data-icon]').forEach(function (el) { el.innerHTML = icon(el.getAttribute('data-icon')); }); }
  function ic(n, cls) { return '<span class="ic' + (cls ? ' ' + cls : '') + '">' + icon(n) + '</span>'; }

  /* ───────────── utilities ───────────── */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function num(n) { return Number(n || 0).toLocaleString('en-US'); }
  function money(n) { return '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
  function pct(n) { return (n > 0 ? '+' : '') + Number(n).toFixed(0) + '%'; }
  function compact(n) { n = Number(n || 0); if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B'; if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'; if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'; return String(n); }
  function initials(name) { var p = String(name || '').trim().split(/[\s@.]+/).filter(Boolean); return (p.length >= 2 ? p[0][0] + p[1][0] : (p[0] || '?').slice(0, 2)).toUpperCase(); }
  function tzName() { return (PREFS.timezone) || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; }
  function fmt(iso, o) { if (!iso) return '—'; var d = new Date(iso); if (isNaN(d)) return '—'; try { return d.toLocaleString('en-US', Object.assign({ timeZone: tzName() }, o || { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })); } catch (e) { return d.toLocaleString(); } }
  function fmtD(iso) { return fmt(iso, { month: 'short', day: 'numeric', year: 'numeric' }); }
  function fmtT(iso) { return fmt(iso, { hour: 'numeric', minute: '2-digit' }); }
  function fmtDay(iso) { return fmt(iso, { weekday: 'long', month: 'long', day: 'numeric' }); }
  function fmtMD(iso) { return fmt(iso, { month: 'short', day: 'numeric' }); }
  function rel(iso) { if (!iso) return '—'; var s = (Date.now() - new Date(iso).getTime()) / 1000; if (s < 0) s = 0; if (s < 60) return 'just now'; if (s < 3600) return Math.round(s / 60) + ' min ago'; if (s < 86400) return Math.round(s / 3600) + ' hr ago'; if (s < 86400 * 14) return Math.round(s / 86400) + ' d ago'; return fmtD(iso); }
  function relDay(iso) { if (!iso) return '—'; var d = new Date(iso), n = new Date(); var a = new Date(d.toLocaleDateString('en-US', { timeZone: tzName() })), b = new Date(n.toLocaleDateString('en-US', { timeZone: tzName() })); var diff = Math.round((b - a) / 864e5); if (diff <= 0) return 'Today'; if (diff === 1) return 'Yesterday'; return fmtMD(iso); }
  function ageDays(iso) { return iso ? Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 864e5)) : null; }
  function hours(h) { if (h == null) return '—'; if (h < 1) return Math.round(h * 60) + ' min'; if (h < 48) return (Math.round(h * 10) / 10) + 'h'; return (Math.round(h / 24 * 10) / 10) + 'd'; }
  function tzLabel(tz) { try { var p = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'short' }).formatToParts(new Date()); var n = (p.find(function (x) { return x.type === 'timeZoneName'; }) || {}).value; return tz.replace(/_/g, ' ') + (n ? ' (' + n + ')' : ''); } catch (e) { return tz; } }
  function domain(u) { try { return new URL(u, location.href).hostname; } catch (e) { return ''; } }
  function delta(cur, prev) { if (prev == null || !prev) return null; return Math.round((cur / prev - 1) * 100); }

  var toastT;
  function toast(msg, err) { var t = $('#toast'); t.textContent = msg; t.className = 'on' + (err ? ' err' : ''); clearTimeout(toastT); toastT = setTimeout(function () { t.className = ''; }, err ? 3200 : 1500); }

  /* ?viewAs=<email> lets a platform owner check what a given manager's page looks
   * like. It is forwarded as a header and nothing more: the API decides whether the
   * delegation is allowed (rbac_view_as) and refuses it otherwise, so putting the
   * parameter in the URL grants nobody anything they did not already have.
   *
   * When there is no ?viewAs= in the URL we fall back to the session-wide
   * View-As the topbar/landing set via rbac-client (sessionStorage
   * 'itcmd_viewas'). rbac-client already restores its amber banner + DOM guards
   * on this page from that same key; without this fallback the banner would say
   * "Viewing as X" while /api/profile still loaded the viewer's own data — the
   * chrome and the body would disagree. The server still decides (rbac_view_as),
   * so this grants nobody anything the header alone would not. */
  var VIEW_AS = (function () {
    var m = /[?&]viewAs=([^&]+)/.exec(location.search || '');
    if (m) return decodeURIComponent(m[1]).trim().toLowerCase();
    try {
      var raw = sessionStorage.getItem('itcmd_viewas');
      if (raw) { var d = JSON.parse(raw); if (d && d.email) return String(d.email).trim().toLowerCase(); }
    } catch (e) {}
    return '';
  })();

  var VIEW_AS_ACTIVE = null;            // null = not resolved yet; set by loadMe()
  function api(method, path, body) {
    var m = (method || 'GET').toUpperCase();
    /* A borrowed view is read-only and the API enforces that (VIEW_AS_READ_ONLY).
     * Refusing here too means the click gets an immediate, plain answer, and no
     * write is ever attempted while the page is showing somebody else. */
    if (VIEW_AS && VIEW_AS_ACTIVE !== false && m !== 'GET' && m !== 'HEAD') {
      return Promise.reject(new Error('You are viewing this page as ' + VIEW_AS + '. A borrowed view is read-only.'));
    }
    var init = { method: m, credentials: 'same-origin', cache: 'no-store', headers: {} };
    if (VIEW_AS) init.headers['X-View-As'] = VIEW_AS;
    if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    return fetch('/api/profile' + path, init).then(function (r) {
      if (r.status === 401) { location.href = '/login.html?expired=1&return=' + encodeURIComponent(location.pathname + location.hash); throw new Error('Signed out'); }
      if (r.status === 204) return null;
      return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status)); return j; });
    });
  }

  /* ───────────── state + router ───────────── */
  var ME = null, PREFS = {}, HUB = null, PINS = null, WORK = null, CLAUDE = null, STATS = null, SUGG = null, CHANGES = null, SECURITY = null;
  var AI = null, TEAM = null, ACCESS = null, ALERT_EMAIL = null;
  var VIEWS = ['overview', 'profile', 'access', 'work', 'favorites', 'activity', 'suggestions', 'changes'];
  var TITLES = { overview: '', profile: 'Settings', access: 'My Access', work: 'My work', devices: 'My devices', claude: 'AI tools & usage', favorites: 'Favorites', activity: 'Activity & stats', suggestions: 'Suggestions', changes: 'ITAM → CorpIT changes' };
  var NAV_FOR = { overview: 'profile', profile: 'profile', access: 'access', work: 'work', devices: 'devices', claude: 'hub', favorites: 'hub', activity: 'hub', suggestions: 'hub', changes: 'hub' };
  var loaded = {};
  function route() {
    var h = location.hash.replace(/^#/, ''), parts = h.split('/'), v = VIEWS.indexOf(parts[0]) >= 0 ? parts[0] : 'overview';
    // The whole remainder, not just the first segment: the AI view routes on
    // #claude/team and #claude/u/<email>, and #profile/<section> is unaffected.
    showView(v, parts.slice(1).join('/'));
  }
  function showView(v, sub) {
    $$('.view').forEach(function (el) { el.classList.toggle('on', el.id === 'v-' + v); });
    $$('.nav-item').forEach(function (a) { a.classList.toggle('active', a.getAttribute('data-nav') === NAV_FOR[v]); });
    var crumb = $('#crumb'); crumb.textContent = TITLES[v]; crumb.hidden = v === 'overview'; $('#back-ov').hidden = v === 'overview';
    document.title = (TITLES[v] ? TITLES[v] + ' · ' : '') + 'My Profile · CorpIT';
    if (!loaded[v]) { loaded[v] = true; LOADERS[v](); }
    if (v === 'profile') {
      var target = sub ? $('#s-' + sub) : null;
      $$('#subnav a').forEach(function (a) { a.classList.toggle('on', a.getAttribute('href') === '#profile/' + (sub || 'identity')); });
      if (target) target.scrollIntoView({ block: 'start', behavior: 'auto' }); else window.scrollTo(0, 0);
    } else window.scrollTo(0, 0);
    if (v === 'overview') aiRoute(sub);
    if (v === 'changes' && CHANGES) markChangesSeenSoon();
  }
  window.addEventListener('hashchange', route);

  /* ───────────── account menu (sidebar) ───────────── */
  (function accountMenu() {
    var card = $('#user-card'), menu = $('#acct-menu');
    function open(on) { menu.classList.toggle('on', on); card.setAttribute('aria-expanded', on ? 'true' : 'false'); }
    card.addEventListener('click', function (e) { if (e.target.closest('.acct-menu')) return; open(!menu.classList.contains('on')); });
    card.addEventListener('keydown', function (e) { if (e.target !== card) return; if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(!menu.classList.contains('on')); } });
    document.addEventListener('click', function (e) { if (!e.target.closest('#user-card')) open(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') open(false); });
    $('#acct-refresh').addEventListener('click', function (e) {
      e.stopPropagation(); var b = this; b.disabled = true;
      api('POST', '/access/refresh').then(function () { return loadMe(); }).then(function () { toast('Access refreshed'); if (window.itRbac && window.itRbac.refresh) window.itRbac.refresh(); if (loaded.profile) paintProfile(); })
        .catch(function (er) { toast(er.message, true); }).then(function () { b.disabled = false; open(false); });
    });
  })();

  /* ───────────── View As (sidebar) ─────────────
   * The account menu carries a "View as another user" item for anyone who holds
   * a view-as grant (rbac_view_as) — NOT only super-admins, so a supervisor with
   * a bounded grant gets it too. The grant + candidate list resolve from the
   * REAL viewer (plain /api/rbac calls, never X-View-As), and the server re-checks
   * every pick. Picking navigates to ?viewAs=<email>; the borrowed view is
   * read-only and server-enforced. */
  var VA_LEVEL = null, vaModal = null, vaT;
  (function viewAsControl() {
    var item = $('#acct-viewas'); if (!item) return;
    fetch('/api/rbac/me/view-as', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.grant) return;
        VA_LEVEL = d.grant.level || null;
        item.hidden = false;
        item.addEventListener('click', function (e) { e.stopPropagation(); openViewAsPicker(); });
      })
      .catch(function () {});
  })();

  function buildViewAsModal() {
    var ov = document.createElement('div');
    ov.id = 'va-overlay';
    ov.setAttribute('style', 'position:fixed;inset:0;z-index:10200;display:none;align-items:flex-start;justify-content:center;background:rgba(4,10,20,.55);padding:12vh 16px 16px');
    ov.innerHTML =
      '<div role="dialog" aria-modal="true" aria-label="View as another user" style="width:100%;max-width:460px;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow-menu);overflow:hidden">' +
        '<div style="display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line-2)">' +
          '<b style="font-size:14px;flex:1">View as another user</b>' +
          '<button type="button" id="va-x" aria-label="Close" style="width:26px;height:26px;border-radius:6px;color:var(--muted);font-size:18px;line-height:1">×</button>' +
        '</div>' +
        '<div style="padding:12px 16px 16px">' +
          '<input type="text" id="va-q" autocomplete="off" spellcheck="false" placeholder="Search by name or email…" aria-label="Search users" ' +
            'style="width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--input-bg);color:var(--ink);font-size:14px">' +
          '<div id="va-hint" style="font-size:12px;color:var(--muted);margin:8px 2px 0"></div>' +
          '<div id="va-list" role="listbox" style="margin-top:8px;max-height:46vh;overflow:auto"></div>' +
          '<div style="font-size:11.5px;color:var(--muted);margin-top:10px;border-top:1px solid var(--line-2);padding-top:8px">Read-only. Each look-up is audited.</div>' +
        '</div>' +
      '</div>';
    document.body.appendChild(ov);
    var m = { overlay: ov, input: ov.querySelector('#va-q'), list: ov.querySelector('#va-list'), hint: ov.querySelector('#va-hint') };
    ov.addEventListener('mousedown', function (e) { if (e.target === ov) closeViewAsPicker(); });
    ov.querySelector('#va-x').addEventListener('click', closeViewAsPicker);
    ov.addEventListener('keydown', function (e) { if (e.key === 'Escape') { e.preventDefault(); closeViewAsPicker(); } });
    m.input.addEventListener('input', function () {
      clearTimeout(vaT); var q = m.input.value.trim();
      vaT = setTimeout(function () { runViewAsSearch(q); }, 200);
    });
    return m;
  }

  function openViewAsPicker() {
    var menu = $('#acct-menu'); if (menu) menu.classList.remove('on');
    if (!vaModal) vaModal = buildViewAsModal();
    vaModal.overlay.style.display = 'flex';
    vaModal.input.value = '';
    vaModal.list.innerHTML = '';
    if (VA_LEVEL && VA_LEVEL !== 'any') { vaModal.hint.textContent = 'Loading the people you can view…'; runViewAsSearch(''); }
    else { vaModal.hint.textContent = 'Type a name or email to search.'; }
    setTimeout(function () { vaModal.input.focus(); }, 30);
  }

  function closeViewAsPicker() { if (vaModal) vaModal.overlay.style.display = 'none'; }

  function runViewAsSearch(q) {
    var list = vaModal.list, hint = vaModal.hint;
    list.innerHTML = ''; hint.textContent = 'Searching…';
    fetch('/api/rbac/me/view-as/candidates?q=' + encodeURIComponent(q), { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var rows = (d && d.candidates) || [];
        if (!rows.length) {
          hint.textContent = (VA_LEVEL === 'any' && q.length < 2) ? 'Type at least 2 characters.' : 'No matches you can view as.';
          return;
        }
        hint.textContent = '';
        list.innerHTML = rows.map(function (u) {
          return '<button type="button" class="va-row" role="option" data-email="' + esc(u.email) + '" ' +
              'style="display:block;width:100%;text-align:left;padding:9px 10px;border-radius:8px;color:var(--ink)">' +
            '<span style="display:block;font-size:13.5px;font-weight:600">' + esc(u.display_name || u.email) + '</span>' +
            '<span style="display:block;font-size:11.5px;color:var(--muted)">' + esc(u.email) + (u.title ? ' · ' + esc(u.title) : '') + '</span>' +
          '</button>';
        }).join('');
        Array.prototype.forEach.call(list.querySelectorAll('.va-row'), function (b) {
          b.addEventListener('mouseenter', function () { b.style.background = 'var(--line-2)'; });
          b.addEventListener('mouseleave', function () { b.style.background = ''; });
          b.addEventListener('click', function () {
            location.href = '/my-profile.html?viewAs=' + encodeURIComponent(b.getAttribute('data-email'));
          });
        });
      })
      .catch(function () { hint.textContent = 'Search failed — try again.'; });
  }

  /* An unlabelled borrowed view is how somebody files a bug against data that was
   * never theirs — or reads a role chip as their own. The bar is not decoration. */
  function paintViewAsBar(m) {
    var bar = document.getElementById('view-as-bar');
    var on = m && (m.viewingAs || m.viewAsDenied);
    if (!on) { if (bar) bar.parentNode.removeChild(bar); return; }
    if (!bar) {
      var wrap = document.querySelector('.main-wrap');
      if (!wrap) return;
      bar = document.createElement('div');
      bar.id = 'view-as-bar';
      wrap.insertBefore(bar, wrap.firstChild);
    }
    var denied = !m.viewingAs;
    bar.setAttribute('style', 'display:flex;align-items:center;gap:6px 14px;flex-wrap:wrap;padding:10px 20px;font-size:13px;line-height:1.45;' +
      (denied ? 'background:#6b1d1d;color:#ffdede;border-bottom:2px solid #c0392b' : 'background:#6b5200;color:#fff5d6;border-bottom:2px solid #d4a017'));
    bar.innerHTML = denied
      ? '<b>Viewing as ' + esc(VIEW_AS) + ' was refused</b><span>' + esc(m.viewAsDenied) + ' \u2014 showing your own profile.</span>'
      : '<b>Viewing as ' + esc(m.displayName || m.viewingAs.email) + '</b>' +
        '<span>' + esc(m.viewingAs.email) + (m.viewingAs.label ? ' \u00b7 ' + esc(m.viewingAs.label) : '') + ' \u00b7 read-only \u00b7 this look-up is audited</span>' +
        '<a href="#" id="view-as-leave" style="margin-left:auto;color:inherit;font-weight:600">Leave this view</a>';
    if (!denied) {
      var lv = bar.querySelector('#view-as-leave');
      if (lv) lv.addEventListener('click', function (e) { e.preventDefault(); leaveViewAs(); });
    }
  }

  /* Exit a borrowed view from EITHER source: the ?viewAs= URL param OR the
   * session-wide key the topbar sets (sessionStorage 'itcmd_viewas'). Stripping
   * only the query would leave the session key in place, and the carry-over
   * fallback in VIEW_AS would silently re-enter the borrowed view on reload. */
  function leaveViewAs() {
    try { (window.itRbac && window.itRbac.exitViewAs) ? window.itRbac.exitViewAs() : sessionStorage.removeItem('itcmd_viewas'); } catch (e) {}
    if (location.search) location.href = location.pathname + (location.hash || '');
    else location.reload();
  }

  /* ───────────── identity ───────────── */
  function loadMe() {
    return api('GET', '/me').then(function (m) {
      ME = m; PREFS = m.prefs || {};
      applyPrefsToDocument();
      var allTicketsButton = $('#tsearch-scope button[data-v="all"]');
      if (allTicketsButton) allTicketsButton.hidden = !m.canSearchAllTickets;
      var name = m.displayName || m.email, title = (m.entra && m.entra.jobTitle) || (m.hr && m.hr.title) || '';
      VIEW_AS_ACTIVE = !!m.viewingAs;
      paintViewAsBar(m);
      // Leadership-only return link. The server decides (canReturnToReporting
      // is computed from the signed-in viewer, not the View-As subject), so a
      // leader keeps the link while borrowing a view and nobody else inherits it.
      var rrLink = document.getElementById('reporting-return');
      if (rrLink) rrLink.hidden = !m.canReturnToReporting;
      /* The sidebar card is the account menu -- "you are signed in as", with Sign out
       * and Admin center hanging off it. It follows the VIEWER. Only the hero and the
       * page body below it describe the subject. Conflating the two is the bug that
       * branded a non-super-admin as one. */
      var acct = m.viewer
        ? { email: m.viewer.email, displayName: m.viewer.displayName, isSuperAdmin: m.viewer.isSuperAdmin, photoUrl: '/api/photo?upn=' + encodeURIComponent(m.viewer.email) }
        : m;
      var acctName = acct.displayName || acct.email;
      $('#side-name').textContent = acctName; $('#side-title').textContent = m.viewer ? 'Viewing as ' + (m.displayName || m.email) : (title || m.email);
      $('#acct-name').textContent = acctName; $('#acct-email').textContent = acct.email;
      $('#acct-admin').hidden = !acct.isSuperAdmin;
      paintPhoto($('#side-av'), acct, 40); paintPhoto($('#hero-photo'), m, 128);
      $('#hero-name').textContent = name; $('#hero-title').textContent = title || (m.roles || []).join(', ') || 'Technician';
      $('#hero-badge').innerHTML = m.entra ? (m.entra.source === 'live' ? '<span class="badge" title="Read from Microsoft Graph ' + esc(fmt(m.entra.fetchedAt)) + '">' + ic('check-circle') + 'Entra ID · live</span>' : '<span class="badge warn" title="Graph unreachable; showing the nightly copy">' + ic('alert') + 'Entra ID synced ' + esc(rel(m.entra.syncedAt)) + '</span>') : '<span class="badge warn">' + ic('alert') + 'Not found in Entra ID</span>';
      var facts = ['<div>' + ic('mail') + '<span>' + esc(m.entra ? (m.entra.mail || m.entra.upn) : m.email) + '</span></div>'];
      var loc = (m.hr && m.hr.location) || (m.entra && (m.entra.officeLocation || [m.entra.city, m.entra.state].filter(Boolean).join(', ')));
      if (loc) facts.push('<div>' + ic('pin') + '<span>' + esc(String(loc).split(' - ')[0]) + '</span></div>');
      facts.push('<div>' + ic('clock') + '<span>' + esc(tzLabel(tzName())) + '</span></div>');
      $('#hero-facts').innerHTML = facts.join('');
      hydrate($('#hero'));
      loadHub().then(function (hub) {
        var people = hub.links.find(function (l) { return /identity diagnostics|user lookup|people/i.test(l.title); });
        var el = $('#nav-people'); if (people && el) { el.href = safeHref(people.url); el.hidden = false; if (!people.url.startsWith('/')) { el.target = '_blank'; el.rel = 'noopener noreferrer'; } }

      }).catch(function () {});
      return m;
    });
  }
  function paintPhoto(el, m, size) {
    if (!el) return;
    el.textContent = initials(m.displayName || m.email);
    if (PREFS.photo_source === 'initials') return;
    var img = new Image();
    img.alt = ''; img.width = size; img.height = size;
    img.onload = function () { el.innerHTML = ''; el.appendChild(img); };
    img.src = m.photoUrl + '&v=' + (PREFS.photo_v || '');
  }
  /* The same idea for a table of people, with two differences.
   *
   * ONE: /api/photo is a Graph call behind a 7-day disk cache. A leader with 88
   * directs would fire 88 of them on first paint and, on a cold cache, 88 calls
   * to Graph. So rows are fetched only as they come near the viewport.
   *
   * TWO: as in paintPhoto, initials are already IN the box before anything is
   * requested. A 404 -- which is what /api/photo returns for the many people
   * Graph has no photo of -- never fires onload, so the initials simply stay.
   * There is no broken-image state to fall back from. */
  function hydratePhotos(root) {
    var boxes = $$('[data-photo]', root || document).filter(function (el) {
      return !el.getAttribute('data-photo-done') && el.getAttribute('data-photo');
    });
    if (!boxes.length || PREFS.photo_source === 'initials') return;
    var load = function (el) {
      if (el.getAttribute('data-photo-done')) return;
      el.setAttribute('data-photo-done', '1');
      var img = new Image();
      img.alt = '';
      img.onload = function () { el.innerHTML = ''; el.appendChild(img); };
      img.src = '/api/photo?upn=' + encodeURIComponent(el.getAttribute('data-photo'))
        + '&v=' + (PREFS.photo_v || '');
    };
    if (!window.IntersectionObserver) { boxes.forEach(load); return; }
    var io = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        obs.unobserve(e.target);
        load(e.target);
      });
    }, { rootMargin: '200px' });
    boxes.forEach(function (el) { io.observe(el); });
  }
  function applyPrefsToDocument() {
    var r = document.documentElement;
    r.setAttribute('data-density', PREFS.density === 'compact' ? 'compact' : 'comfortable');
    r.setAttribute('data-reduce-motion', PREFS.reduce_motion === 'on' ? 'on' : 'off');
    // it-theme.js paints the accent family (ocean/reef/abyss/ember) as inline vars on :root,
    // choosing the light or dark twin for the mode in force - the same engine ITAM pages use.
    if (window.itThemeApply) { try { window.itThemeApply(PREFS); } catch (e) {} }
  }
  // Host it-theme-toggle's button in the page header instead of its floating dock.
  function hostThemeToggle() {
    var slot = $('#theme-slot'), btn = document.getElementById('itThemeBtn');
    if (!slot || !btn || slot.contains(btn)) return;
    var dock = document.getElementById('itThemeDock');
    slot.appendChild(btn);
    if (dock) dock.remove();
  }
  var saveTimers = {};
  function savePref(k, v, opts) {
    PREFS[k] = v; applyPrefsToDocument();
    clearTimeout(saveTimers[k]);
    saveTimers[k] = setTimeout(function () {
      var body = {}; body[k] = v;
      api('PUT', '/prefs', { prefs: body }).then(function () { if (!(opts && opts.quiet)) toast('Saved'); }).catch(function (e) { toast(e.message, true); });
    }, opts && opts.now ? 0 : 250);
  }

  /* ───────────── loaders per view ───────────── */
  var LOADERS = {
    overview: function () {
      // Overview now hosts the AI tools & usage stack (moved out of its own view).
      // Entitlement first decides whether there is a Team usage tab at all and which
      // reporting periods the collector can speak for; renderAi then paints the stack.
      loadAi().then(function () { fillMonths(); paintAiAccess(); renderAi(); })
        .catch(function (e) { $('#ai-access').innerHTML = errBox(e); });
    },
    profile: function () {
      paintProfile();
      // Session, MFA and sign-in history describe the browser session and the account
      // holding it -- the VIEWER's. Rendering them under somebody else's name would be
      // a fabrication, so a borrowed view says so instead of showing the wrong person's.
      if (ME && ME.viewingAs) {
        $('#f-security').innerHTML = '<div class="empty"><b>Not shown in a borrowed view</b>Session, sign-in methods and sign-in history belong to the account you are signed in with, not to ' + esc(ME.displayName || ME.email) + '.</div>';
        return;
      }
      (SECURITY ? Promise.resolve(SECURITY) : api('GET', '/security').then(function (s) { SECURITY = s; return s; })).then(paintSecurity).catch(function (e) { $('#f-security').innerHTML = errBox(e); });
    },
    work: function () { loadWork().then(paintWork).catch(function (e) { $('#work-tickets').innerHTML = errBox(e); }); },
    access: function () { loadAccess().then(paintAccess).catch(function (e) { $('#acc-pages').innerHTML = errBox(e); $('#acc-sites').innerHTML = ''; }); },
    claude: function () {
      // Entitlement first: it decides whether there is a Team usage tab at all, and
      // which reporting periods the collector can actually speak for.
      loadAi().then(function () { fillMonths(); paintAiAccess(); renderAi(); })
        .catch(function (e) { $('#ai-access').innerHTML = errBox(e); });
    },
    favorites: function () { loadPins().then(paintFavorites).catch(function (e) { $('#pinbar').innerHTML = errBox(e); }); },
    activity: function () { loadStats().then(paintStats).catch(function (e) { $('#st-kpis').innerHTML = errBox(e); }); loadTrail(); },
    suggestions: function () { fillAreas(); loadSugg('mine').then(paintSugg).catch(function (e) { $('#sg-list').innerHTML = errBox(e); }); restoreDraft(); },
    changes: function () { loadChanges().then(paintChanges).catch(function (e) { $('#ch-notes').innerHTML = errBox(e); }); },
  };
  function errBox(e) { return '<div class="empty"><b>Could not load</b>' + esc(e && e.message || e) + '</div>'; }

  /* The rail and the Overview tab ask for pins/work/claude in the same tick; a loader
   * that memoises only after it resolves still sends both requests. Share the
   * in-flight promise per key; once settled the next call fetches fresh again. */
  var INFLIGHT = {};
  function once(key, fn) {
    if (INFLIGHT[key]) return INFLIGHT[key];
    var p = fn().then(function (r) { delete INFLIGHT[key]; return r; }, function (e) { delete INFLIGHT[key]; throw e; });
    INFLIGHT[key] = p; return p;
  }
  function loadPins() { return once('pins', function () { return api('GET', '/pins').then(function (p) { PINS = p; return p; }); }); }
  function loadHub() { return HUB ? Promise.resolve(HUB) : api('GET', '/hub-links').then(function (h) { HUB = h; return h; }); }
  function loadWork(force) { if (WORK && !force) return Promise.resolve(WORK); return once(force ? 'work:refresh' : 'work', function () { return api('GET', '/work' + (force ? '?refresh=1' : '')).then(function (w) { WORK = w; return w; }); }); }
  var claudeMonth = null, claudeEmail = null;
  function loadAi(force) {
    var m = claudeMonth || '';
    if (AI && !force && AI.period.month === (m || AI.period.month)) return Promise.resolve(AI);
    var url = '/ai-tools' + (m ? '?month=' + m : '');
    return once('ai:' + url, function () { return api('GET', url).then(function (a) { AI = a; return a; }); });
  }
  function loadTeam(force) {
    var m = claudeMonth || (AI && AI.period.month) || '';
    if (TEAM && !force && TEAM.period.month === m) return Promise.resolve(TEAM);
    var url = '/ai-team' + (m ? '?month=' + m : '');
    return once('aiteam:' + url, function () { return api('GET', url).then(function (t) { TEAM = t; return t; }); });
  }
  function loadClaude(force) {
    if (CLAUDE && !force && CLAUDE.month === (claudeMonth || CLAUDE.month) && (claudeEmail || ME.email) === CLAUDE.subject.email) return Promise.resolve(CLAUDE);
    var q = []; if (claudeMonth) q.push('month=' + claudeMonth); if (claudeEmail) q.push('email=' + encodeURIComponent(claudeEmail));
    var url = '/claude' + (q.length ? '?' + q.join('&') : '');
    return once('claude:' + url, function () { return api('GET', url).then(function (c) { CLAUDE = c; return c; }); });
  }
  function loadStats() { return STATS ? Promise.resolve(STATS) : api('GET', '/stats').then(function (s) { STATS = s; return s; }); }
  function loadSugg(scope) { return api('GET', '/suggestions?scope=' + scope).then(function (s) { SUGG = s; return s; }); }
  function loadChanges() { return CHANGES ? Promise.resolve(CHANGES) : api('GET', '/changes').then(function (c) { CHANGES = c; return c; }); }
  function notifPrefs() { try { return JSON.parse(PREFS.notifications || '{}') || {}; } catch (e) { return {}; } }

  /* ───────────── link / tile rendering helpers ───────────── */
  function tileIcon(l, cls) {
    if (l.iconKind === 'logo' && l.iconHtml) return '<span class="' + cls + ' logo"><img alt="" src="data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(l.iconHtml))) + '"></span>';
    if (l.iconHtml) return '<span class="' + cls + ' t-' + esc(l.tone) + '"><span class="ic">' + l.iconHtml + '</span></span>';
    return '<span class="' + cls + ' t-' + esc(l.tone) + '">' + ic('grid') + '</span>';
  }
  function plainIcon(l) {   // overview favourites: blue outline glyph, or the vendor logo, on white
    if (l.iconKind === 'logo' && l.iconHtml) return '<span class="sq logo"><img alt="" src="data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(l.iconHtml))) + '"></span>';
    if (l.iconHtml) return '<span class="sq"><span class="ic">' + l.iconHtml + '</span></span>';
    return '<span class="sq">' + ic('grid') + '</span>';
  }
  /* Root-relative links on this page are Hub destinations -- favourites, the
   * tools in your activity feed, the Asset Inventory, the changes table. They
   * are written as '/identity-diag.html' because this page was born on corpit,
   * where that is right. This page is now served on the other vhosts too, and
   * there '/identity-diag.html' is a 404, so anything that is not served
   * alongside us gets sent to the Hub host. On corpit ITHubLink.url() is the
   * identity function, so nothing changes there. */
  var LOCAL_PATH = /^\/(my-profile\.html|api\/|login\.html|auth-complete\.html|no-site-access\.html)/;
  function hubPath(p) { return window.ITHubLink ? window.ITHubLink.url(p) : p; }
  function safeHref(u) { if (!u) return '#'; if (u.startsWith('/') && !u.startsWith('//')) return LOCAL_PATH.test(u) ? u : hubPath(u); try { return new URL(u).protocol === 'https:' ? u : '#'; } catch (e) { return '#'; } }
  function targetAttr(l) { return (l.newTab && !safeHref(l.url).startsWith('/')) ? ' target="_blank" rel="noopener noreferrer"' : ''; }
  var HOST_LABEL = { corpit: 'CorpIT', itam: 'ITAM', reporting: 'Reporting', accessportal: 'Access Portal', subadmin: 'Admin', external: 'External', unknown: '' };
  function recordOpen(l) { if (window.itProfile) window.itProfile.open({ id: l.id, name: l.title, href: l.url }); }
  function unavailable(t) {
    var r = (t && t.reason) || 'unavailable';
    var msg = r === 'sdp-not-configured' ? 'ServiceDesk Plus is not configured on this host.' : r === 'changes-scope' ? 'The ServiceDesk Plus token on CorpIT does not have the <b>changes</b> scope yet, so change controls cannot be read here.' : 'ServiceDesk Plus did not answer' + (t && t.detail ? ': ' + esc(String(t.detail).replace(/\{.*$/, '').trim()) : '.');
    return '<div class="callout">' + ic('alert') + '<div>' + msg + '</div></div>';
  }
  function prodName(p) { return { claude_code: 'Claude Code', cowork: 'Cowork', chat: 'Chat', claude_in_chrome: 'Claude in Chrome', claude_design: 'Design', research: 'Research', voice_mode: 'Voice Mode', other: 'Other' }[p] || p; }
  function prodClass(p) { return 'pd-' + String(p || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-'); }
  // A rounded 0% reads as "nothing", which is wrong for a real but tiny slice.
  function share(a, b) {
    var v = b > 0 ? a / b * 100 : 0;
    if (v > 0 && v < 0.5) return '&lt;1%';
    // 99.6 rounding to a flat 100% beside a visibly non-zero sibling reads as a bug.
    if (v > 99.5 && v < 99.95) return v.toFixed(1) + '%';
    return Math.round(v) + '%';
  }

  /* ───────────── OVERVIEW ───────────── */
  function paintOvWork() {
    if (!$('#ov-work')) return;
    var el = $('#ov-work'), t = WORK.tickets;
    if (!t || !t.available) { el.innerHTML = unavailable(t); return; }
    var c = t.counts, weekTotal = c.closedWeek + c.active, pctWeek = weekTotal ? Math.round(c.closedWeek / weekTotal * 100) : 0;
    var daysLeft = 6 - ((new Date().getDay() + 6) % 7);
    el.innerHTML =
      '<div style="display:flex;gap:16px;align-items:flex-start;justify-content:space-between">' +
        '<div><div class="lbl">Assigned tickets</div><div class="n">' + num(c.active) + '</div></div>' +
        '<div style="min-width:132px">' +
          '<div class="stat"><span><i style="background:var(--pblue)"></i>Open</span><b>' + num(c.open) + '</b></div>' +
          '<div class="stat"><span><i style="background:var(--amber)"></i>In progress</span><b>' + num(c.inProgress) + '</b></div>' +
          '<div class="stat"><span><i style="background:var(--dim)"></i>On hold</span><b>' + num(c.onHold + c.pendingVerification) + '</b></div>' +
          (c.overdue ? '<div class="stat"><span><i style="background:var(--red)"></i>Overdue</span><b class="down">' + num(c.overdue) + '</b></div>' : '') +
        '</div></div>' +
      '<div style="margin-top:18px;display:flex;justify-content:space-between;font-size:13px"><span class="lbl">This week</span><b>' + pctWeek + '%</b></div>' +
      '<div class="bar" style="margin-top:8px"><span style="width:' + pctWeek + '%"></span></div>' +
      '<div style="display:flex;justify-content:space-between;margin-top:8px;font-size:13px;color:var(--muted)"><span>' + num(c.closedWeek) + ' / ' + num(weekTotal) + ' closed</span><span>' + daysLeft + ' day' + (daysLeft === 1 ? '' : 's') + ' left</span></div>';
  }
  /* The Overview tile answers the two questions in one glance — what am I entitled
   * to, and what did I use — without becoming a second copy of the detail view.
   * Access chips come from the rosters; the number under them comes from usage. */
  function paintOvClaude() {
    if (!$('#ov-claude')) return;
    var el = $('#ov-claude'), c = CLAUDE, a = AI;
    var chips = a ? '<div class="models" style="margin-bottom:12px">' +
        '<span class="chip' + (a.claude.access === 'active' ? ' green' : a.claude.access === 'none' ? '' : ' amber') + '">Claude · ' + (a.claude.access === 'active' ? 'Active' : a.claude.access === 'none' ? 'No access' : 'Can\u2019t confirm') + '</span>' +
        '<span class="chip' + (a.copilot.access === 'licensed' ? ' green' : a.copilot.access === 'none' ? '' : ' amber') + '">Copilot · ' + (a.copilot.access === 'licensed' ? 'Licensed' : a.copilot.access === 'none' ? 'No licence' : 'Can\u2019t confirm') + '</span>' +
      '</div>' : '';

    if (a && a.claude.access === 'none') {
      // No seat means there is no usage to chart. Saying so plainly, with the way to
      // ask for one, beats an empty axis that reads like a measurement.
      el.innerHTML = chips + '<div class="lbl">You don\'t currently have Claude access.</div>' +
        '<p class="note" style="margin-top:6px">Checked against the Claude member roster ' + esc(a.claude.asOf ? rel(a.claude.asOf) : 'at an unknown time') + '.</p>' +
        (a.requestAccess && a.requestAccess.available ? '<a class="req" style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;font-size:13px;font-weight:500;color:var(--pblue)" href="' + esc(safeHref(a.requestAccess.url)) + '" target="_blank" rel="noopener noreferrer">' + ic('external') + 'Request access</a>' : '') +
        '<a class="link-center" href="#claude/me" style="margin-top:8px">Your AI tools</a>';
      hydrate(el); return;
    }
    if (a && !a.period.zeroIsMeasured) {
      el.innerHTML = chips + '<div class="lbl">Usage for ' + esc(a.period.label) + ' is not available.</div>' +
        '<p class="note" style="margin-top:6px">' + esc(a.period.note || '') + '</p>' +
        '<a class="link-center" href="#claude/me" style="margin-top:8px">Your AI tools</a>';
      hydrate(el); return;
    }
    var mom = c.momPct == null ? '<div class="flat" style="font-size:13px;font-weight:500">no prior month</div>' : '<div class="' + (c.momPct > 0 ? 'down' : 'up') + '" style="font-size:14px;font-weight:600">' + (c.momPct > 0 ? '\u2191' : '\u2193') + ' ' + Math.abs(c.momPct).toFixed(0) + '%</div><div class="note">vs last month</div>';
    el.innerHTML = chips +
      '<div style="display:flex;justify-content:space-between;align-items:flex-start"><div><div class="lbl">Claude spend, ' + esc(a ? a.period.label : 'this month') + '</div><div class="big" style="margin-top:6px">' + money(c.spend) + '</div></div><div style="text-align:right;padding-top:2px">' + mom + '</div></div>' +
      (c.products.length ? '' : '<p class="note" style="margin-top:8px">No usage in ' + esc(a ? a.period.label : 'this period') + '</p>');
    hydrate(el);
  }

  /* A manager opens this page for their people, so the team gets a card of its own
   * beside My work rather than a strip inside the AI tile: the subject is who reports
   * to you, and usage is one of the things reported about them. The card only exists
   * for people who actually have a team, and a failed roll-up leaves the rest alone. */
  function paintOvTeam() {
    if (!$('#ov-team') && !$('#ov-team-card')) return;
    var card = $('#ov-team-card'), el = $('#ov-team'), grid = $('.cards3'), t = AI && AI.team;
    var ok = !!(t && t.available);
    if (card) card.hidden = !ok;
    if (grid) grid.classList.toggle('with-team', ok);
    if (!ok || !el) return;
    el.innerHTML = '<div class="lbl">Direct reports</div><div class="big" style="margin-top:6px">' + num(t.directReports) + '</div>' +
      (t.totalReports > t.directReports ? '<p class="note" style="margin-top:6px">' + num(t.totalReports) + ' in total across your reporting line</p>' : '') +
      '<div class="note" id="ov-team-line" style="margin-top:12px">Loading team usage\u2026</div>';
    hydrate(el);
    loadTeam().then(function (r) {
      var line = $('#ov-team-line'); if (!line) return;
      var known = r.period.zeroIsMeasured, sm = r.summary;
      line.innerHTML = num(sm.claudeActive) + ' of ' + num(sm.people) + ' with Claude' +
        (known ? '<br><b>' + money(sm.spend) + '</b> in ' + esc(r.period.label) + ' \u00b7 ' + num(sm.activeInPeriod) + ' used it'
               : '<br>Usage for ' + esc(r.period.label) + ' is not available');
    }).catch(function () {
      var line = $('#ov-team-line'); if (line) line.textContent = 'Team usage could not be loaded.';
    });
  }
  function paintOvFav() {
    if (!$('#ov-fav')) return;
    var links = PINS.links.length ? PINS.links : PINS.fallback, el = $('#ov-fav');
    if (!links.length) { el.innerHTML = '<div class="empty"><b>No favorites yet</b>Pin tools from the Hub or the Favorites tab.</div>'; return; }
    el.innerHTML = '<div class="fav-grid">' + links.slice(0, 4).map(function (l) {
      return '<a class="fav-tile" href="' + esc(safeHref(l.url)) + '"' + targetAttr(l) + ' data-link="' + esc(l.id) + '">' + plainIcon(l) + '<b>' + esc(l.title) + '</b><span>Open</span></a>';
    }).join('') + '</div>';
    $$('a.fav-tile', el).forEach(function (a) { a.addEventListener('click', function () { var l = links.find(function (x) { return x.id === a.getAttribute('data-link'); }); if (l) recordOpen(l); }); });
  }
  function paintOvStats() {
    if (!$('#ov-stats')) return;
    var el = $('#ov-stats'), s = STATS, w = WORK && WORK.tickets && WORK.tickets.available ? WORK.tickets : null, c = w ? w.counts : null;
    var total = s.actions.reduce(function (a, b) { return a + b.count; }, 0);
    var colors = ['var(--accent)', 'var(--green)', 'var(--amber)', 'var(--dim)', 'var(--purple)', 'var(--teal)'];
    var top = s.actions.slice(0, 3); var rest = s.actions.slice(3).reduce(function (a, b) { return a + b.count; }, 0); if (rest) top.push({ label: 'Other actions', count: rest });
    var legend = top.map(function (a, i) { return '<div><i style="background:' + colors[i] + '"></i>' + esc(a.label) + '<span class="n">' + num(a.count) + '<small>(' + (total ? Math.round(a.count / total * 100) : 0) + '%)</small></span></div>'; }).join('');
    var tools = s.tools.length ? s.tools.slice(0, 5).map(function (t) { return '<div class="li">' + ic('grid') + '<span class="nm">' + esc(t.label || t.id) + '</span><span class="when">' + esc(relDay(t.lastAt)) + '</span></div>'; }).join('') : '<div class="note" style="padding:6px 0">Open tools from the Hub and they show up here.</div>';
    var claude = CLAUDE || null, sc = s.claude || {};
    var rows = [];
    if (c) {
      var d1 = delta(c.closedMonth, c.closedMonthPrev);
      rows.push(prodRow('check-circle', 'var(--pblue-lt)', 'var(--pblue)', 'Tickets closed', num(c.closedMonth), d1, false, (WORK.tickets.closedWeeks || []).map(function (x) { return x.count; }), 'var(--accent)'));
      var d2 = c.avgResolveHours != null && c.avgResolveHoursPrev ? delta(c.avgResolveHours, c.avgResolveHoursPrev) : null;
      rows.push(prodRow('clock', 'var(--green-lt)', 'var(--green)', 'Avg time to resolve', c.avgResolveHours == null ? '—' : hours(c.avgResolveHours), d2, true, (WORK.tickets.resolveWeeks || []).map(function (x) { return x.hours || 0; }), 'var(--green)'));
    } else {
      rows.push('<div class="p"><span class="ico" style="background:var(--pblue-lt);color:var(--pblue)">' + ic('clipboard') + '</span><div class="txt"><div class="l">Ticket stats need ServiceDesk Plus</div><div class="v">—</div></div></div>');
    }
    var sessions = claude ? (claude.activity.ccSessions || 0) : (sc.ccSessions || 0);
    var d3 = claude ? delta(sessions, claude.prevMonthSessions || 0) : null;
    rows.push(prodRow('sparkle', 'var(--purple-lt)', 'var(--purple)', 'Claude Code sessions', num(sessions), d3, false, claude ? (claude.monthsActivity || []).map(function (m) { return m.ccSessions; }) : [], 'var(--purple)'));
    el.innerHTML =
      '<div><div class="lbl" style="margin-bottom:12px">Actions this month</div><div class="donut-wrap">' + donut(top.map(function (a, i) { return { v: a.count, c: colors[i] }; }), total, 120) + '<div class="legend">' + (legend || '<div class="note">No actions recorded yet.</div>') + '</div></div></div>' +
      '<div><div class="lbl" style="margin-bottom:8px">Recent tools used</div><div class="list">' + tools + '</div></div>' +
      '<div><div class="lbl" style="margin-bottom:12px">Productivity <span class="note">(this month)</span></div><div class="prod">' + rows.join('') + '</div></div>';
  }
  function prodRow(iconName, bg, fg, label, value, d, lowerIsBetter, series, color) {
    var good = d == null ? null : (lowerIsBetter ? d <= 0 : d >= 0);
    var dl = d == null ? '<span class="delta flat">—<small>vs last month</small></span>' : '<span class="delta ' + (good ? 'up' : 'down') + '">' + (d >= 0 ? '↑' : '↓') + ' ' + Math.abs(d) + '%<small>vs last month</small></span>';
    return '<div class="p"><span class="ico" style="background:' + bg + ';color:' + fg + '">' + ic(iconName) + '</span><div class="txt"><div class="l">' + esc(label) + '</div><div class="v">' + value + '</div></div>' + dl + spark(series, 96, 34, color) + '</div>';
  }
  function paintOvActivity(a) {
    if (!$('#ov-activity')) return;
    var el = $('#ov-activity');
    if (!a.items.length) { el.innerHTML = '<div class="empty"><b>Nothing recorded yet</b>Your actions across CorpIT will appear here.</div><a class="link-center" href="#activity">View all activity</a>'; return; }
    el.innerHTML = a.items.slice(0, 5).map(function (e) {
      var parts = splitText(e.text);
      return '<div class="act-row">' + ic(evIcon(e)) + '<span class="t">' + (e.url ? '<a href="' + esc(safeHref(e.url)) + '"' + (e.url.startsWith('/') ? '' : ' target="_blank" rel="noopener"') + '>' + esc(parts[0]) + '</a>' : esc(parts[0])) + '</span><span class="s">' + esc(parts[1] || (e.kind === 'signin' ? 'Microsoft sign-in' : e.kind === 'security' ? 'Access & security' : (e.source ? 'via ' + e.source : ''))) + '</span><span class="w">' + esc(fmtD(e.at)) + '<span>' + esc(fmtT(e.at)) + '</span></span></div>';
    }).join('') + '<a class="link-center" href="#activity">View all activity</a>';
  }
  function splitText(t) { var m = /^(.*?)(?:\s·\s|\s—\s|:\s)(.*)$/.exec(t || ''); return m ? [m[1], m[2]] : [t, '']; }
  function evIcon(e) { if (e.kind === 'signin') return e.ok === false ? 'alert' : 'log-in'; if (e.kind === 'security') return 'shield'; return { open: 'grid', view: 'eye', search: 'search', save: 'star', update: 'settings', submit: 'bulb', remove: 'trash', refresh: 'refresh', revoke: 'logout', vote: 'thumb' }[e.verb] || 'activity'; }

  /* ───────────── RAIL (computed from live data; nothing is invented) ───────────── */
  function paintRail() {
    if (!$('#rail-sugg')) return;
    var tips = [];
    if (WORK && WORK.tickets && WORK.tickets.available) {
      var old = WORK.tickets.tickets.filter(function (t) { return (ageDays(t.createdAt) || 0) > 7; }).length;
      if (old) tips.push({ ico: 'clipboard', t: 'Review ' + old + ' open ticket' + (old === 1 ? '' : 's') + ' older than 7 days', s: old + ' ticket' + (old === 1 ? ' needs' : 's need') + ' attention', href: '#work' });
      if (WORK.tickets.counts.overdue) tips.push({ ico: 'alert', t: WORK.tickets.counts.overdue + ' overdue ticket' + (WORK.tickets.counts.overdue === 1 ? '' : 's') + ' in your queue', s: 'Past their due date in ServiceDesk Plus', href: '#work' });
    }
    if (SECURITY && SECURITY.mfa && !SECURITY.mfa.strong) tips.push({ ico: 'shield', t: 'Add a phishing-resistant sign-in method', s: 'Authenticator or Windows Hello at Microsoft Security info', href: SECURITY.links.securityInfo, ext: true });
    if (CHANGES) { var unseen = CHANGES.notes.filter(function (n) { return n.unseen; }).length; if (unseen) tips.push({ ico: 'compass', t: 'Read ' + unseen + ' new ITAM → CorpIT note' + (unseen === 1 ? '' : 's'), s: 'What changed for technicians', href: '#changes' }); }
    if (PINS && !PINS.links.length) tips.push({ ico: 'star', t: 'Pin your favorite tools', s: 'Favorites follow you to any machine', href: '#favorites' });
    if (CLAUDE && CLAUDE.momPct != null && CLAUDE.momPct >= 50) tips.push({ ico: 'dollar', t: 'Claude spend is up ' + Math.round(CLAUDE.momPct) + '% vs last month', s: money(CLAUDE.spend) + ' so far · on track for ' + money(CLAUDE.projectedMonthEnd || CLAUDE.spend), href: '#claude/me' });
    if (SUGG && SUGG.counts && !SUGG.counts.mine) tips.push({ ico: 'bulb', t: 'Share an idea for CorpIT', s: 'Suggest a feature and follow its status', href: '#suggestions' });
    var el = $('#rail-sugg');
    if (!tips.length && !(WORK && CHANGES && (SECURITY || (ME && ME.viewingAs)))) return;   // wait until the inputs have loaded
    el.innerHTML = (tips.length ? tips.slice(0, 3).map(function (x) {
      return '<a class="rail-item" href="' + esc(safeHref(x.href)) + '"' + (x.ext ? ' target="_blank" rel="noopener noreferrer"' : '') + '><span class="ico">' + ic(x.ico) + '</span><div class="txt"><b>' + esc(x.t) + '</b><span>' + esc(x.s) + '</span></div><span class="go">' + ic('chevron-right') + '</span></a>';
    }).join('') : '<div class="empty" style="padding:18px 0"><b>You are all caught up</b>No open items need your attention.</div>') + '<a class="link-center" href="#suggestions">View all suggestions</a>';

    if (CHANGES) {
      var secs = {};
      CHANGES.tiles.forEach(function (t) { var s = secs[t.section] = secs[t.section] || { name: t.section, total: 0, moved: 0 }; s.total++; if (t.host === 'corpit' || t.host === 'reporting') s.moved++; });
      var rows = Object.keys(secs).map(function (k) { return secs[k]; }).map(function (s) {
        s.state = s.moved === s.total ? 'ok' : s.moved ? 'wip' : 'pend'; s.pct = s.total ? Math.round(s.moved / s.total * 100) : 0; return s;
      }).sort(function (a, b) { var o = { ok: 0, wip: 1, pend: 2 }; return o[a.state] - o[b.state] || b.total - a.total; });
      var LBL = { ok: 'Migration complete', wip: 'In progress', pend: 'Pending' };
      $('#rail-changes').innerHTML = rows.slice(0, 4).map(function (s) {
        var st = s.state === 'ok' ? '<span class="st ok">' + ic('check') + '</span>' : s.state === 'wip' ? '<span class="st wip">' + ring(s.pct) + '</span>' : '<span class="st pend">' + ic('clock') + '</span>';
        var sub = s.state === 'ok' ? s.moved + ' of ' + s.total + ' tool' + (s.total === 1 ? '' : 's') + ' on CorpIT' : s.state === 'wip' ? s.pct + '% · ' + s.moved + ' of ' + s.total + ' tools moved' : 'Migration not started · ' + s.total + ' tool' + (s.total === 1 ? '' : 's') + ' on ITAM';
        return '<a class="rail-item" href="#changes">' + st + '<div class="txt"><b>' + esc(s.name) + '</b><div class="status ' + s.state + '">' + LBL[s.state] + '</div><span>' + esc(sub) + '</span></div><span class="go">' + ic('chevron-right') + '</span></a>';
      }).join('') + '<a class="link-center" href="#changes">View migration dashboard</a>';
    }
  }
  function ring(p) { var r = 15, C = 2 * Math.PI * r; return '<svg width="36" height="36" viewBox="0 0 36 36"><circle cx="18" cy="18" r="' + r + '" fill="none" style="stroke:var(--accent-tint)" stroke-width="3"/><circle cx="18" cy="18" r="' + r + '" fill="none" style="stroke:var(--accent)" stroke-width="3" stroke-linecap="round" stroke-dasharray="' + (C * p / 100) + ' ' + C + '" transform="rotate(-90 18 18)"/></svg>'; }

  /* ───────────── charts (inline SVG) ───────────── */
  function areaChart(el, series, o) {
    if (!el) return; o = o || {};
    var W = el.clientWidth || 420, H = el.clientHeight || (o.small ? 112 : 190), padL = 34, padB = 18, padT = 6;
    if (!series.length) { el.innerHTML = '<div class="empty">No usage in this window.</div>'; return; }
    var max = Math.max.apply(null, series.map(function (s) { return s.spend; })) || 1;
    var nice = niceMax(max);
    var x = function (i) { return padL + (series.length === 1 ? 0 : i * (W - padL - 4) / (series.length - 1)); };
    var y = function (v) { return padT + (H - padT - padB) * (1 - v / nice); };
    var pts = series.map(function (s, i) { return [x(i), y(s.spend)]; });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
    var area = line + ' L' + pts[pts.length - 1][0].toFixed(1) + ' ' + (H - padB) + ' L' + pts[0][0].toFixed(1) + ' ' + (H - padB) + ' Z';
    var grid = '', labels = '';
    var ticks = o.small ? [0, .5, 1] : [0, .25, .5, .75, 1];
    ticks.forEach(function (f) { var yy = y(nice * f); grid += '<line x1="' + padL + '" x2="' + W + '" y1="' + yy + '" y2="' + yy + '" style="stroke:var(--line)"/><text x="' + (padL - 6) + '" y="' + (yy + 3.5) + '" text-anchor="end" font-size="10" style="fill:var(--dim)">$' + fmtTick(nice * f) + '</text>'; });
    var step = Math.max(1, Math.round(series.length / (o.small ? 4 : 6)));
    series.forEach(function (s, i) { if (i % step === 0 || i === series.length - 1) labels += '<text x="' + x(i) + '" y="' + (H - 4) + '" text-anchor="' + (i === series.length - 1 ? 'end' : i === 0 ? 'start' : 'middle') + '" font-size="10" style="fill:var(--dim)">' + esc(mdLabel(s.day)) + '</text>'; });
    var id = 'g' + Math.random().toString(36).slice(2, 8);
    var dots = pts.filter(function (p, i) { return o.small ? (i % step === 0 || i === pts.length - 1) : true; }).map(function (p) { return '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="2.6" style="fill:var(--card);stroke:var(--accent)" stroke-width="1.6"/>'; }).join('');
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="Daily spend"><defs><linearGradient id="' + id + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" style="stop-color:var(--accent)" stop-opacity=".24"/><stop offset="1" style="stop-color:var(--accent)" stop-opacity="0"/></linearGradient></defs>' + grid +
      '<path d="' + area + '" fill="url(#' + id + ')"/><path d="' + line + '" fill="none" style="stroke:var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' + dots + labels + '</svg>';
  }
  function niceMax(v) { if (v <= 0) return 1; var p = Math.pow(10, Math.floor(Math.log10(v))); var m = v / p; var n = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10; return n * p; }
  function fmtTick(v) { return v >= 100 ? Math.round(v).toString() : v >= 10 ? v.toFixed(0) : v.toFixed(v % 1 ? 1 : 0); }
  function mdLabel(day) { var d = new Date(day + 'T00:00:00Z'); return d.toLocaleString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }); }
  function donut(parts, total, size) {
    var r = size / 2 - 9, C = 2 * Math.PI * r, off = 0, segs = '';
    parts.forEach(function (p) { if (!p.v) return; var len = total ? p.v / total * C : 0; segs += '<circle r="' + r + '" cx="' + size / 2 + '" cy="' + size / 2 + '" fill="none" style="stroke:' + p.c + '" stroke-width="14" stroke-dasharray="' + Math.max(0, len - 2) + ' ' + (C - Math.max(0, len - 2)) + '" stroke-dashoffset="' + (-off) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"/>'; off += len; });
    if (!total) segs = '<circle r="' + r + '" cx="' + size / 2 + '" cy="' + size / 2 + '" fill="none" style="stroke:var(--line)" stroke-width="14"/>';
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" role="img" aria-label="Actions this month">' + segs + '<text x="50%" y="49%" text-anchor="middle" font-size="22" font-weight="700" style="fill:var(--ink)">' + num(total) + '</text><text x="50%" y="66%" text-anchor="middle" font-size="11" style="fill:var(--muted)">Total</text></svg>';
  }
  function spark(vals, w, h, color) {
    if (!vals || vals.length < 2) return '<svg class="spark" width="' + w + '" height="' + h + '"></svg>';
    var max = Math.max.apply(null, vals) || 1, min = Math.min.apply(null, vals), span = (max - min) || 1;
    var pts = vals.map(function (v, i) { return (i * w / (vals.length - 1)).toFixed(1) + ',' + (h - 3 - (h - 6) * (v - min) / span).toFixed(1); });
    return '<svg class="spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '"><polyline fill="none" style="stroke:' + (color || 'var(--accent)') + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="' + pts.join(' ') + '"/></svg>';
  }

  /* ───────────── PROFILE & SETTINGS ───────────── */
  function field(k, v, src, edit, how) {
    var SRC = { entra: 'Entra ID', hr: 'HR', ad: 'Active Directory', corpit: 'CorpIT', session: 'Session', sdp: 'ServiceDesk', claude: 'Claude' };
    var ED = { ro: 'Read-only', synced: 'Synced', you: 'You can edit', admin: 'Admin only' };
    return '<div class="field"><div class="k">' + esc(k) + '</div><div class="v">' + (v == null || v === '' ? '<span class="dim">—</span>' : v) + (how ? '<span class="how">' + how + '</span>' : '') + '</div><div class="m">' + (src ? '<span class="src ' + src + '">' + SRC[src] + '</span>' : '') + (edit ? '<span class="edit ' + (edit === 'you' ? 'you' : edit === 'admin' ? 'admin' : '') + '">' + ED[edit] + '</span>' : '') + '</div></div>';
  }
  function paintProfile() {
    var m = ME, e = m.entra || {}, h = m.hr || {};
    // The standing note promises these preferences are yours to change. In a borrowed
    // view they are somebody else's and the API refuses the write, so it must not.
    var own = $('#pf-own-note');
    if (own) own.innerHTML = m.viewer
      ? 'You are looking at <b>' + esc(m.displayName || m.email) + '</b>\u2019s profile. Organization identity is owned by <b>Microsoft Entra ID</b> and <b>HR</b>; the roles shown are theirs, from Active Directory. Appearance, Workspace and Notifications are their settings and cannot be changed from here.'
      : 'Organization identity is owned by <b>Microsoft Entra ID</b> and <b>HR</b> and is read-only here. Your <b>roles</b> come from Active Directory groups. Everything under Appearance, Workspace and Notifications is yours to change and follows you to any machine.';
    $('#f-identity').innerHTML =
      '<div style="display:flex;align-items:center;gap:16px;padding:4px 0 14px;border-bottom:1px solid var(--line-2)"><div class="photo-lg" id="pf-photo">' + esc(initials(m.displayName)) + '</div><div style="flex:1"><div style="font-size:16px;font-weight:600">' + esc(m.displayName) + '</div><div class="note">Profile photo comes from Microsoft 365. Change it in Outlook or Teams; CorpIT picks it up within a week, or refresh now.</div><div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap"><button class="btn sm" id="pf-photo-refresh">' + ic('refresh') + 'Refresh from Microsoft 365</button><div class="seg"><button data-v="entra"' + (PREFS.photo_source !== 'initials' ? ' class="on"' : '') + '>Photo</button><button data-v="initials"' + (PREFS.photo_source === 'initials' ? ' class="on"' : '') + '>Initials</button></div></div></div></div>' +
      field('Display name', esc(e.displayName || m.displayName), 'entra', 'ro', 'Managed in Entra ID. Ask IT to change it.') +
      field('First / last name', e.givenName || e.surname ? esc((e.givenName || '') + ' ' + (e.surname || '')) : null, 'entra', 'ro') +
      field('Sign-in (UPN)', '<span class="mono">' + esc(e.upn || m.email) + '</span>', 'entra', 'ro') +
      field('Email', '<span class="mono">' + esc(e.mail || m.email) + '</span>', 'entra', 'ro') +
      field('Job title', esc(e.jobTitle || h.title), e.jobTitle ? 'entra' : 'hr', 'ro', 'Flows from HR (Dayforce) into Entra ID.') +
      field('Phone numbers', (e.mobilePhone || (e.businessPhones && e.businessPhones.length)) ? [e.mobilePhone ? 'Mobile ' + esc(e.mobilePhone) : null].concat((e.businessPhones || []).map(function (p) { return 'Work ' + esc(p); })).filter(Boolean).join(' <span class="dim">·</span> ') : null, 'entra', 'ro', 'Manage them at <a href="https://myaccount.microsoft.com/" target="_blank" rel="noopener">myaccount.microsoft.com</a>.') +
      field('Account', e.accountEnabled === false ? '<span class="chip red">Disabled</span>' : '<span class="chip green">' + ic('check') + 'Enabled</span>', 'entra', 'ro', e.source === 'live' ? 'Live from Entra ID · read ' + esc(rel(e.fetchedAt)) + (e.onPremLastSync ? ' · AD → Entra sync ' + esc(rel(e.onPremLastSync)) : '') : (e.syncedAt ? 'Nightly copy from ' + esc(rel(e.syncedAt)) + ' (Graph unreachable)' : null));
    paintPhoto($('#pf-photo'), m, 72);
    if (m.viewer) { $('#pf-photo-refresh').disabled = true; $('#pf-photo-refresh').title = 'Unavailable while viewing as somebody else'; }
    $('#pf-photo-refresh').addEventListener('click', function () { var b = this; b.disabled = true; api('POST', '/photo/refresh').then(function () { PREFS.photo_v = String(Date.now()); toast('Photo refreshed'); paintPhoto($('#pf-photo'), m, 72); paintPhoto($('#side-av'), m, 40); paintPhoto($('#hero-photo'), m, 128); }).catch(function (e) { toast(e.message, true); }).then(function () { b.disabled = false; }); });
    $$('#f-identity .seg button').forEach(function (b) { b.addEventListener('click', function () { $$('#f-identity .seg button').forEach(function (x) { x.classList.toggle('on', x === b); }); savePref('photo_source', b.getAttribute('data-v')); paintPhoto($('#pf-photo'), m, 72); paintPhoto($('#side-av'), m, 40); paintPhoto($('#hero-photo'), m, 128); }); });

    $('#f-org').innerHTML =
      field('Department', esc(h.department || e.department), h.department ? 'hr' : 'entra', 'ro', 'Owned by HR. Changes come through Dayforce.') +
      field('Office / location', esc(h.location || e.officeLocation || [e.city, e.state].filter(Boolean).join(', ')), h.location ? 'hr' : 'entra', 'ro') +
      field('Manager', e.managerName ? esc(e.managerName) + (e.managerTitle ? ' <span class="dim">· ' + esc(e.managerTitle) + '</span>' : '') + ' <span class="mono dim" style="font-size:11.5px">' + esc(e.managerUpn) + '</span>' : (h.managerName ? esc(h.managerName) + ' <span class="mono dim" style="font-size:11.5px">' + esc(h.managerEmail) + '</span>' : null), e.managerName ? 'entra' : 'hr', 'ro') +
      field('Department leader', h.leaderName ? esc(h.leaderName) + ' <span class="mono dim" style="font-size:11.5px">' + esc(h.leaderEmail) + '</span>' : null, 'hr', 'ro') +
      field('Hire date', h.hireDate ? esc(fmtD(h.hireDate)) : null, 'hr', 'ro') +
      field('HR status', h.status ? esc(h.status) : null, 'hr', 'ro', h.loadedAt ? 'HR roster loaded ' + esc(rel(h.loadedAt)) : 'Not in the HR roster') +
      field('Time zone', '<select class="sel" id="pf-tz"></select>', 'corpit', 'you', 'Used for every timestamp on this page. Leave on “Browser” to follow your computer.');
    var tzSel = $('#pf-tz'), zones = ['America/Los_Angeles', 'America/Denver', 'America/Phoenix', 'America/Chicago', 'America/New_York', 'America/Anchorage', 'Pacific/Honolulu', 'UTC', 'Europe/London', 'Asia/Kolkata', 'Asia/Manila'];
    var browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone; if (browserTz && zones.indexOf(browserTz) < 0) zones.unshift(browserTz);
    tzSel.innerHTML = '<option value="">Browser (' + esc(tzLabel(browserTz || 'UTC')) + ')</option>' + zones.map(function (z) { return '<option value="' + esc(z) + '">' + esc(tzLabel(z)) + '</option>'; }).join('');
    tzSel.value = PREFS.timezone || '';
    tzSel.addEventListener('change', function () { savePref('timezone', tzSel.value); loadMe(); });

    var pages = m.pages || {}, keys = Object.keys(pages).sort();
    $('#f-access').innerHTML =
      field('Roles', (m.roles || []).length ? m.roles.map(function (r) { return '<span class="chip ' + (r === 'superadmin' ? 'purple' : 'blue') + '">' + esc(r) + '</span> '; }).join('') : '<span class="dim">No roles resolved</span>', 'ad', 'admin', 'Resolved from ' + (m.viewer ? 'their' : 'your') + ' AD group membership (SaaS-ITH-*) at sign-in' + (m.rolesResolvedAt ? ' · last resolved ' + esc(rel(m.rolesResolvedAt)) : '') + '. Ask a super-admin to change groups.') +
      field('Super-admin', m.isSuperAdmin ? '<span class="chip purple">Yes</span> <span class="dim">via ' + esc(m.superAdminSource || 'role') + '</span>' : 'No', 'ad', 'admin') +
      field('Groups in this session', m.viewer ? '<span class="dim">Not shown in a borrowed view \u2014 the session token is yours, not theirs</span>' : (m.session && m.session.groups && m.session.groups.length ? '<div class="groups">' + m.session.groups.map(function (g) { return '<span class="chip">' + esc(g) + '</span>'; }).join('') + '</div>' : '<span class="dim">None carried in the session token</span>'), 'session', 'ro', 'Per-site access is decided from these groups. They refresh when you sign in again.') +
      field('Page access', '<button class="btn sm" id="pa-toggle">' + keys.length + ' pages · show</button><div class="pa" id="pa-list" hidden style="margin-top:8px">' + (keys.map(function (k) { return '<div class="pr"><span>' + esc(k) + '</span><span class="lv ' + esc(pages[k]) + '">' + esc(pages[k]) + '</span></div>'; }).join('') || '<div class="empty">No page access.</div>') + '</div>', 'corpit', 'admin', 'Derived from roles plus any per-user override.') +
      '<div class="field"><div class="k">Refresh</div><div class="v"><button class="btn sm" id="pa-refresh">' + ic('refresh') + 'Refresh from Active Directory</button><span class="how">' + (m.viewer ? 'Only the signed-in account can be refreshed, so this is unavailable while you are viewing somebody else.' : 'Re-reads your group membership on the next request. Use it after IT changes your groups.') + '</span></div><div class="m"><span class="src ad">Active Directory</span><span class="edit you">You can edit</span></div></div>';
    $('#pa-toggle').addEventListener('click', function () { var l = $('#pa-list'); l.hidden = !l.hidden; this.textContent = keys.length + ' pages · ' + (l.hidden ? 'show' : 'hide'); });
    if (m.viewer) { $('#pa-refresh').disabled = true; $('#pa-refresh').title = 'Unavailable while viewing as somebody else'; }
    $('#pa-refresh').addEventListener('click', function () { var b = this; b.disabled = true; api('POST', '/access/refresh').then(function () { return loadMe(); }).then(function () { toast('Access refreshed'); paintProfile(); if (window.itRbac && window.itRbac.refresh) window.itRbac.refresh(); }).catch(function (e) { toast(e.message, true); }).then(function () { b.disabled = false; }); });

    var mode = (window.itColorMode && window.itColorMode.getPreference()) || PREFS.color_mode || 'system';
    $('#f-appearance').innerHTML =
      '<div class="row"><div class="l"><div class="t">Mode</div><div class="d">Light or dark. Saved to your profile, so it follows you to any machine.</div></div><div class="c"><div class="seg" id="seg-mode"><button data-m="light"' + (mode === 'light' ? ' class="on"' : '') + '>Light</button><button data-m="dark"' + (mode === 'dark' ? ' class="on"' : '') + '>Dark</button><button data-m="system"' + (mode === 'system' ? ' class="on"' : '') + '>System</button></div></div></div>' +
      '<div class="row"><div class="l"><div class="t">Accent</div><div class="d">Colors buttons, links and charts. Applies instantly, follows you to any machine.</div></div><div class="c"><div class="swatches">' + ['ocean', 'reef', 'abyss', 'ember'].map(function (t) { return '<button class="sw' + ((PREFS.theme || 'ocean') === t ? ' on' : '') + '" data-t="' + t + '" title="' + t + '" aria-label="' + t + '"></button>'; }).join('') + '</div></div></div>' +
      '<div class="row"><div class="l"><div class="t">Density</div><div class="d">Row spacing in tables and lists.</div></div><div class="c"><div class="seg" id="seg-density"><button data-d="comfortable"' + ((PREFS.density || 'comfortable') === 'comfortable' ? ' class="on"' : '') + '>Comfortable</button><button data-d="compact"' + (PREFS.density === 'compact' ? ' class="on"' : '') + '>Compact</button></div></div></div>' +
      '<div class="row"><div class="l"><div class="t">Reduce motion</div><div class="d">Turns off animations and transitions.</div></div><div class="c"><button class="toggle" role="switch" id="tog-motion" aria-checked="' + (PREFS.reduce_motion === 'on') + '" aria-label="Reduce motion"></button></div></div>';
    $$('#seg-mode button').forEach(function (b) { b.addEventListener('click', function () { $$('#seg-mode button').forEach(function (x) { x.classList.toggle('on', x === b); }); var v = b.getAttribute('data-m'); PREFS.color_mode = v; if (window.itColorMode) { window.itColorMode.setPreference(v); toast('Saved'); } else savePref('color_mode', v); }); });
    $$('#f-appearance .sw').forEach(function (s) { s.addEventListener('click', function () { $$('#f-appearance .sw').forEach(function (x) { x.classList.toggle('on', x === s); }); savePref('theme', s.getAttribute('data-t')); }); });
    $$('#seg-density button').forEach(function (b) { b.addEventListener('click', function () { $$('#seg-density button').forEach(function (x) { x.classList.toggle('on', x === b); }); savePref('density', b.getAttribute('data-d')); }); });
    $('#tog-motion').addEventListener('click', function () { var on = this.getAttribute('aria-checked') !== 'true'; this.setAttribute('aria-checked', on); savePref('reduce_motion', on ? 'on' : 'off'); });

    loadHub().then(function (hub) {
      var opts = '<option value="">CorpIT Hub (/)</option>' + hub.links.filter(function (l) { return l.host === 'corpit'; }).map(function (l) { return '<option value="' + esc(l.id) + '">' + esc(l.title) + '</option>'; }).join('');
      $('#f-workspace').innerHTML =
        '<div class="row"><div class="l"><div class="t">Start page</div><div class="d">Where CorpIT takes you after sign-in. Only tools that run on CorpIT can be a start page.</div></div><div class="c"><select class="sel" id="sel-start">' + opts + '</select></div></div>' +
        '<div class="row"><div class="l"><div class="t">Favorites</div><div class="d">' + (PINS && PINS.links.length ? PINS.links.length + ' pinned · ' + esc(PINS.links.map(function (l) { return l.title; }).slice(0, 4).join(', ')) + (PINS.links.length > 4 ? '…' : '') : 'Nothing pinned yet — the Hub defaults are shown.') + '</div></div><div class="c"><a class="btn sm" href="#favorites">' + ic('star') + 'Manage favorites</a></div></div>' +
        '<div class="row"><div class="l"><div class="t">Saved searches &amp; drafts</div><div class="d">Kept under My work.</div></div><div class="c"><a class="btn sm" href="#work">' + ic('search') + 'Open My work</a></div></div>';
      // Personal, DEV-only reset. Borrowed profiles stay read-only, just like
      // the other settings; the API also always scopes deletion to the caller.
      if (location.hostname === 'dev-myprofile.nrpi.local') {
        var guideRow = document.createElement('div'); guideRow.className = 'row';
        guideRow.innerHTML = '<div class="l"><div class="t">How-to guides</div><div class="d" id="pf-guide-reset-note">Replay the first-launch guides for your DEV account across browsers and devices. Each guide will open on your next visit.</div><div class="note" id="pf-guide-reset-status" role="status" aria-live="polite" aria-atomic="true"></div></div><div class="c"><button class="btn sm" type="button" id="pf-guide-reset" aria-describedby="pf-guide-reset-note">' + ic('refresh') + 'Reset guides</button></div>';
        $('#f-workspace').appendChild(guideRow);
        var resetGuides = $('#pf-guide-reset'), resetStatus = $('#pf-guide-reset-status');
        resetGuides.disabled = !!m.viewer;
        if (m.viewer) resetGuides.title = 'Return to your own profile to reset your guides';
        resetGuides.addEventListener('click', function () {
          if (m.viewer || resetGuides.disabled) return;
          resetGuides.disabled = true;
          resetGuides.textContent = 'Resetting…';
          resetStatus.textContent = '';
          api('POST', '/guides/reset').then(function (result) {
            if (!result || result.ok !== true) throw new Error('Guides could not be reset. Please try again.');
            resetStatus.textContent = 'Guides reset. Revisit or refresh each workspace to see its welcome guide.';
            toast('Guides reset for your DEV account');
          }).catch(function (error) {
            resetStatus.textContent = error.message;
            toast(error.message, true);
          }).then(function () {
            resetGuides.disabled = false;
            resetGuides.innerHTML = ic('refresh') + 'Reset guides';
          });
        });
      }
      var sel = $('#sel-start'); sel.value = PREFS.default_landing || ''; if (sel.value !== (PREFS.default_landing || '')) sel.value = '';
      sel.addEventListener('change', function () { savePref('default_landing', sel.value); });
    });

    var n = notifPrefs();
    $('#f-notifications').innerHTML =
      '<div class="row"><div class="l"><div class="t">Email me when a suggestion I submitted changes status</div><div class="d">Sent from itcommand@auction.com when a super-admin moves your idea to reviewing, planned, building, shipped or declined.</div></div><div class="c"><button class="toggle" role="switch" data-k="suggestion_status" aria-checked="' + (n.suggestion_status !== false) + '"></button></div></div>' +
      '<div class="row"><div class="l"><div class="t">Suggest new ITAM → CorpIT notes in the rail</div><div class="d">Unread migration notes appear under Suggestions until you open them.</div></div><div class="c"><button class="toggle" role="switch" data-k="changes_badge" aria-checked="' + (n.changes_badge !== false) + '"></button></div></div>' +
      '<p class="note" style="margin-top:10px">Only notifications CorpIT can actually send are listed. Ticket and bug-report emails come from ServiceDesk Plus and Report a Bug, not from here.</p>';
    $$('#f-notifications .toggle').forEach(function (t) { t.addEventListener('click', function () { var on = t.getAttribute('aria-checked') !== 'true'; t.setAttribute('aria-checked', on); var cur = notifPrefs(); cur[t.getAttribute('data-k')] = on; savePref('notifications', JSON.stringify(cur)); paintRail(); }); });
    hydrate($('#v-profile'));
  }
  function paintSecurity() {
    var s = SECURITY, ss = s.session || {}, e = s.entra || {};
    var html =
      '<div class="sec-lbl">This session</div><div class="sess">' +
        '<div><div class="k">Signed in</div><div class="v">' + esc(ss.signedInAt ? fmt(ss.signedInAt) : '—') + '</div></div>' +
        '<div><div class="k">Expires</div><div class="v">' + esc(ss.expiresAt ? fmt(ss.expiresAt) : '—') + (ss.expiresAt ? ' <span class="dim">(' + esc(relFuture(ss.expiresAt)) + ')</span>' : '') + '</div></div>' +
        '<div><div class="k">Credential</div><div class="v">' + (ss.via === 'cookie' ? 'Session cookie' : ss.via === 'bearer' ? 'Bearer token' : '—') + (ss.jtiShort ? ' <span class="mono dim">' + esc(ss.jtiShort) + '…</span>' : '') + '</div></div>' +
        '<div><div class="k">Sign-out everywhere</div><div class="v">' + (s.lastRevokeAll ? 'Last used ' + esc(rel(s.lastRevokeAll)) : 'Never used') + '</div></div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button class="btn danger" id="sec-revoke">' + ic('logout') + 'Sign out everywhere</button><a class="btn" href="/api/gate/federated-logout">' + ic('log-in') + 'Sign out of this browser</a></div>' +
      '<p class="note" style="margin-top:8px">“Sign out everywhere” ends every CorpIT session you hold on any device, including this one. Your Microsoft session is not affected.</p>' +
      '<div class="sec-lbl" style="margin-top:20px">Password &amp; sign-in methods <span class="src entra" style="margin-left:6px">Entra ID' + (s.source === 'live' ? ' · live' : '') + '</span></div>' +
      field('Password last changed', e.lastPasswordChange ? esc(fmtD(e.lastPasswordChange)) + ' <span class="dim">(' + esc(rel(e.lastPasswordChange)) + ')</span>' : null, 'entra', 'you', '<a href="' + esc(s.links.changePassword) + '" target="_blank" rel="noopener">Change your password at Microsoft</a> · changes reach CorpIT on the next directory sync.') +
      field('Sign-in methods', s.mfa.methods.length ? s.mfa.methods.map(function (m) { return '<span class="chip ' + (/Authenticator|Hello|fido2|Oath/i.test(m.type) ? 'green' : '') + '">' + esc(m.label) + (m.name ? ' · ' + esc(m.name) : '') + '</span> '; }).join('') : '<span class="dim">No methods synced</span>', 'entra', 'you', (s.mfa.strong ? 'Strong MFA is registered. ' : 'No phishing-resistant method registered. ') + '<a href="' + esc(s.links.securityInfo) + '" target="_blank" rel="noopener">Manage at Microsoft Security info</a>' + (s.mfa.source === 'live' ? ' · read live from Entra ID' : (s.mfa.syncedAt ? ' · synced ' + esc(rel(s.mfa.syncedAt)) : ''))) +
      field('Last Microsoft sign-in', e.lastLogin ? esc(fmt(e.lastLogin)) : null, 'entra', 'ro', e.likelyLocked ? '<span class="chip red">Account looks locked</span>' : null) +
      '<div class="sec-lbl" style="margin-top:20px">Recent sign-ins <span class="note" style="margin-left:6px;text-transform:none;letter-spacing:0">' + (s.signinsSource === 'live' ? 'live from Entra ID' : 'nightly copy, synced ' + esc(s.signinsAsOf ? rel(s.signinsAsOf) : 'never')) + '</span></div>' +
      (s.signins.length ? '<div class="tblwrap"><table class="tbl"><thead><tr><th>When</th><th>Result</th><th>Application</th><th>From</th><th>Device</th></tr></thead><tbody>' + s.signins.map(function (x) {
        return '<tr><td class="mono" style="font-size:11.5px">' + esc(fmt(x.at)) + '</td><td>' + (x.ok ? '<span class="chip green">OK</span>' : '<span class="chip red" title="' + esc(x.reason || '') + '">Failed</span>') + '</td><td>' + esc(x.app || '') + '</td><td>' + esc([x.city, x.state].filter(Boolean).join(', ') || x.country || '') + ' <span class="mono dim" style="font-size:11px">' + esc(x.ip || '') + '</span></td><td class="dim">' + esc([x.os, x.browser].filter(Boolean).join(' · ')) + '</td></tr>';
      }).join('') + '</tbody></table></div>' : '<div class="empty">No interactive sign-ins synced yet.</div>');
    $('#f-security').innerHTML = html;
    var armed = false, armT;
    $('#sec-revoke').addEventListener('click', function () {
      var b = this;
      if (!armed) { armed = true; b.innerHTML = ic('alert') + 'Click again to confirm'; clearTimeout(armT); armT = setTimeout(function () { armed = false; b.innerHTML = ic('logout') + 'Sign out everywhere'; }, 5000); return; }
      b.disabled = true;
      api('POST', '/sessions/revoke-all').then(function () { location.href = '/login.html?signedout=1'; }).catch(function (e) { toast(e.message, true); b.disabled = false; });
    });
  }
  function relFuture(iso) { var s = (new Date(iso).getTime() - Date.now()) / 1000; if (s <= 0) return 'expired'; if (s < 3600) return 'in ' + Math.round(s / 60) + ' min'; return 'in ' + (Math.round(s / 360) / 10) + ' h'; }

  /* ───────────── MY WORK ───────────── */
  function sev(t) { var p = String(t.priority || '').toLowerCase(); return /high|major|urgent|critical/.test(p) ? 'high' : /medium/.test(p) ? 'medium' : 'baseline'; }
  function ticketRow(t) {
    var a = ageDays(t.createdAt);
    return '<a class="tk" href="' + esc(t.url || '#') + '" target="_blank" rel="noopener noreferrer" data-tid="' + esc(t.displayId) + '" title="' + esc(t.subject) + '"><span class="sev ' + sev(t) + '" title="' + esc(t.priority || 'No priority') + '"></span><span class="id">#' + esc(t.displayId) + '</span><span class="sub">' + esc(t.subject) + '</span><span class="req">' + esc(t.requester || '') + '</span><span class="st">' + esc(t.status) + '</span><span class="age' + (t.overdue ? ' over' : '') + '">' + (t.overdue ? 'overdue · ' : '') + (a == null ? '' : a + 'd') + '</span></a>';
  }
  function bindTicketViews(root) {
    $$('a.tk', root).forEach(function (a) { a.addEventListener('click', function () { if (window.itProfile) window.itProfile.view('ticket', a.getAttribute('data-tid'), 'Opened ticket #' + a.getAttribute('data-tid') + ' · ' + a.title.slice(0, 80), a.href); }); });
  }
  function paintWork() {
    var t = WORK.tickets, el = $('#work-tickets');
    if (!t || !t.available) el.innerHTML = unavailable(t);
    else {
      var c = t.counts;
      el.innerHTML = '<div class="kpi-row" style="margin-bottom:12px">' +
        [['Open', c.open, ''], ['In progress', c.inProgress, ''], ['On hold', c.onHold, ''], ['Overdue', c.overdue, c.overdue ? 'down' : ''], ['Closed this week', c.closedWeek, 'up'], ['Closed this month', c.closedMonth, ''], ['Avg resolve', c.avgResolveHours == null ? '—' : hours(c.avgResolveHours), ''], ['All time', c.total, '']].map(function (k) {
          return '<div class="kpi"><div class="v ' + k[2] + '">' + (typeof k[1] === 'number' ? num(k[1]) : k[1]) + '</div><div class="l">' + k[0] + '</div></div>'; }).join('') + '</div>' +
        (t.tickets.length ? '<div>' + t.tickets.map(ticketRow).join('') + '</div>' : '<div class="empty"><b>Queue is clear</b>' + (t.isTechnician ? 'No active tickets are assigned to you.' : 'No tickets have ever been assigned to you in ServiceDesk Plus.') + '</div>') +
        '<p class="note" style="margin-top:10px">Live from ServiceDesk Plus ' + esc(rel(t.asOf)) + ' · refreshed at most once a minute · opens tickets in ServiceDesk Plus.</p>';
      bindTicketViews(el);
    }
    paintCabs();
    var r = WORK.recent || [];
    $('#work-recent').innerHTML = r.length ? '<div class="list">' + r.map(function (x) { return '<a class="li" href="' + esc(safeHref(x.url) || '#') + '"' + (x.url && !x.url.startsWith('/') ? ' target="_blank" rel="noopener"' : '') + '>' + ic({ asset: 'monitor', ticket: 'ticket', user: 'user', change: 'shield' }[x.object_type] || 'eye') + '<span class="nm">' + esc(x.label || (x.object_type + ' ' + x.object_id)) + '</span><span class="when">' + esc(rel(x.created_at)) + '</span></a>'; }).join('') + '</div>'
      : '<div class="empty"><b>Nothing viewed yet</b>Tickets, assets and user profiles you open on CorpIT appear here. Tools still on ITAM do not report views yet.</div>';
    var d = WORK.drafts || [];
    $('#work-drafts').innerHTML = d.length ? '<div class="list">' + d.map(function (x) { var k = x.draft_key; var href = k.indexOf('suggestion:') === 0 ? '#suggestions' : '#work'; return '<a class="li" href="' + href + '">' + ic('edit') + '<span class="nm">' + esc(x.title || k) + ' <span class="dim">· ' + esc(k.split(':')[0]) + '</span></span><span class="when">' + esc(rel(x.updated_at)) + '</span></a>'; }).join('') + '</div>'
      : '<div class="empty"><b>No drafts</b>Unfinished suggestions are saved here automatically as you type.</div>';
    paintSavedSearches();
    hydrate($('#v-work'));
  }
  var cabView = 'open';
  function paintCabs() {
    var ch = WORK.changes, el = $('#work-cabs');
    if (!ch || !ch.available) { el.innerHTML = unavailable(ch) + (ch && ch.reason === 'changes-scope' ? '<p class="note" style="margin-top:8px">Once the token carries <code>SDPOnDemand.changes.ALL</code>, this panel lists the change controls you requested or own, with closed history.</p>' : ''); return; }
    var rows = cabView === 'open' ? ch.open : ch.closed;
    el.innerHTML = (rows.length ? rows.map(function (c) {
      return '<a class="cab" href="' + esc(c.url || '#') + '" target="_blank" rel="noopener noreferrer" data-cid="' + esc(c.displayId) + '"><span class="id">' + esc(c.displayId) + '</span><span class="t">' + esc(c.title) + '</span><span class="s">' + esc([c.stage, c.status].filter(Boolean).join(' · ')) + '</span><span class="d">' + esc(c.type || '') + (c.priority ? ' · ' + esc(c.priority) : '') + '</span><span class="d mono">' + esc(c.completedAt ? fmtD(c.completedAt) : c.scheduledStart ? fmtD(c.scheduledStart) : fmtD(c.createdAt)) + '</span></a>';
    }).join('') : '<div class="empty"><b>' + (cabView === 'open' ? 'No open change controls' : 'No closed change controls') + '</b>' + (cabView === 'open' ? 'Changes you request or own in ServiceDesk Plus appear here.' : 'Completed, closed and cancelled changes you requested or owned.') + '</div>') +
      '<p class="note" style="margin-top:10px">' + num(ch.open.length) + ' open · ' + num(ch.closed.length) + ' closed · live ' + esc(rel(ch.asOf)) + '</p>';
    $$('a.cab', el).forEach(function (a) { a.addEventListener('click', function () { if (window.itProfile) window.itProfile.view('change', a.getAttribute('data-cid'), 'Opened change ' + a.getAttribute('data-cid'), a.href); }); });
  }
  $$('#cab-seg button').forEach(function (b) { b.addEventListener('click', function () { $$('#cab-seg button').forEach(function (x) { x.classList.toggle('on', x === b); }); cabView = b.getAttribute('data-v'); if (WORK) paintCabs(); }); });
  $('#work-refresh').addEventListener('click', function () { var b = this; b.disabled = true; loadWork(true).then(function () { paintWork(); STATS = null; if (loaded.overview) { paintOvWork(); paintRail(); } toast('Refreshed'); }).catch(function (e) { toast(e.message, true); }).then(function () { b.disabled = false; }); });

  var tsScope = 'mine', tsStatus = 'any';
  $$('#tsearch-scope button').forEach(function (b) { b.addEventListener('click', function () { $$('#tsearch-scope button').forEach(function (x) { x.classList.toggle('on', x === b); }); tsScope = b.getAttribute('data-v'); }); });
  $$('#tsearch-status button').forEach(function (b) { b.addEventListener('click', function () { $$('#tsearch-status button').forEach(function (x) { x.classList.toggle('on', x === b); }); tsStatus = b.getAttribute('data-v'); }); });
  function runSearch(q, scope, status) {
    var out = $('#tsearch-out');
    if (!q || q.length < 2) { out.innerHTML = '<div class="empty">Type at least two characters.</div>'; return; }
    out.innerHTML = '<div class="empty">Searching ServiceDesk Plus…</div>';
    api('GET', '/work/tickets/search?q=' + encodeURIComponent(q) + '&scope=' + scope + '&status=' + status).then(function (r) {
      if (!r.available) { out.innerHTML = unavailable(r); return; }
      out.innerHTML = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><span class="note">' + num(r.total) + ' match' + (r.total === 1 ? '' : 'es') + (r.total > r.tickets.length ? ' · showing ' + r.tickets.length : '') + '</span><button class="btn sm" id="tsearch-save" style="margin-left:auto">' + ic('star') + 'Save this search</button></div>' + (r.tickets.length ? r.tickets.map(ticketRow).join('') : '<div class="empty">No tickets matched.</div>');
      bindTicketViews(out);
      $('#tsearch-save').addEventListener('click', function () {
        var name = prompt('Name this search', q); if (!name) return;
        api('POST', '/saved-searches', { name: name, kind: 'tickets', query: q, params: { scope: scope, status: status } }).then(function () { toast('Search saved'); return loadWork(true); }).then(paintSavedSearches).catch(function (e) { toast(e.message, true); });
      });
    }).catch(function (e) { out.innerHTML = errBox(e); });
  }
  $('#tsearch-go').addEventListener('click', function () { runSearch($('#tsearch-q').value.trim(), tsScope, tsStatus); });
  $('#tsearch-q').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); runSearch(this.value.trim(), tsScope, tsStatus); } });
  function paintSavedSearches() {
    var el = $('#tsearch-saved'), s = (WORK && WORK.savedSearches) || [];
    el.innerHTML = s.length ? '<span class="note" style="align-self:center">Saved:</span>' + s.map(function (x) { return '<span class="chip click blue" data-id="' + x.id + '" data-q="' + esc(x.query) + '" data-p="' + esc(x.params ? JSON.stringify(x.params) : '{}') + '" title="Used ' + x.use_count + '×">' + ic('search') + esc(x.name) + '<span class="x" data-del="' + x.id + '" title="Remove">' + icon('x') + '</span></span>'; }).join('') : '';
    $$('.chip.click', el).forEach(function (c) { c.addEventListener('click', function (e) {
      if (e.target.closest('[data-del]')) return;
      var p = {}; try { p = JSON.parse(c.getAttribute('data-p')); } catch (x) {}
      $('#tsearch-q').value = c.getAttribute('data-q'); runSearch(c.getAttribute('data-q'), p.scope || 'mine', p.status || 'any');
      api('POST', '/saved-searches/' + c.getAttribute('data-id') + '/used').catch(function () {});
    }); });
    $$('[data-del]', el).forEach(function (x) { x.addEventListener('click', function (e) { e.stopPropagation(); api('DELETE', '/saved-searches/' + x.getAttribute('data-del')).then(function () { toast('Removed'); return loadWork(true); }).then(paintSavedSearches).catch(function (er) { toast(er.message, true); }); }); });
  }

  /* ───────────── AI TOOLS & USAGE ─────────────
   * Entitlement and usage are rendered from separate fields and never substituted
   * for one another: a seat with no spend still reads "Active", and spend in a month
   * the collector never covered reads "—", not "$0.00". Three states everywhere —
   * has it / does not have it / could not be determined — because collapsing the
   * third into the second is how a stale feed announces that nobody has Copilot.
   * Authorization for the Team tab is the API's decision, not this file's: the tab
   * is hidden without it, and the endpoint refuses the data regardless. */
  var aiSub = '', aiTab = 'me', aiDrill = null;
  var orgQ = '';   /* the roll-up's find box — the only filter left on this tab */

  function aiRoute(sub) { aiSub = sub || ''; if (AI) renderAi(); }

  function renderAi() {
    var parts = aiSub.split('/');
    var drill = parts[0] === 'u' && parts[1] ? decodeURIComponent(parts[1]).toLowerCase() : null;
    var teamOk = !!(AI.team && AI.team.available);
    // A manager opening this section came for their team far more often than for
    // their own seat, so #claude lands there and #claude/me is the explicit way back.
    // Anyone without reports has one tab and never notices the difference.
    if (parts[0] === 'team') aiTab = teamOk ? 'team' : 'me';
    else if (parts[0] === 'me' || parts[0] === 'limit') aiTab = 'me';
    else aiTab = teamOk ? 'team' : 'me';
    aiDrill = drill;

    var btn = $('#ai-tabs button[data-tab="team"]');
    btn.hidden = !teamOk;
    $$('#ai-tabs button').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-tab') === aiTab); });

    var showTeam = aiTab === 'team' && !drill;
    $('#ai-pane-team').hidden = !showTeam;
    $('#ai-pane-me').hidden = showTeam;
    $('#ai-drillbar').hidden = !drill;
    // A drilldown answers for somebody else. The viewer's own entitlement card sitting
    // above their figures reads as if it described them, so it steps aside.
    $('#ai-mytools').hidden = !!drill;
    if (drill) { $('#claude-limit-card').hidden = true; $('#claude-approvals-card').hidden = true; if ($('#claude-queue-card')) $('#claude-queue-card').hidden = true; }
    else paintLimitCards();

    if (drill) {
      var back = '#claude/' + aiTab;
      var known = TEAM && TEAM.members ? TEAM.members.filter(function (m) { return m.email === drill; })[0] : null;
      /* Painted twice on purpose. This first pass runs before /api/profile/claude
       * has answered, so it can only use what the team payload already holds --
       * enough to put the right NAME and FACE on screen immediately instead of an
       * empty strip. paintDrillSubject() repaints it with the authoritative name
       * and the status badge once the figures are in. */
      $('#ai-drillbar').innerHTML = drillHeadHtml({
        back: back, backLabel: 'Back to ' + (aiTab === 'team' ? 'team usage' : 'my usage'),
        email: drill, name: known ? known.name : drill,
        title: known ? known.title : '', department: known ? known.department : '',
        status: null,
      });
      hydrate($('#ai-drillbar'));
      hydratePhotos($('#ai-drillbar'));
      claudeEmail = drill;
      loadClaude().then(paintClaude).catch(function (e) { $('#claude-kpis').innerHTML = errBox(e); });
      /* The subtitle's TITLE and DEPARTMENT are the reference's own identifying
       * line -- ai-usage-credits.html:1951 renders `dept · email` under the
       * name -- and they live in the team payload, not in /claude, which knows
       * only the Claude roster's display name. Arriving straight at
       * #claude/u/<email> leaves TEAM null, so the header would name the person
       * by email alone. That is not a rare path: the "view someone" box at the
       * bottom of this tab sets exactly this hash on every use, as does any
       * pasted or bookmarked link. Memoised by once(), so it costs nothing when
       * the drill came from the team table, and a failure is swallowed -- the
       * name and the badge do not depend on it. */
      if (teamOk && !TEAM) {
        loadTeam().then(function () {
          if (aiDrill === drill && CLAUDE && CLAUDE.subject && CLAUDE.subject.email === drill) paintSubjectCopy(CLAUDE);
        }).catch(function () {});
      }
      return;
    }
    if (showTeam) {
      $('#ai-team-kpis').innerHTML = '<div class="empty">Loading…</div>';
      loadTeam().then(paintTeam).catch(function (e) { $('#ai-team-kpis').innerHTML = errBox(e); });
      return;
    }
    claudeEmail = null;
    loadClaude().then(paintClaude).catch(function (e) { $('#claude-kpis').innerHTML = errBox(e); });
  }

  /* ───────────── CLAUDE LIMIT: raise, request, approve ─────────────
   * Two cards. "Claude limit" (My usage pane) is the person's own limit and what
   * they can do about it: one click from the default, or a request to their
   * manager. "Claude limit approvals" (above both panes) is the approver's queue:
   * what is waiting for them, what they are waiting on, what they decided.
   * Every rule lives in the API (claude-limit-approvals.js); this file only
   * renders what it is told and posts the button presses. */
  var LIMIT = null, LQUEUE = null, limitBusy = false;
  function loadLimit() { return api('GET', '/claude-limit').then(function (d) { LIMIT = d; return d; }); }
  function loadLQueue() { return api('GET', '/claude-limit/queue').then(function (d) { LQUEUE = d; return d; }); }
  function usd(n) { if (n == null) return 'no cap'; var v = Number(n); return '$' + v.toLocaleString('en-US', { minimumFractionDigits: Number.isInteger(v) ? 0 : 2, maximumFractionDigits: 2 }); }
  var LSTATUS = {
    pending_manager: ['amber', 'Waiting for manager'], forwarding: ['amber', 'Forwarding'], pending_leader: ['amber', 'Waiting for functional leader'],
    applying: ['blue', 'Being applied'], approved: ['green', 'Approved'], apply_failed: ['red', 'Approved, not applied'],
    denied: ['red', 'Not approved'], cancelled: ['', 'Withdrawn'], failed: ['red', 'Not sent'], escalated: ['purple', 'With the Service Desk'],
  };
  function lchip(r) {
    var s = LSTATUS[r.status] || ['', r.status];
    var label = s[1];
    if (r.status === 'pending_manager' && r.manager) label = 'Waiting for ' + (r.manager.name || r.manager.email);
    if (r.status === 'pending_leader' && r.leader) label = 'Waiting for ' + (r.leader.name || r.leader.email);
    if (r.status === 'approved' && r.applied == null) label = 'Approved, no change needed';
    if (r.status === 'approved' && r.resetState === 'reset') label = 'Ended on the 1st';
    return '<span class="chip ' + s[0] + '">' + esc(label) + '</span>';
  }
  function ltickets(r) {
    return (r.tickets || []).map(function (t) {
      return '<a href="' + esc(t.url) + '" target="_blank" rel="noopener" class="note" title="' + esc(t.action + (t.closed ? ', closed' : ', open')) + '">' + esc(t.display) + '</a>';
    }).join(' ');
  }
  // The API flags a request whose step stopped part-way (the service restarted) and has not moved since.
  var INTERRUPTED = 'This stopped part-way through and has not moved since.';
  var LSTEP = 100;   // the request stepper moves in $100
  /* Try again answers with what it finished: applied, forwarded or escalated. */
  function retryToast(r) {
    if (r.resumed === 'escalated') return 'Sent to the Service Desk';
    if (r.resumed === 'forwarded') return 'Forwarded to ' + ((r.request.leader && (r.request.leader.name || r.request.leader.email)) || 'the functional leader');
    return r.request.applied == null ? 'Approved; no change was needed' : 'Applied: limit is now ' + usd(r.request.requested);
  }
  function lbandText(r) { return (r.band === 'self' ? 'Self-raise' : r.band === 'manager' ? 'Manager' : 'Manager + functional leader') + (r.ownerApproval ? ' (Claude seat owner)' : ''); }

  function paintLimitCards() {
    var card = $('#claude-limit-card'), qcard = $('#claude-approvals-card');
    if (!card || !qcard) return Promise.resolve();
    return Promise.all([loadLimit().catch(function (e) { return { _err: e }; }), loadLQueue().catch(function (e) { return { _err: e }; })]).then(function (res) {
      paintLimit(res[0]); paintLQueue(res[1]); paintBoard(res[1]);
      if (aiSub === 'limit') {
        var go = (LQUEUE && LQUEUE.forMe && LQUEUE.forMe.length) ? qcard : card;
        if (!go.hidden) try { go.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (e) {}
      }
    });
  }

  function paintLimit(d) {
    var card = $('#claude-limit-card'), el = $('#claude-limit');
    if (d && d._err) { card.hidden = false; el.innerHTML = errBox(d._err); return; }
    if (!d || (!d.member && !(d.history || []).length && !d.open)) { card.hidden = true; return; }
    card.hidden = false;
    var L = d.limit, s = d.settings, h = '';
    if (L) {
      var pct = L.amount ? Math.round(L.spent / L.amount * 100) : null;
      h += '<div class="kpi-row" style="margin-bottom:12px">'
        + '<div class="kpi"><div class="v">' + esc(L.unlimited ? 'No cap' : usd(L.amount)) + '</div><div class="l">Monthly limit' + (L.justApplied ? ' · just changed' : '') + '</div></div>'
        + '<div class="kpi"><div class="v">' + esc(usd(L.spent)) + '</div><div class="l">Counted toward this limit' + (pct != null ? ' · ' + pct + '%' : '') + '</div></div>'
        + (L.amount != null && d.base != null && L.amount !== d.base && !d.resetDue ? '<div class="kpi"><div class="v" style="font-size:16px">' + esc(d.resetsOn) + '</div><div class="l">Back to ' + esc(usd(d.base)) + ' on this date (UTC)</div></div>' : '')
        + '</div>';
    }
    var act = '';
    if (d.viewingAs) act = '<p class="note">A borrowed view is read-only. Only ' + esc(d.viewingAs.email) + ' can raise or request their limit.</p>';
    else if (!d.enabled) act = '<p class="note">Raising your limit from My Profile is not switched on yet.</p>';
    else if (!d.member) act = '<p class="note">You do not have a Claude seat on record, so there is no limit to raise.</p>';
    else if (!s || s.managerRaise == null || d.base === undefined) {
      // A page newer than the hub it is talking to (only for the moments of a deploy).
      act = '<p class="note">This card is being updated. Reload the page in a minute.</p>';
      d = Object.assign({}, d, { canSelfRaise: false, canRequest: false });
    }
    if (d.open) {
      var o = d.open;
      act += '<div class="drill-lim" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">'
        + '<span>Your request for <b class="mono">' + esc(usd(o.requested)) + '</b>/mo</span>' + lchip(o) + ltickets(o)
        + ((o.canWithdraw != null ? o.canWithdraw : o.status === 'pending_manager' || o.status === 'pending_leader') && !d.viewingAs ? '<button class="btn sm ghost" data-lim-cancel="' + o.id + '">Withdraw</button>' : '')
        + (o.canRetry && d.enabled && !d.viewingAs ? '<button class="btn sm" data-lim-retry="' + o.id + '">Try again</button>' : '')
        + '</div>'
        + (o.failReason && o.status === 'apply_failed' ? '<p class="note" style="color:var(--red-tx)">' + esc(o.failReason) + '</p>' : '')
        + (o.interrupted ? '<p class="note">' + INTERRUPTED + (o.canRetry ? ' Try again picks up where it stopped.' : '') + (o.canWithdraw ? (o.canRetry ? ' Or withdraw it.' : ' You can withdraw it.') : '') + '</p>' : '');
    } else if (d.escalated) {
      act += '<p class="note">Your request for ' + esc(usd(d.escalated.requested)) + '/mo is with the Service Desk ' + ltickets(d.escalated) + ' because it could not be routed. A Claude seat owner can approve or deny it; until then you cannot make another request this month.</p>';
    }
    // The one self-raise of the month first, then the stepper for anything bigger.
    if (d.canSelfRaise) {
      act += '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px">'
        + '<button class="btn" data-lim-self>Raise my limit to ' + esc(usd(d.selfTo)) + '</button>'
        + '<span class="note">' + (d.manager || d.seatOwner ? '+' + esc(usd(d.settings.selfRaise)) + ' once a month is automatic. No approval needed.'
          : 'No manager on record (' + esc(d.managerWhy || 'unknown') + '), so this goes to the Service Desk and is not applied now.') + '</span></div>';
    } else if (d.canRequest && d.base != null && (d.selfUsed || !d.resetDue)) {
      // Last month's raise not put back yet (the reset retries hourly): "already raised this month" would be false.
      act += '<p class="note" style="margin-bottom:8px">' + (d.selfUsed ? 'This month\'s automatic +' + esc(usd(d.settings.selfRaise)) + ' has been used.'
        : 'Your limit was already raised this month.') + '</p>';
    }
    if (d.canRequest) {
      var start = d.canSelfRaise ? d.selfTo : L.amount + LSTEP;   // the new amount: +$100
      act += '<div data-lim-ask data-start="' + start + '" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
        + '<span class="note">' + (d.canSelfRaise ? 'Or choose an amount:' : 'Choose an amount:') + '</span>'
        + '<span style="display:inline-flex;align-items:stretch;border:1px solid var(--line);border-radius:6px;background:var(--card);overflow:hidden">'
        + '<b class="mono" data-lim-val tabindex="0" role="spinbutton" aria-label="New monthly total" aria-valuemin="' + start + '" style="min-width:90px;padding:8px 12px;text-align:right;font-size:15px;align-self:center"></b>'
        + '<span style="display:flex;flex-direction:column;border-left:1px solid var(--line)">'
        + '<button type="button" data-lim-up aria-label="$' + LSTEP + ' more" style="flex:1;min-height:17px;padding:0 12px;border:0;background:none;color:inherit;cursor:pointer;font-size:11px;line-height:1">&#9650;</button>'
        + '<button type="button" data-lim-dn aria-label="$' + LSTEP + ' less" style="flex:1;min-height:17px;padding:0 12px;border:0;border-top:1px solid var(--line);background:none;color:inherit;cursor:pointer;font-size:11px;line-height:1">&#9660;</button>'
        + '</span></span>'
        + '<button class="btn sm" data-lim-req></button>'
        + '<span data-lim-live aria-live="polite" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap"></span></div>'
        + '<p class="note" data-lim-rule style="margin-top:6px"></p>';
    }
    act += '<div class="note" data-lim-msg style="margin-top:6px"></div>';
    var hist = (d.history || []);
    if (hist.length) {
      act += '<table class="tbl" style="margin-top:10px"><thead><tr><th>Asked</th><th class="num">New total</th><th>How</th><th>Status</th><th>Tickets</th></tr></thead><tbody>'
        + hist.map(function (r) {
          return '<tr><td>' + esc(rel(r.createdAt)) + '</td><td class="num">' + esc(usd(r.requested)) + '</td><td>' + esc(lbandText(r)) + '</td><td>' + lchip(r)
            + (r.denyReason ? '<div class="note">' + esc(r.denyReason) + '</div>' : '') + '</td><td>' + ltickets(r) + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    el.innerHTML = h + act;
    if (s && s.selfRaise != null && s.managerRaise != null) limitHelp(s, d.seatOwner);
    bindLimit(el, d);
  }

  /* The ? on the card: the raise sizes come from the console, so the text is built from
   * what the hub sent, and the label and any tooltip already made are refreshed. */
  function limitHelp(s, owner) {
    var t = 'Your monthly Claude spend limit in Anthropic, and how to raise it. +' + usd(s.selfRaise) + ' once a month is automatic: no approval needed, and it applies straight away. More than +' + usd(s.selfRaise) + ', or a second raise that month, goes to your manager. More than +' + usd(s.managerRaise) + ' over the limit you started the month with goes to your manager, then your functional leader.'
      + (owner ? ' As a Claude seat owner, your own raises need no other approval and apply straight away; your manager is emailed.' : '')
      + ' Each approval is logged on a Service Desk ticket and emailed from Enterprise Approvals. Raises made here end on the 1st (UTC), back to the limit you started the month with.';
    if (HELP['sec-limit'] === t) return;
    HELP['sec-limit'] = t;
    $$('.help[data-h="sec-limit"]').forEach(function (b) {
      b.setAttribute('aria-label', helpLabel('sec-limit'));
      var tip = b.querySelector('.htip');
      if (tip) tip.textContent = t;
    });
  }

  function limMsg(el, text, err) { var m = el.querySelector('[data-lim-msg]'); if (m) { m.textContent = text; m.style.color = err ? 'var(--red-tx)' : 'var(--green-tx)'; } }
  function limPost(el, btn, path, body, ok) {
    if (limitBusy) return;
    limitBusy = true; btn.disabled = true; var was = btn.textContent; btn.textContent = 'Working…';
    api('POST', path, body).then(function (r) {
      limitBusy = false; toast(ok(r)); paintLimitCards();
    }).catch(function (e) {
      // Repaint first (the state may have moved on), then say why; painting after the message would wipe it.
      var why = e.message || 'That did not work.';
      limitBusy = false; btn.disabled = false; btn.textContent = was; toast(why, true);
      paintLimitCards().then(function () { limMsg($('#claude-limit'), why, true); });
    });
  }
  function bindLimit(el, d) {
    // The raise sizes this card showed: if they were changed in the console since, the hub
    // refuses (409 SETTINGS_CHANGED) and the card repaints with the new ones.
    var sizes = d.settings ? { selfRaise: d.settings.selfRaise, managerRaise: d.settings.managerRaise } : {};
    var self = el.querySelector('[data-lim-self]');
    if (self) self.addEventListener('click', function () {
      limPost(el, self, '/claude-limit/self-raise', sizes, function (r) {
        return r.escalated ? 'Sent to the Service Desk: no manager on record' : 'Your limit is now ' + usd(r.request.requested);
      });
    });
    var ask = el.querySelector('[data-lim-ask]'), req = el.querySelector('[data-lim-req]');
    if (ask && req) {
      var start = Number(ask.getAttribute('data-start')), v = start;
      var val = ask.querySelector('[data-lim-val]'), up = ask.querySelector('[data-lim-up]'), dn = ask.querySelector('[data-lim-dn]'), rule = el.querySelector('[data-lim-rule]');
      var mgr = d.manager ? d.manager.name || d.manager.email : null;
      var same = d.manager && d.leader && d.leader.email === d.manager.email;
      var ldr = d.leader ? d.leader.name || d.leader.email : 'the Service Desk (' + (d.leaderWhy || 'no functional leader on record') + ')';
      var cap = d.base + d.settings.managerRaise;   // above this, the functional leader approves as well
      var show = function () {
        val.textContent = usd(v); val.setAttribute('aria-valuenow', String(v));
        dn.setAttribute('aria-disabled', v <= start ? 'true' : 'false'); dn.style.opacity = v <= start ? '.35' : ''; dn.style.cursor = v <= start ? 'default' : 'pointer';
        req.textContent = d.seatOwner || auto() ? 'Raise to ' + usd(v) + ' now' : !mgr ? 'Send to the Service Desk' : same || v <= cap ? 'Send to ' + mgr : 'Send to ' + mgr + ', then ' + ldr;
        rule.innerHTML = d.seatOwner ? esc('As a Claude seat owner, any amount you choose applies straight away; no other approval is needed.' + (mgr ? ' ' + mgr + ' is emailed.' : ''))
          : !mgr ? esc('No manager on record (' + (d.managerWhy || 'unknown') + '), so a request goes to the Service Desk.')
          : esc('More than +' + usd(d.settings.selfRaise) + ', or a second raise this month, goes to ' + mgr + '.') + '<br>'
            + esc(same ? mgr + ' approves any amount (your manager and functional leader).'
              : 'More than +' + usd(d.settings.managerRaise) + ' over ' + usd(d.base) + ' goes to ' + mgr + ', then ' + ldr + '.');
      };
      // The first +$100 of the month from the stepper is the same automatic raise as the button.
      var auto = function () { return d.canSelfRaise && v === d.selfTo; };
      var step = function (n) { var w = v + n * LSTEP; if (w < start || w > 1000000) return; v = w; show(); };
      var live = ask.querySelector('[data-lim-live]');
      var say = function () { live.textContent = usd(v) + '. ' + req.textContent; };
      up.addEventListener('click', function () { step(1); say(); });
      dn.addEventListener('click', function () { step(-1); say(); });
      val.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowUp') { e.preventDefault(); step(1); } else if (e.key === 'ArrowDown') { e.preventDefault(); step(-1); } else if (e.key === 'Enter') { e.preventDefault(); req.click(); }
      });
      show();
      req.addEventListener('click', function () {
        if (auto()) return limPost(el, req, '/claude-limit/self-raise', sizes, function (r) {
          return r.escalated ? 'Sent to the Service Desk: no manager on record' : 'Your limit is now ' + usd(r.request.requested);
        });
        // A seat owner's raise is not reviewed by anybody, so it is confirmed here first.
        if (d.seatOwner && !confirm('Raise your Claude limit to ' + usd(v) + '/mo now? As a Claude seat owner it applies in Anthropic straight away.')) return;
        limPost(el, req, '/claude-limit/requests', Object.assign({ newLimit: v }, sizes), function (r) {
          if (r.escalated) return 'Sent to the Service Desk: no manager on record';
          if (r.request && r.request.status === 'approved') return 'Your limit is now ' + usd(r.request.requested);
          // The hub treats a first +selfRaise of the month as the self-raise, applied now.
          if (r.request && r.request.band === 'self') return 'Your limit is now ' + usd(r.request.requested);
          return 'Request sent to ' + ((r.request.manager && (r.request.manager.name || r.request.manager.email)) || 'your manager');
        });
      });
    }
    $$('[data-lim-cancel]', el).forEach(function (b) {
      b.addEventListener('click', function () { if (!confirm('Withdraw this request?')) return; limPost(el, b, '/claude-limit/requests/' + b.getAttribute('data-lim-cancel') + '/cancel', {}, function () { return 'Request withdrawn'; }); });
    });
    $$('[data-lim-retry]', el).forEach(function (b) {
      b.addEventListener('click', function () { limPost(el, b, '/claude-limit/requests/' + b.getAttribute('data-lim-retry') + '/retry', {}, retryToast); });
    });
  }

  function paintLQueue(q) {
    var card = $('#claude-approvals-card'), el = $('#claude-approvals');
    if (q && q._err) { card.hidden = true; return; }       // the limit card already says if the API is down
    var me = ME && ME.email;
    var forMe = (q && q.forMe) || [], waiting = ((q && q.waitingOn) || []).filter(function (r) { return r.requester.email !== me; }), decided = (q && q.decided) || [];
    if (!forMe.length && !waiting.length && !decided.length) { card.hidden = true; return; }
    card.hidden = false;
    $('#claude-approvals-note').textContent = forMe.length ? forMe.length + ' waiting for you' : '';
    var ro = !!(q.viewingAs), off = !q.enabled, h = '';
    h += '<h3 style="font-size:13px;margin:0 0 6px">Waiting for you</h3>';
    if (!forMe.length) h += '<p class="note" style="margin-bottom:12px">Nothing is waiting for your approval.</p>';
    else h += '<table class="tbl" style="margin-bottom:14px"><thead><tr><th>Person</th><th class="num">Now</th><th class="num">Asking for</th><th>Your step</th><th>Asked</th><th></th></tr></thead><tbody>'
      + forMe.map(function (r) {
        var step = r.step === 'leader' ? 'Final approval (functional leader)' : r.forwards ? 'Manager, then ' + esc((r.leader && (r.leader.name || r.leader.email)) || 'the Service Desk') : 'Manager approval';
        var btns = ro ? '<span class="note">Read-only view</span>' : off ? '<span class="note">Approvals are switched off</span>'
          : '<button class="btn sm" data-q-ok="' + r.id + '" data-q-amt="' + esc(usd(r.requested)) + '" data-q-fwd="' + (r.forwards ? 1 : 0) + '" data-q-to="' + esc((r.leader && (r.leader.name || r.leader.email)) || 'the Service Desk (no functional leader on record)') + '">' + (r.forwards ? 'Approve and forward' : 'Approve') + '</button> '
          + '<button class="btn sm ghost" data-q-no="' + r.id + '">Deny</button>';
        return '<tr data-q-row="' + r.id + '"><td><b>' + esc(r.requester.name || r.requester.email) + '</b><div class="note">' + esc(r.requester.email) + '</div></td>'
          + '<td class="num">' + esc(usd(r.current)) + '</td><td class="num"><b>' + esc(usd(r.requested)) + '</b></td><td>' + step + '</td><td>' + esc(rel(r.createdAt)) + '</td>'
          + '<td style="white-space:nowrap">' + btns + '<div class="note" data-q-msg></div></td></tr>';
      }).join('') + '</tbody></table>';
    if (waiting.length) {
      h += '<h3 style="font-size:13px;margin:0 0 6px">You approved, waiting on</h3><table class="tbl" style="margin-bottom:14px"><thead><tr><th>Person</th><th class="num">Asking for</th><th>Status</th><th>Tickets</th><th></th></tr></thead><tbody>'
        + waiting.map(function (r) {
          return '<tr data-q-row="' + r.id + '"><td style="white-space:nowrap">' + esc(r.requester.name || r.requester.email) + '</td><td class="num">' + esc(usd(r.requested)) + '</td><td>' + lchip(r)
            + (r.status === 'apply_failed' && r.failReason ? '<div class="note" style="color:var(--red-tx)">' + esc(r.failReason) + '</div>' : '')
            + (r.interrupted ? '<div class="note">' + INTERRUPTED + '</div>' : '') + '</td><td>' + ltickets(r) + '</td>'
            + '<td style="white-space:nowrap">' + (r.canRetry && !ro && !off ? '<button class="btn sm" data-q-retry="' + r.id + '">Try again</button><div class="note" data-q-msg></div>' : '') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    if (decided.length) {
      h += '<h3 style="font-size:13px;margin:0 0 6px">Recently decided by you</h3><table class="tbl"><thead><tr><th>Person</th><th class="num">New total</th><th>Status</th><th>When</th><th>Tickets</th></tr></thead><tbody>'
        + decided.map(function (r) {
          return '<tr><td>' + esc(r.requester.name || r.requester.email) + '</td><td class="num">' + esc(usd(r.requested)) + '</td><td>' + lchip(r)
            + (r.denyReason ? '<div class="note">' + esc(r.denyReason) + '</div>' : '') + '</td><td>' + esc(rel(r.updatedAt)) + '</td><td>' + ltickets(r) + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    el.innerHTML = h;
    bindLQueue(el);
  }

  function qPost(btn, path, body, ok) {
    if (limitBusy) return;
    var row = btn.closest('tr'), rid = row && row.getAttribute('data-q-row');
    limitBusy = true; btn.disabled = true; var was = btn.textContent; btn.textContent = 'Working…';
    api('POST', path, body).then(function (r) { limitBusy = false; toast(ok(r)); paintLimitCards(); })
      .catch(function (e) {
        // Same order as limPost: repaint, then put the reason back on the row if it is still listed.
        var why = e.message || 'That did not work.';
        limitBusy = false; btn.disabled = false; btn.textContent = was; toast(why, true);
        paintLimitCards().then(function () {
          var r2 = rid && $('#claude-approvals [data-q-row="' + rid + '"]'), msg = r2 && r2.querySelector('[data-q-msg]');
          if (msg) { msg.textContent = why; msg.style.color = 'var(--red-tx)'; }
        });
      });
  }
  function bindLQueue(el) {
    $$('[data-q-ok]', el).forEach(function (b) {
      b.addEventListener('click', function () {
        // Approving the last step changes the person's limit in Anthropic; say so before it happens.
        var fwd = b.getAttribute('data-q-fwd') === '1';
        if (!confirm(fwd ? 'Approve ' + b.getAttribute('data-q-amt') + '/mo and send it to ' + b.getAttribute('data-q-to') + ' for the final approval?'
          : 'Approve ' + b.getAttribute('data-q-amt') + '/mo? Their Claude limit is changed in Anthropic straight away.')) return;
        qPost(b, '/claude-limit/requests/' + b.getAttribute('data-q-ok') + '/approve', {}, function (r) {
          return r.forwarded ? 'Approved and forwarded' : r.escalated ? 'Approved; sent to the Service Desk (no functional leader)' : 'Approved: limit is now ' + usd(r.request.requested);
        });
      });
    });
    $$('[data-q-no]', el).forEach(function (b) {
      b.addEventListener('click', function () {
        var cell = b.parentNode, id = b.getAttribute('data-q-no');
        cell.innerHTML = '<input class="inp" data-q-reason placeholder="Reason (the person sees this)" style="width:220px" maxlength="500"> '
          + '<button class="btn sm danger" data-q-deny>Deny</button> <button class="btn sm ghost" data-q-back>Back</button><div class="note" data-q-msg></div>';
        var inp = cell.querySelector('[data-q-reason]'); try { inp.focus(); } catch (e) {}
        cell.querySelector('[data-q-back]').addEventListener('click', function () { paintLQueue(LQUEUE); });
        cell.querySelector('[data-q-deny]').addEventListener('click', function () {
          var reason = inp.value.trim(), m = cell.querySelector('[data-q-msg]');
          if (reason.length < 3) { m.textContent = 'Give the person a reason.'; m.style.color = 'var(--red-tx)'; return; }
          qPost(this, '/claude-limit/requests/' + id + '/deny', { reason: reason }, function () { return 'Denied; they have been emailed'; });
        });
      });
    });
    $$('[data-q-retry]', el).forEach(function (b) {
      b.addEventListener('click', function () { qPost(b, '/claude-limit/requests/' + b.getAttribute('data-q-retry') + '/retry', {}, retryToast); });
    });
  }

  /* ───────── request flipper: Waiting on me / My team / All (Jeramy's picks 12-15) ─────────
   * One request at a time, like a rolodex, from the queue's `board`: ← → (or the arrow keys,
   * or the list) to flip. The buttons post to the same approve / deny / retry routes as the
   * approvals card, so the API still decides who may do what; this only shows what it sent. */
  var BOARD = null, BTAB = null, BPOS = {}, BTABS = [['waiting', 'Waiting on me'], ['team', 'My team'], ['all', 'All']];
  var BOPEN = { pending_manager: 1, forwarding: 1, pending_leader: 1, applying: 1, apply_failed: 1 };
  function reducedMotion() { return document.documentElement.getAttribute('data-reduce-motion') === 'on' || !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches); }
  function boardCard() {
    var c = $('#claude-queue-card'), anchor = $('#claude-limit-card');
    if (c || !anchor) return c;
    if (!$('#cq-css')) {
      var s = document.createElement('style'); s.id = 'cq-css';
      s.textContent = '#claude-queue-card .tabs button:focus-visible,#cq-deck:focus-visible{outline:2px solid var(--pblue);outline-offset:2px}'
        + '#cq-stage{perspective:900px;padding-bottom:8px}'
        + '#cq-deck{position:relative;border:1px solid var(--line);border-radius:12px;background:var(--card);padding:14px 16px;min-height:150px;outline:none;'
        + 'box-shadow:0 4px 0 -1px var(--card),0 4px 0 0 var(--line),0 8px 0 -2px var(--card),0 8px 0 -1px var(--line);transform-origin:50% 0}'
        + '#cq-deck.one{box-shadow:none}'
        + '.cq-top{display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}.cq-top .who{flex:1 1 200px;min-width:0}.cq-top .who b{font-size:15px}'
        + '.cq-amt{display:flex;gap:18px;flex-wrap:wrap;margin:12px 0 10px}.cq-amt .v{font-size:20px;font-weight:700;letter-spacing:-.02em}.cq-amt .l{font-size:12px;color:var(--muted)}'
        + '.cq-route{display:grid;grid-template-columns:auto 1fr;gap:3px 12px;font-size:13px;margin-bottom:8px}.cq-route dt{color:var(--muted)}.cq-route dd{margin:0;min-width:0;overflow-wrap:anywhere}'
        + '.cq-act{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}'
        + '.cq-nav{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}.cq-nav .pos{font-family:var(--mono);font-size:12px;color:var(--muted);min-width:64px;text-align:center}'
        + '.cq-nav select{flex:1 1 180px;min-width:0;max-width:100%}.cq-nav .btn .ic{width:15px;height:15px}';
      document.head.appendChild(s);
    }
    c = document.createElement('div'); c.className = 'card'; c.id = 'claude-queue-card'; c.hidden = true; c.style.marginBottom = '14px';
    c.innerHTML = '<div class="card-hd"><span class="ic" data-icon="users"></span><h2>Claude limit requests</h2>' + hx('sec-queue')
      + '<span class="note" id="cq-note" style="margin-left:auto"></span></div><div class="card-bd" id="cq-bd"></div>';
    anchor.parentNode.insertBefore(c, anchor);
    hydrate(c);
    c.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      var t = e.target && e.target.tagName; if (t === 'INPUT' || t === 'SELECT' || t === 'TEXTAREA') return;
      if (e.target && e.target.closest && e.target.closest('.tabs')) return;   // the tab strip moves between tabs
      e.preventDefault(); boardGo(e.key === 'ArrowLeft' ? -1 : 1);
    });
    return c;
  }
  // Open requests first, then newest, for the tabs that list history.
  function boardSort(list) {
    return list.slice().sort(function (a, b) {
      var o = (BOPEN[a.status] ? 0 : 1) - (BOPEN[b.status] ? 0 : 1);
      return o || (new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    });
  }
  function paintBoard(q) {
    var c = boardCard(); if (!c) return;
    var b = q && !q._err && q.board;
    if (!b) { c.hidden = true; BOARD = null; return; }
    var lists = { waiting: b.waiting || [], team: boardSort(b.team || []), all: b.all ? boardSort(b.all) : null };
    // Nothing to act on and nobody under them: a seat owner still gets the card (All), nobody else.
    if (!b.seatOwner && !lists.waiting.length && !lists.team.length) { c.hidden = true; BOARD = null; return; }
    c.hidden = false;
    if (!BTAB || !lists[BTAB]) BTAB = lists.waiting.length ? 'waiting' : lists.team.length ? 'team' : 'all';
    BOARD = { q: q, b: b, lists: lists };
    $('#cq-note').textContent = lists.waiting.length ? lists.waiting.length + ' waiting on you' : '';
    renderBoard(0);
  }
  function boardIdx() {
    var list = BOARD.lists[BTAB] || [], want = BPOS[BTAB], i = 0;
    if (want) { list.forEach(function (r, k) { if (r.id === want.id) i = k + 1; }); if (!i) i = Math.min(want.i, list.length - 1) + 1; }
    return Math.max(0, i - 1);
  }
  function renderBoard(dir) {
    var bd = $('#cq-bd'), b = BOARD.b, list = BOARD.lists[BTAB] || [], i = boardIdx(), r = list[i];
    BPOS[BTAB] = r ? { id: r.id, i: i } : null;
    var h = '<div class="tabs" role="tablist" aria-label="Claude limit requests">' + BTABS.filter(function (t) { return BOARD.lists[t[0]]; }).map(function (t) {
      var on = t[0] === BTAB;
      return '<button type="button" role="tab" id="cq-tab-' + t[0] + '" aria-controls="cq-panel" aria-selected="' + on + '" tabindex="' + (on ? 0 : -1) + '" data-cq-tab="' + t[0] + '"' + (on ? ' class="on"' : '') + '>'
        + esc(t[1]) + '<span class="n">' + BOARD.lists[t[0]].length + '</span></button>';
    }).join('') + '</div>';
    h += '<div id="cq-panel" role="tabpanel" aria-labelledby="cq-tab-' + BTAB + '">';
    var scope = BTAB === 'waiting' ? '' : BTAB === 'team' ? 'Everyone under you in the reporting line. ' : 'Every request (Claude seat owners). ';
    if (BTAB !== 'waiting') h += '<p class="note" style="margin:0 0 10px">' + scope + 'Last ' + esc(b.historyDays) + ' days, plus anything still open.'
      + (BTAB === 'team' ? ' View only, unless it is waiting on you.' : '') + '</p>';
    if (!r) {
      h += '<div class="empty">' + (BTAB === 'waiting' ? 'Nothing is waiting on you.' : BTAB === 'team' ? 'No requests from your team in that time.' : 'No requests in that time.') + '</div></div>';
      bd.innerHTML = h; bindBoard(bd); return;
    }
    h += '<div id="cq-stage"><div id="cq-deck" tabindex="0" role="group" aria-roledescription="card" aria-label="Request ' + (i + 1) + ' of ' + list.length + '"'
      + (list.length === 1 ? ' class="one"' : '') + '>' + boardFace(r) + '</div></div>';
    if (list.length > 1) {
      h += '<div class="cq-nav"><button type="button" class="btn sm ghost" data-cq-go="-1" aria-label="Previous request"><span class="ic" data-icon="left"></span></button>'
        + '<span class="pos" aria-live="polite">' + (i + 1) + ' of ' + list.length + '</span>'
        + '<button type="button" class="btn sm ghost" data-cq-go="1" aria-label="Next request"><span class="ic" data-icon="chevron-right"></span></button>'
        + '<select class="sel" data-cq-jump aria-label="Go to a request">' + list.map(function (x, k) {
          return '<option value="' + k + '"' + (k === i ? ' selected' : '') + '>' + esc((x.requester.name || x.requester.email) + ' · ' + usd(x.requested) + ' · ' + ((LSTATUS[x.status] || ['', x.status])[1])) + '</option>';
        }).join('') + '</select></div>';
    }
    h += '</div>';
    // The card is redrawn on every flip; focus goes back to the control that had it, so the keys keep working.
    var ae = document.activeElement, keep = ae && bd.contains(ae) ? (ae.id ? '#' + ae.id : ae.hasAttribute('data-cq-go') ? '[data-cq-go="' + ae.getAttribute('data-cq-go') + '"]' : ae.hasAttribute('data-cq-jump') ? '[data-cq-jump]' : null) : null;
    bd.innerHTML = h; hydrate(bd); bindBoard(bd);
    if (keep && $(keep, bd)) try { $(keep, bd).focus({ preventScroll: true }); } catch (e) {}
    if (dir && !reducedMotion() && $('#cq-deck').animate) {
      $('#cq-deck').animate([{ transform: 'rotateX(' + (dir > 0 ? -55 : 55) + 'deg)', opacity: 0 }, { transform: 'rotateX(0)', opacity: 1 }], { duration: 220, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' });
    }
  }
  function boardFace(r) {
    var q = BOARD.q, ro = !!q.viewingAs, off = !q.enabled, who = r.requester.name || r.requester.email;
    var d = function (iso) { return iso ? esc(rel(iso)) : '—'; };
    var h = '<div class="cq-top"><div class="who"><b>' + esc(who) + '</b>' + (r.mine ? ' <span class="note">(you)</span>' : '') + '<div class="note">' + esc(r.requester.email) + '</div></div>'
      + '<div>' + (r.canDecide && !r.seatOwnerStep ? '<span class="chip amber">Waiting for you</span>' : lchip(r)) + '</div></div>';
    h += '<div class="cq-amt"><div><div class="v">' + esc(usd(r.current)) + '</div><div class="l">Limit when asked</div></div>'
      + '<div><div class="v">' + esc(usd(r.requested)) + '</div><div class="l">Asking for (monthly)</div></div>'
      + '<div><div class="v" style="font-size:15px;padding-top:4px">' + esc(lbandText(r)) + '</div><div class="l">Approval</div></div></div>';
    h += '<dl class="cq-route"><dt>Asked</dt><dd>' + d(r.createdAt) + '</dd>';
    if (r.manager) h += '<dt>Manager</dt><dd>' + esc(r.manager.name || r.manager.email) + (r.managerDecidedAt ? ' <span class="note">approved ' + d(r.managerDecidedAt) + '</span>' : '') + '</dd>';
    if (r.leader) h += '<dt>Functional leader</dt><dd>' + esc(r.leader.name || r.leader.email) + (r.leaderDecidedAt ? ' <span class="note">approved ' + d(r.leaderDecidedAt) + '</span>' : '') + '</dd>';
    if (r.ownerApproval) h += '<dt>Claude seat owner</dt><dd>' + esc(r.ownerApproval.by) + (r.ownerApproval.at ? ' <span class="note">approved ' + d(r.ownerApproval.at) + '</span>' : '') + '</dd>';
    if (r.appliedAt) h += '<dt>Applied</dt><dd>' + d(r.appliedAt) + '</dd>';
    if (r.deniedAt) h += '<dt>Not approved</dt><dd>' + d(r.deniedAt) + (r.deniedBy ? ' by ' + esc(r.deniedBy) : '') + '</dd>';
    if ((r.tickets || []).length) h += '<dt>Tickets</dt><dd>' + ltickets(r) + '</dd>';
    h += '</dl>';
    if (r.denyReason) h += '<div class="note">Reason: ' + esc(r.denyReason) + '</div>';
    if (r.status === 'apply_failed' && r.failReason) h += '<div class="note" style="color:var(--red-tx)">' + esc(r.failReason) + '</div>';
    if (r.status === 'escalated' && r.failReason) h += '<div class="note">Why it went to the Service Desk: ' + esc(r.failReason) + '</div>';
    if (r.interrupted) h += '<div class="note">' + INTERRUPTED + '</div>';
    var act = '';
    if (r.canDecide && r.seatOwnerStep) {
      // Stage S: a seat owner approves (and, for an escalated one, denies) with no other approval.
      act = '<button type="button" class="btn sm" data-cq-ok="' + r.id + '">Approve</button>'
        + (r.status === 'escalated' ? '<button type="button" class="btn sm ghost" data-cq-no="' + r.id + '">Deny</button>' : '')
        + '<span class="note">' + (r.mine ? 'Your own request: as a Claude seat owner you can approve it; no other approval is needed.'
          : 'Claude seat owner: approving sets the limit in Anthropic now and closes the Service Desk ticket.') + '</span>';
    } else if (r.canDecide) {
      var step = r.status === 'pending_leader' ? 'Final approval (functional leader)' : r.forwards ? 'Manager, then ' + ((r.leader && (r.leader.name || r.leader.email)) || 'the Service Desk') : 'Manager approval';
      act = '<button type="button" class="btn sm" data-cq-ok="' + r.id + '">' + (r.forwards ? 'Approve and forward' : 'Approve') + '</button>'
        + '<button type="button" class="btn sm ghost" data-cq-no="' + r.id + '">Deny</button><span class="note">Your step: ' + esc(step) + '</span>';
    } else if (r.canRetry) {
      act = '<button type="button" class="btn sm" data-cq-retry="' + r.id + '">Try again</button>'
        + (r.status === 'apply_failed' && !r.mine && BOARD.b.seatOwner ? '<span class="note">Writes the approved limit to Anthropic; the ticket and emails name who approved it.</span>' : '');
    } else if (r.status === 'escalated') {
      act = '<span class="note">With the Service Desk: nothing changes in Anthropic until a Claude seat owner approves it or someone acts on the ticket.</span>';
    } else if (BOPEN[r.status]) {
      act = '<span class="note">' + (ro ? 'Read-only view.' : off ? 'Approvals are switched off.' : r.waitingFor ? 'View only. Waiting on ' + esc(r.waitingFor) + '.'
        : r.status === 'apply_failed' ? 'View only. Whoever approved it, or a Claude seat owner, can try again.' : 'View only.') + '</span>';
    }
    if (act) h += '<div class="cq-act" data-cq-act="' + r.id + '">' + act + '<div class="note" data-cq-msg style="flex-basis:100%"></div></div>';
    return h;
  }
  function boardGo(step, to) {
    if (!BOARD || limitBusy) return;
    var list = BOARD.lists[BTAB] || []; if (list.length < 2) return;
    var i = boardIdx(), j = to != null ? to : (i + step + list.length) % list.length;
    if (j === i) return;
    BPOS[BTAB] = { id: list[j].id, i: j };
    renderBoard(to != null ? (j > i ? 1 : -1) : step);
  }
  function boardPost(btn, path, body, ok) {
    if (limitBusy) return;
    var id = Number(btn.closest('[data-cq-act]').getAttribute('data-cq-act'));
    limitBusy = true; btn.disabled = true; var was = btn.textContent; btn.textContent = 'Working…';
    api('POST', path, body).then(function (r) { limitBusy = false; toast(ok(r)); paintLimitCards(); })
      .catch(function (e) {
        var why = e.message || 'That did not work.';
        limitBusy = false; btn.disabled = false; btn.textContent = was; toast(why, true);
        paintLimitCards().then(function () {
          var a = $('#cq-bd [data-cq-act="' + id + '"]'), m = a && a.querySelector('[data-cq-msg]');
          if (m) { m.textContent = why; m.style.color = 'var(--red-tx)'; }
        });
      });
  }
  function boardRow(id) { var list = BOARD.lists[BTAB] || []; for (var k = 0; k < list.length; k++) if (list[k].id === id) return list[k]; return null; }
  function bindBoard(bd) {
    $$('[data-cq-tab]', bd).forEach(function (t) {
      t.addEventListener('click', function () { if (BTAB !== t.getAttribute('data-cq-tab')) { BTAB = t.getAttribute('data-cq-tab'); renderBoard(0); try { $('#cq-tab-' + BTAB).focus(); } catch (e) {} } });
      t.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
        var tabs = $$('[data-cq-tab]', bd), k = tabs.indexOf(t) + (e.key === 'ArrowLeft' ? -1 : 1);
        e.preventDefault(); tabs[(k + tabs.length) % tabs.length].click();
      });
    });
    $$('[data-cq-go]', bd).forEach(function (b) { b.addEventListener('click', function () { boardGo(Number(b.getAttribute('data-cq-go'))); }); });
    var jump = $('[data-cq-jump]', bd); if (jump) jump.addEventListener('change', function () { boardGo(0, Number(jump.value)); });
    $$('[data-cq-ok]', bd).forEach(function (b) {
      b.addEventListener('click', function () {
        var r = boardRow(Number(b.getAttribute('data-cq-ok'))); if (!r) return;
        var to = (r.leader && (r.leader.name || r.leader.email)) || 'the Service Desk (no functional leader on record)';
        // Same words as the approvals card: the last step changes the limit in Anthropic.
        if (!confirm(r.seatOwnerStep ? (r.mine ? 'Approve your own request for ' + usd(r.requested) + '/mo as a Claude seat owner? Your Claude limit is changed in Anthropic straight away.'
            : 'Approve ' + usd(r.requested) + '/mo for ' + (r.requester.name || r.requester.email) + ' as a Claude seat owner? Their Claude limit is changed in Anthropic straight away.')
          : r.forwards ? 'Approve ' + usd(r.requested) + '/mo and send it to ' + to + ' for the final approval?'
          : 'Approve ' + usd(r.requested) + '/mo? Their Claude limit is changed in Anthropic straight away.')) return;
        boardPost(b, '/claude-limit/requests/' + r.id + '/approve', {}, function (x) {
          return x.forwarded ? 'Approved and forwarded' : x.escalated ? 'Approved; sent to the Service Desk (no functional leader)' : 'Approved: limit is now ' + usd(x.request.requested);
        });
      });
    });
    $$('[data-cq-no]', bd).forEach(function (b) {
      b.addEventListener('click', function () {
        var a = b.closest('[data-cq-act]'), id = a.getAttribute('data-cq-act');
        a.innerHTML = '<input class="inp" data-cq-reason placeholder="Reason (the person sees this)" style="flex:1 1 220px;min-width:0" maxlength="500">'
          + '<button type="button" class="btn sm danger" data-cq-deny>Deny</button><button type="button" class="btn sm ghost" data-cq-back>Back</button><div class="note" data-cq-msg style="flex-basis:100%"></div>';
        var inp = a.querySelector('[data-cq-reason]'); try { inp.focus(); } catch (e) {}
        a.querySelector('[data-cq-back]').addEventListener('click', function () { renderBoard(0); });
        a.querySelector('[data-cq-deny]').addEventListener('click', function () {
          var reason = inp.value.trim(), m = a.querySelector('[data-cq-msg]');
          if (reason.length < 3) { m.textContent = 'Give the person a reason.'; m.style.color = 'var(--red-tx)'; return; }
          boardPost(this, '/claude-limit/requests/' + id + '/deny', { reason: reason }, function () { return 'Denied; they have been emailed'; });
        });
      });
    });
    $$('[data-cq-retry]', bd).forEach(function (b) {
      b.addEventListener('click', function () { boardPost(b, '/claude-limit/requests/' + b.getAttribute('data-cq-retry') + '/retry', {}, retryToast); });
    });
  }

  /* Reporting periods are the months the collector actually holds, plus the current
   * one. Offering a month that was never collected invites a screenful of zeroes
   * that mean "no data", which is the one thing this section must not say with a 0. */
  function fillMonths() {
    var sel = $('#claude-month'), cur = claudeMonth || AI.period.month;
    sel.innerHTML = '';
    (AI.periods || []).forEach(function (p) { sel.appendChild(new Option(p.label + (p.isCurrent ? ' (to date)' : ''), p.month)); });
    if (!(AI.periods || []).some(function (p) { return p.month === cur; })) sel.appendChild(new Option(AI.period.label, cur));
    sel.value = cur;
    $('#ai-period-label').textContent = 'Reporting period';
    if (sel.getAttribute('data-bound')) return;
    sel.setAttribute('data-bound', '1');
    sel.addEventListener('change', function () {
      // The period is the one piece of state every pane shares, so changing it
      // reloads all three and leaves the tab, the drill-down and the filters alone.
      claudeMonth = sel.value; AI = null; TEAM = null; CLAUDE = null; orgPath = [];
      loadAi(true).then(function () { paintAiAccess(); renderAi(); }).catch(function (e) { $('#ai-access').innerHTML = errBox(e); });
    });
    $$('#ai-tabs button').forEach(function (b) {
      b.addEventListener('click', function () { location.hash = '#claude/' + b.getAttribute('data-tab'); });
    });
    $('#claude-view').addEventListener('click', function () { var v = $('#claude-email').value.trim().toLowerCase(); if (v) location.hash = '#claude/u/' + encodeURIComponent(v); });
    $('#claude-self').addEventListener('click', function () { $('#claude-email').value = ''; location.hash = '#claude/me'; });
    bindTeamControls();
  }

  /* ── entitlement tiles ── */
  var CLAUDE_REASON = {
    'roster-never-synced': 'The Claude member roster has never synced, so access cannot be confirmed either way.',
    'roster-stale': 'The Claude member roster has not synced recently enough to rule a seat out.',
  };
  var COPILOT_REASON = {
    'not-in-licence-report': 'You do not appear in the Microsoft licence assignment report, so a Copilot licence cannot be confirmed either way.',
    'licence-report-stale': 'The Microsoft licence assignment report is too old to rule a licence out.',
  };
  function stateChip(state) {
    if (state === 'active' || state === 'licensed') return '<span class="chip green">' + (state === 'active' ? 'Active' : 'Licensed') + '</span>';
    if (state === 'none') return '<span class="chip">No access</span>';
    return '<span class="chip amber">Can’t confirm</span>';
  }
  function requestLink(text) {
    var r = AI.requestAccess;
    // Nobody can request a seat on somebody else's behalf from here, so the borrowed
    // view says what to do instead of offering a button that would file it for you.
    if (r && r.reason === 'not-self') return '<div class="ln">They have to request this themselves, or the Service Desk can raise it for them.</div>';
    if (!r || !r.available) return '<div class="ln">No self-service request process is published on the Hub, so ask the Service Desk.</div>';
    return '<a class="req" href="' + esc(safeHref(r.url)) + '" target="_blank" rel="noopener noreferrer">' + ic('external') + (text || 'Request access') + '</a>' +
      '<div class="ln">' + esc(r.note || '') + '</div>';
  }
  function paintAiAccess() {
    var c = AI.claude, p = AI.copilot;
    var self = !(AI.subject && AI.subject.isSelf === false);
    // Already escaped: it is interpolated into markup below alongside raw HTML.
    var nm = self ? 'You' : esc((ME && ME.email === AI.subject.email && ME.displayName) || AI.subject.email);
    var hasV = self ? 'have' : 'has', doesnt = self ? 'don\u2019t' : 'doesn\u2019t', them = self ? 'you' : 'them';
    var cl = [];
    if (c.access === 'active') {
      cl.push(nm + ' ' + hasV + ' a Claude seat' + (c.role && c.role !== 'user' ? ' (<b>' + esc(c.role.replace(/_/g, ' ')) + '</b>)' : '') + (c.addedAt ? ', added <b>' + esc(fmtD(c.addedAt)) + '</b>' : '') + '.');
      if (c.limit) cl.push('Monthly limit <b>' + money(c.limit.amount) + '</b> · ' + esc(c.limit.basis === 'individual' ? 'set for ' + them : 'plan default') + ' · <b>' + money(c.limit.periodToDateSpend) + '</b> used period to date.');
    } else if (c.access === 'none') {
      cl.push('<b>' + nm + ' ' + doesnt + ' currently have Claude access.</b>');
      cl.push('Checked against the Claude member roster as of ' + esc(c.asOf ? rel(c.asOf) : 'an unknown time') + '.');
    } else {
      cl.push(esc(CLAUDE_REASON[c.reason] || 'Claude access could not be determined.'));
      cl.push('Last successful roster sync: ' + esc(c.asOf ? rel(c.asOf) : 'never') + '.');
    }
    // The period's usage sits with the access state, so "no access", "no usage in
    // this period" and "we could not measure this period" are told apart in one place.
    var u = AI.usage;
    if (u) {
      if (u.state === 'active') {
        cl.push('Used <b>' + money(u.spend) + '</b> in ' + esc(AI.period.label) + ' · ' + num(u.requests) + ' request' + (u.requests === 1 ? '' : 's') +
          (u.lastActivity ? ' · last active <b>' + esc(fmtD(u.lastActivity)) + '</b>' : '') + '.');
      } else if (u.state === 'no-usage') {
        cl.push('<b>No Claude usage during ' + esc(AI.period.label) + '.</b>');
      } else if (u.state === 'unavailable') {
        cl.push('<b>Usage for ' + esc(AI.period.label) + ' is not available.</b> ' + esc(AI.period.note || ''));
      } else if (u.state === 'no-access' && u.touched) {
        cl.push('Usage was recorded in ' + esc(AI.period.label) + ' even though ' + (self ? 'you are' : 'they are') + ' not on the roster.');
      }
    }
    var pl = [];
    if (p.access === 'licensed') {
      pl.push('Licensed for <b>' + esc(p.licences.join(', ')) + '</b>.');
      pl.push(p.lastActivity ? 'Last Copilot activity <b>' + esc(fmtD(p.lastActivity)) + '</b>' + (p.apps && p.apps.length ? ' · ' + esc(p.apps.slice(0, 4).map(function (a) { return a.app; }).join(', ')) : '') + '.'
        : (p.activityKnown ? 'No Copilot activity recorded in Microsoft’s usage report.' : 'Microsoft’s Copilot usage report has no row for ' + (self ? 'you' : them) + ' yet.'));
    } else if (p.access === 'none') {
      pl.push('<b>No Microsoft 365 Copilot licence is assigned to ' + (self ? 'you' : nm) + '.</b>');
      // Appearing in the usage report without a licence means one was assigned and
      // later removed. Saying so is more use than a bare "no licence".
      if (p.lastActivity) pl.push(nm + ' used Copilot up to <b>' + esc(fmtD(p.lastActivity)) + '</b>, so a licence was assigned at some point and has since been removed.');
      if (p.otherCopilotLicences && p.otherCopilotLicences.length) pl.push(nm + ' ' + (self ? 'do' : 'does') + ' hold <b>' + esc(p.otherCopilotLicences.join(', ')) + '</b>, which is not the Microsoft 365 Copilot licence.');
      pl.push('From the licence assignment report dated ' + esc(p.reportDate ? fmtD(p.reportDate) : 'unknown') + '.');
    } else {
      pl.push(esc(COPILOT_REASON[p.reason] || 'Copilot licensing could not be determined.'));
    }
    var needClaude = c.access === 'none', needCop = p.access === 'none';
    $('#ai-access').innerHTML =
      '<div class="aigrid">' +
        '<div class="aitile' + (c.access === 'active' ? '' : ' off') + '"><div class="hd">' + ic('sparkle') + '<b>Claude</b>' + stateChip(c.access) + '</div>' +
          cl.map(function (x) { return '<div class="ln">' + x + '</div>'; }).join('') + (needClaude ? requestLink('Request Claude access') : '') + '</div>' +
        '<div class="aitile' + (p.access === 'licensed' ? '' : ' off') + '"><div class="hd">' + ic('grid') + '<b>Microsoft Copilot</b>' + stateChip(p.access) + '</div>' +
          pl.map(function (x) { return '<div class="ln">' + x + '</div>'; }).join('') + (needCop && !needClaude ? requestLink('Request a Copilot licence') : '') + '</div>' +
      '</div>' +
      (AI.conflict ? '<div class="callout" style="margin-top:12px">' + ic('alert') + '<div>' + esc(AI.conflict) + '</div></div>' : '') +
      '<p class="note" style="margin-top:12px">Reporting period <b>' + esc(AI.period.label) + '</b>' + (AI.period.isCurrent ? ' (day ' + AI.period.daysElapsed + ' of ' + AI.period.daysInMonth + ')' : '') +
        (AI.period.note ? ' · ' + esc(AI.period.note) : '') +
        ' · licensing is read from the Claude member roster and the Microsoft licence report, never inferred from usage.' +
        (AI.team && AI.team.note ? ' ' + esc(AI.team.note) : '') + '</p>';
    hydrate($('#ai-access'));
  }

  function agoTxt(min) {
    var m = Number(min);
    if (!isFinite(m) || m < 0) return 'age unknown';
    if (m < 2) return 'refreshed just now';
    if (m < 90) return 'refreshed ' + Math.round(m) + ' min ago';
    var h = m / 60;
    return h < 36 ? 'refreshed ' + Math.round(h) + ' h ago' : 'refreshed ' + Math.round(h / 24) + ' days ago';
  }

  /* ── team usage ── */
  /* One control now, where there were eight. The six-way state seg, the
   * department <select> and the per-card search were three ways of narrowing
   * the same list on three different cards; department became a rung of the
   * roll-up and the state counts are stated by the KPI tiles, so the only
   * question left is "where is this person", which no rung can answer. */
  function bindTeamControls() {
    var q = $('#ai-org-q');
    if (q) q.addEventListener('input', function () { orgQ = this.value.trim().toLowerCase(); paintOrg(); });
    bindOrgCard();
  }
  /* Every tile covers everyone under the viewer. Nothing on this tab filters
   * the list any more, so an org-wide numerator can no longer end up over a
   * department denominator — but the figures are still derived from the rows
   * passed in rather than from a summary, so the two cannot disagree. */
  function teamStats(rows, known) {
    var t = { people: rows.length, claudeActive: 0, claudeNone: 0, claudeUnknown: 0, copilotLicensed: 0, copilotUnknown: 0,
              active: 0, idle: 0, noAccess: 0, unavailable: 0, spend: 0, prev: 0, sessions: 0, chats: 0, cowork: 0, requests: 0 };
    rows.forEach(function (m) {
      if (m.claudeAccess === 'active') t.claudeActive++; else if (m.claudeAccess === 'none') t.claudeNone++; else t.claudeUnknown++;
      if (m.copilotAccess === 'licensed') t.copilotLicensed++; else if (m.copilotAccess !== 'none') t.copilotUnknown++;
      if (m.usageState === 'active') t.active++; else if (m.usageState === 'no-usage') t.idle++;
      else if (m.usageState === 'no-access') t.noAccess++; else t.unavailable++;
      t.spend += spendOf(m); t.prev += Number(m.prevSpendRaw) || 0;
      t.sessions += Number(m.sessions) || 0; t.chats += Number(m.chats) || 0;
      t.cowork += Number(m.coworkSessions) || 0; t.requests += Number(m.requests) || 0;
    });
    t.known = known; t.momPct = known && t.prev > 0 ? (t.spend / t.prev - 1) * 100 : null;
    return t;
  }
  function paintTeam() {
    var known = TEAM.period.zeroIsMeasured, sc = TEAM.scope;
    // The scope IS the reporting line, so it is spelled out: who you are in AD, how
    // many people sit under you, and how old that hierarchy is. A stale tree would
    // quietly shrink somebody's team, so its age is on screen rather than implied.
    $('#ai-team-scope').textContent = (sc.viewingAs ? 'Viewing as ' + sc.viewingAs.email + ' · ' : '')
      + sc.label
      + (sc.department ? ' · ' + sc.department : '')
      + ' · ' + num(sc.directReports) + ' direct'
      + (sc.totalReports > sc.directReports ? ', ' + num(sc.totalReports) + ' in total' : '')
      + (sc.hierarchy && sc.hierarchy.refreshedAt ? ' · from Active Directory, ' + agoTxt(sc.hierarchy.ageMinutes) : '');
    $('#ai-team-period').textContent = TEAM.period.label + (TEAM.period.isCurrent ? ' · day ' + TEAM.period.daysElapsed + ' of ' + TEAM.period.daysInMonth : '');

    if (!TEAM.members.length) {
      $('#ai-team-kpis').innerHTML = '<div class="empty"><b>No one to report on</b>' + esc(TEAM.note || 'Nobody is in your reporting scope.') + '</div>';
      /* Both of these own their own .hidden, and until this rewrite the return
         fired BEFORE either painter ran — so switching to a month with nobody
         in it left the previous month's alert list and roll-up on screen,
         looking current. They are painted, and hidden, before the return. */
      paintLimitAlerts();
      paintOrg();
      return;
    }
    paintTeamKpis();
    paintLimitAlerts();
    paintOrg();
  }
  /* A manager usually finds out a report ran out of Claude budget after it has
   * already happened. This card is the earlier signal, and it carries the one
   * action that resolves it, so the alert is not just news.
   *
   * Only DIRECT reports appear: anybody further down has a manager of their own,
   * and that manager is the one who should be having the conversation.
   * Both numbers come from Anthropic's own spend-limit feed, never from the cost
   * table the rest of this page totals -- a percentage mixing the two bases is one
   * neither source would stand behind. */
  function paintLimitAlerts() {
    var card = $('#ai-limit-alert-card');
    if (!card) return;
    var al = (TEAM && TEAM.spendAlerts) || [];
    var control = thresholdControl();
    /* The card stays up for a manager whose team is all inside its limits, because
     * the percentage control lives in it. Hiding the card on an empty list is what
     * would stop somebody LOWERING the number to hear about people sooner — the
     * one person most likely to want it is the one with nothing to see today. */
    card.hidden = !al.length && !control;
    if (card.hidden) return;
    var th = (TEAM && TEAM.alertThreshold) || 70;
    var title = $('#ai-limit-alert-title');
    // A card headed "Approaching their Claude limit" over an empty list says
    // something untrue about the team, so the heading follows the content.
    if (title) title.textContent = al.length ? 'Approaching their Claude limit' : 'Claude spend alerts';
    if (!al.length) {
      $('#ai-limit-alert-note').textContent = 'Nobody on your team is at or past '
        + th + '% of their monthly limit.';
      $('#ai-limit-alert').innerHTML = control;
      hydrate($('#ai-limit-alert'));
      wireThreshold();
      return;
    }
    var tix = {};
    ((TEAM && TEAM.limitTickets) || []).forEach(function (t) { tix[t.email] = t; });
    var over = al.filter(function (a) { return a.state === 'over'; }).length;
    var directs = al.filter(function (a) { return a.direct; }).length;
    var below = al.length - directs;
    /* Name the population exactly. "3 of your direct reports" over a list that is
     * one report and two skip-levels is how a director ends up asking somebody
     * else's report about their spending. */
    var whoTxt = below === 0
      ? num(al.length) + ' of your direct reports ' + (al.length === 1 ? 'is' : 'are')
      : directs === 0
        ? num(al.length) + (al.length === 1 ? ' person in your organisation is' : ' people in your organisation are')
        : num(directs) + ' of your direct reports and ' + num(below)
          + (below === 1 ? ' person further down are' : ' people further down are');
    $('#ai-limit-alert-note').textContent = whoTxt + ' at or past ' + th + '% of their monthly limit'
      + (over ? ' \u00b7 ' + num(over) + ' already over' : '');

    $('#ai-limit-alert').innerHTML = al.map(function (a) {
      var isOver = a.state === 'over';
      var t = tix[a.email];
      var rec = a.recommendation || {};
      var pctTxt = a.pct == null ? 'at the limit' : a.pct + '%';
      /* When the run rate closes inside the cap there is genuinely nothing to ask
       * for, so that case says why instead of offering a button. In a borrowed view
       * the control still renders exactly as the manager sees it (Jeramy, 09-21:
       * "i need to see it") -- only the SEND is disabled, because the API refuses
       * the write (VIEW_AS_READ_ONLY) and a ticket must not be filed under a viewer. */
      var action;
      var preview = !TEAM.canRequest;
      if (t) {
        action = t.url
          ? '<a class="btn sm" href="' + esc(t.url) + '" target="_blank" rel="noopener">Ticket ' + esc(t.ticket || '') + '</a>'
          : '<span class="note">Request already raised</span>';
      } else if (!rec.needed && !isOver) {
        action = '<span class="note">No increase needed yet</span>';
      } else {
        action = '<button class="btn sm" data-limit-req="' + esc(a.email) + '" data-cur="' + esc(String(a.limit || '')) + '" data-rec="' + esc(String(rec.amount || ''))
          + '"' + (preview ? ' data-preview="1" title="Preview \u2014 a borrowed view cannot send the request"' : '') + '>Request an increase</button>';
      }
      return '<div data-lim-row="' + esc(a.email) + '" style="display:flex;gap:14px;align-items:flex-start;padding:12px 0;border-top:1px solid var(--line)">'
        + '<div style="flex:1;min-width:0">'
        + '<div class="who"><span>' + esc(a.name) + '</span><small>' + esc(a.title || a.email)
        + (a.direct ? '' : ' \u00b7 reports to ' + esc(a.reportsTo || 'someone below you'))
        + '</small></div>'
        + '<div style="margin-top:6px;font-size:13px">'
        + '<b style="color:' + (isOver ? 'var(--red-tx)' : 'var(--amber-tx)') + '">' + money(a.ptdSpend) + ' of ' + money(a.limit) + ' \u00b7 ' + pctTxt + '</b>'
        + (isOver ? ' <span style="color:var(--red-tx)">\u2014 already over</span>' : '')
        + '</div>'
        + (rec.note ? '<div class="note" style="margin-top:4px">' + esc(rec.note) + '</div>' : '')
        + '<div class="note" style="margin-top:4px">Day ' + num(a.daysElapsed) + ' of ' + num(a.daysInMonth)
        + (a.basis ? ' \u00b7 ' + esc(a.basis === 'individual' ? 'individual limit' : a.basis) : '') + (a.asOf ? ' \u00b7 figures from ' + esc(String(a.asOf).replace('T', ' ').slice(0, 16)) + ' UTC' : '') + '</div>'
        + '<div data-lim-msg="' + esc(a.email) + '" class="note" style="margin-top:6px"></div>'
        + '</div>'
        + '<div style="flex:none;text-align:right">'
        + (rec.needed ? '<div style="font-size:13px"><b>' + money(rec.amount) + '</b><div class="note">recommended</div></div>' : '')
        + '<div style="margin-top:8px">' + action + '</div>'
        + '</div></div>';
    }).join('')
    + '<p class="note" style="margin-top:10px">Limits and spend come from the Claude Admin API. '
    + 'A request opens a Service Desk ticket in your name with the figures above.</p>'
    + anthropicNote(TEAM && TEAM.feeds, 'claudeLimits', ['claudeCost'])
    + control;

    hydrate($('#ai-limit-alert'));
    $$('#ai-limit-alert [data-limit-req]').forEach(function (b) {
      b.addEventListener('click', function () {
        var row = b.closest('[data-lim-row]');
        openLimitReq(b.getAttribute('data-limit-req'), b.getAttribute('data-cur'), b.getAttribute('data-rec'), b, row ? row.querySelector('[data-lim-msg]') : null, b.hasAttribute('data-preview'));
      });
    });
    wireThreshold();
  }

  /* The manager's own "tell me at" percentage.
   *
   * It is a preference, not an admin setting: it changes who THIS person is told
   * about and nobody else's page, so it lives with them rather than in the console.
   * The console still owns the platform default, which is what the reset goes back
   * to — and the control says which of the two is currently in force, so a default
   * never reads as somebody's decision. */
  function thresholdControl() {
    var cfg = (TEAM && TEAM.alertConfig) || {};
    if (!TEAM || !TEAM.canRequest) return '';
    var cur = cfg.threshold == null ? 70 : cfg.threshold;
    var mine = cfg.thresholdSource === 'manager';
    return '<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap">'
      + '<label class="note" for="ai-th-input">Tell me when someone reaches</label>'
      + '<input id="ai-th-input" type="number" min="1" max="99" step="1" value="' + esc(String(cur))
      + '" style="width:70px;padding:5px 8px;border:1px solid var(--line);border-radius:5px;background:var(--card);color:inherit">'
      + '<span class="note">% of their limit</span>'
      + '<button class="btn sm" id="ai-th-save">Save</button>'
      + (mine ? '<button class="btn sm ghost" id="ai-th-reset">Use the default ('
          + esc(String(cfg.consoleThreshold == null ? 70 : cfg.consoleThreshold)) + '%)</button>' : '')
      + '<span class="note" id="ai-th-msg">' + (mine ? 'Your own setting.'
          : 'The platform default, set in the admin console.') + '</span>'
      + '<span class="note" style="margin-left:auto;white-space:nowrap">Email delivery: the <b>Email alerts</b> switch in the sidebar'
      + (cfg.emailAlert ? ' (on)' : ' (off)') + '</span>'
      + '</div>';
  }

  function wireThreshold() {
    var save = $('#ai-th-save'), reset = $('#ai-th-reset'), input = $('#ai-th-input');
    if (save) save.addEventListener('click', function () { saveThreshold(input ? input.value : null, save); });
    if (reset) reset.addEventListener('click', function () { saveThreshold(null, reset); });
  }

  /* ───────────── sidebar: Email alerts switch ───────────── */
  /* The manager's own on/off for the Claude spend-alert EMAIL, in the sidebar where
   * Settings used to be (Jeramy, 09-21). Default off; on makes the hourly digest
   * mail them when a report crosses their threshold. ONE control for one row in
   * ai_spend_alert_manager -- the Team card no longer carries a second copy that
   * would have to be kept in step. Hidden for anyone with no direct reports, since
   * there is nothing it could ever send them; shown but locked in a borrowed view,
   * where it reports the other manager's choice. */
  function loadAlertEmailNav() {
    var el = $('#nav-alert-email'); if (!el) return Promise.resolve();
    return api('GET', '/ai-team/alert-email').then(function (r) {
      ALERT_EMAIL = r;
      el.hidden = !r.manager;
      if (r.manager) paintAlertEmailNav();
    }).catch(function () { el.hidden = true; });
  }
  function paintAlertEmailNav() {
    var el = $('#nav-alert-email'), sub = $('#nav-alert-email-sub'), r = ALERT_EMAIL; if (!el || !r) return;
    var on = !!r.emailAlert, th = r.threshold == null ? 70 : r.threshold;
    el.setAttribute('aria-checked', String(on));
    el.disabled = !r.canChange;
    el.title = !r.canChange ? 'Preview \u2014 a borrowed view is read-only'
      : on ? 'Turn off the Claude spend-alert email' : 'Email me when a report reaches ' + th + '% of their Claude limit';
    if (sub) sub.textContent = on ? 'On \u00b7 at ' + th + '% of a limit' : 'Off';
  }
  function saveEmailAlert(on, el) {
    var sub = $('#nav-alert-email-sub');
    el.disabled = true;
    if (sub) sub.textContent = 'Saving\u2026';
    api('PUT', '/ai-team/alert-email', { enabled: !!on }).then(function () {
      if (ALERT_EMAIL) ALERT_EMAIL.emailAlert = !!on;
      if (TEAM && TEAM.alertConfig) TEAM.alertConfig.emailAlert = !!on;
      paintAlertEmailNav();
      if (loaded.overview && TEAM) paintLimitAlerts();
      toast(on ? 'Email alerts on' : 'Email alerts off');
    }).catch(function (e) {
      paintAlertEmailNav();
      toast((e && e.message) || 'Could not save that.', true);
    });
  }
  (function () {
    var el = $('#nav-alert-email'); if (!el) return;
    el.addEventListener('click', function () {
      if (!ALERT_EMAIL || !ALERT_EMAIL.canChange) return;
      saveEmailAlert(!ALERT_EMAIL.emailAlert, el);
    });
  })();

  function saveThreshold(value, btn) {
    var msg = $('#ai-th-msg');
    var body = { threshold: value === null ? null : parseInt(value, 10) };
    if (body.threshold !== null && (!isFinite(body.threshold) || body.threshold < 1 || body.threshold > 99)) {
      if (msg) { msg.textContent = 'Pick a whole number between 1 and 99.'; msg.style.color = 'var(--red-tx)'; }
      return;
    }
    btn.disabled = true;
    if (msg) { msg.textContent = 'Saving\u2026'; msg.style.color = ''; }
    api('PUT', '/ai-team/alert-threshold', body).then(function () {
      /* The list itself changes with the threshold, so the whole report is refetched
       * and repainted rather than the number patched in place — a card still showing
       * the old population under a new percentage is worse than a moment's wait. */
      TEAM = null;
      return loadTeam(true).then(paintTeam);
    }).catch(function (e) {
      btn.disabled = false;
      if (msg) { msg.textContent = (e && e.message) || 'Could not save that.'; msg.style.color = 'var(--red-tx)'; }
    });
  }

  /* Swaps the "Request an increase" button for an inline entry: the manager types
   * the ABSOLUTE new monthly total (200 = raise them to \$200/mo, not +\$200). The
   * server validates it against the current cap and quotes it in the ticket. A
   * blank current limit just means the server will tell us if there is nothing to
   * raise. `preview` (a borrowed view) opens the same entry with Send disabled, so
   * a viewer sees what the manager sees without being able to file anything. */
  /* The same spend-limit control the Direct reports table carries, on the page a
   * manager actually reads before deciding. It is drawn from the server's own
   * verdict, so a control that appears here is one the POST will accept. */
  /* Cumulative spend against the monthly cap, for the month being viewed. The
   * projection uses the same run-rate method the limit-increase ticket quotes, so
   * the card and the ticket can never disagree about where the month is heading. */
  /* claude-opus-4-8 -> "Opus 4.8"; the trailing build date on some ids is noise.
   * claude-3-opus is the old family-last order, so it is spelled out as given. */
  function modelName(m) {
    var s = String(m || '').trim();
    if (!s || s === 'no-model') return 'Unattributed';
    s = s.replace(/^claude-/, '').replace(/-\d{8}$/, '');
    var p = s.split('-');
    if (/^\d+$/.test(p[0])) return 'Claude ' + p.map(cap).join(' ');
    return cap(p[0]) + (p.length > 1 ? ' ' + p.slice(1).join('.') : '');
    function cap(x) { return x.charAt(0).toUpperCase() + x.slice(1); }
  }
  function modelClass(m) {
    var s = String(m || '').toLowerCase();
    return 'md-' + (s.indexOf('opus') >= 0 ? 'opus' : s.indexOf('sonnet') >= 0 ? 'sonnet'
      : s.indexOf('haiku') >= 0 ? 'haiku' : s.indexOf('fable') >= 0 ? 'fable' : 'other');
  }

  /* Models the person actually used, cost and usage both. Ordered by spend, each row
   * opening onto the products that model was used from. */
  function paintModels(c) {
    var el = $('#claude-models'), card = $('#claude-models-card');
    if (!el || !card) return;
    var M = c.models || [];
    if (!M.length) { card.hidden = true; return; }
    card.hidden = false;
    var maxM = Math.max.apply(null, M.map(function (m) { return m.spend; }).concat([0.01]));
    var totReq = M.reduce(function (a, b) { return a + b.requests; }, 0);
    var totTok = M.reduce(function (a, b) { return a + b.tokens; }, 0);
    var totSpend = M.reduce(function (a, b) { return a + b.spend; }, 0);

    var body = M.map(function (m, i) {
      var mid = 'mmx-' + modelClass(m.model) + '-' + i;
      var names = m.products.map(function (p) { return prodName(p.product); }).join(' \u00b7 ');
      var rows = m.products.map(function (p) {
        return '<div class="mm-r"><span class="mm-p"><i class="pdot ' + prodClass(p.product) + '"></i>' + esc(prodName(p.product)) + '</span>' +
          '<b>' + money(p.spend) + '</b><span>' + num(p.requests) + ' req</span><span>' + compact(p.tokens) + ' tok</span></div>';
      }).join('');
      return '<div class="pmix-row">' +
        '<button class="pmix-top" type="button" aria-expanded="false" aria-controls="' + mid + '">' +
          '<span class="pmix-name"><i class="pdot ' + modelClass(m.model) + '"></i>' + esc(modelName(m.model)) +
            '<span class="pmix-chev">' + ic('chevron-right') + '</span></span>' +
          '<span class="pmix-v">' + money(m.spend) + '</span>' +
          '<span class="pmix-p">' + share(m.spend, totSpend) + '</span>' +
          '<span class="pmix-r">' + num(m.requests) + ' req</span></button>' +
        '<div class="pmix-track"><span data-w="' + (m.spend / maxM * 100).toFixed(1) + '" style="transition-delay:' + Math.min(i * 40, 200) + 'ms"></span></div>' +
        '<div class="pmix-sub">' + esc(names) + ' \u00b7 ' + compact(m.tokens) + ' tokens</div>' +
        '<div class="pmix-more" id="' + mid + '"><div class="pmix-more-in"><div class="mm-tbl">' + rows + '</div></div></div>' +
        '</div>';
    }).join('');

    var subj = c.subject.isSelf ? 'You' : (c.subject.displayName || c.subject.email);
    el.innerHTML = '<div class="pmix-hd"><span>' + esc(subj) + ' \u00b7 ' + esc(AI.period.label) + '</span>' +
      '<span class="pmix-tot"><b>' + num(M.length) + '</b> model' + (M.length === 1 ? '' : 's') + ' \u00b7 ' +
      num(totReq) + ' requests \u00b7 ' + compact(totTok) + ' tokens</span></div>' + body;
    requestAnimationFrame(function () {
      $$('#claude-models .pmix-track > span').forEach(function (s) { s.style.width = s.getAttribute('data-w') + '%'; });
    });
    $$('#claude-models .pmix-top[aria-controls]').forEach(function (b) {
      b.addEventListener('click', function () {
        var open = b.getAttribute('aria-expanded') === 'true';
        b.setAttribute('aria-expanded', open ? 'false' : 'true');
        var panel = document.getElementById(b.getAttribute('aria-controls'));
        if (panel) panel.toggleAttribute('data-open', !open);
      });
    });
  }

  function paintCap(c) {
    var el = $('#claude-cap'), card = $('#claude-cap-card');
    if (!el || !card) return;
    var LT = c.limitTrend;
    if (!LT || (LT.cap == null && !LT.days.length)) { card.hidden = true; return; }
    card.hidden = false;
    var dim = LT.daysInMonth, upto = LT.isCurrent ? Math.min(LT.daysElapsed, dim) : dim;
    var spendBy = {}, capBy = {};
    LT.days.forEach(function (r) { spendBy[Number(r.day.slice(8, 10))] = r.spend; });
    LT.caps.forEach(function (r) { capBy[Number(r.day.slice(8, 10))] = r.cap; });
    var cum = [], run = 0, lastCap = LT.cap;
    for (var i = 1; i <= dim; i++) {
      run += spendBy[i] || 0;
      if (capBy[i] != null) lastCap = capBy[i];
      cum.push({ d: i, v: Math.round(run * 100) / 100, cap: lastCap });
    }
    var ptd = cum[upto - 1] ? cum[upto - 1].v : 0;
    var cap = LT.cap;
    var projected = LT.isCurrent ? Math.round((ptd / Math.max(upto, 1)) * dim * 100) / 100 : ptd;
    var rate = Math.round((ptd / Math.max(upto, 1)) * 100) / 100;
    // cap === 0 is a real $0 limit, not "unlimited"; only cap == null is unlimited.
    // Any spend against a $0 limit is over it, so it reads as Infinity% here.
    var pctOf = function (v) { return cap == null ? null : (cap > 0 ? v / cap * 100 : (v > 0 ? Infinity : 0)); };
    var pctCap = pctOf(ptd), projPct = pctOf(projected);

    var W = el.clientWidth || 640, H = el.clientHeight || 190, padL = 42, padR = 8, padB = 20, padT = 8;
    var top = niceMax(Math.max(cap || 0, projected, ptd, 0.01));
    var x = function (d) { return padL + (d - 1) * (W - padL - padR) / Math.max(dim - 1, 1); };
    var y = function (v) { return padT + (H - padT - padB) * (1 - v / top); };
    var pts = cum.slice(0, upto).map(function (r) { return [x(r.d), y(r.v)]; });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
    var area = pts.length ? line + ' L' + pts[pts.length - 1][0].toFixed(1) + ' ' + (H - padB) + ' L' + pts[0][0].toFixed(1) + ' ' + (H - padB) + ' Z' : '';
    var grid = '';
    [0, .25, .5, .75, 1].forEach(function (f) {
      var yy = y(top * f);
      grid += '<line x1="' + padL + '" x2="' + (W - padR) + '" y1="' + yy + '" y2="' + yy + '" style="stroke:var(--line)"/>' +
        '<text x="' + (padL - 6) + '" y="' + (yy + 3.5) + '" text-anchor="end" font-size="10" style="fill:var(--dim)">$' + fmtTick(top * f) + '</text>';
    });
    var labels = '';
    [1, Math.round(dim / 4), Math.round(dim / 2), Math.round(dim * 3 / 4), dim].forEach(function (d, i, arr) {
      labels += '<text x="' + x(d) + '" y="' + (H - 5) + '" text-anchor="' + (d === 1 ? 'start' : d === dim ? 'end' : 'middle') + '" font-size="10" style="fill:var(--dim)">' + d + '</text>';
    });
    // The cap is drawn as a step, because it can move mid-month.
    var capPath = '';
    if (cap != null) {
      capPath = cum.map(function (r, i) { return (i ? 'L' : 'M') + x(r.d).toFixed(1) + ' ' + y(r.cap).toFixed(1); }).join(' ');
    }
    var over = cap != null && projected > cap;
    var proj = (LT.isCurrent && upto < dim && pts.length)
      ? '<path d="M' + pts[pts.length - 1][0].toFixed(1) + ' ' + pts[pts.length - 1][1].toFixed(1) + ' L' + x(dim).toFixed(1) + ' ' + y(Math.min(projected, top)).toFixed(1) + '" fill="none" stroke-dasharray="4 4" stroke-width="2" style="stroke:' + (over ? 'var(--red)' : 'var(--accent)') + '" opacity=".8"/>' : '';
    var id = 'cap' + Math.random().toString(36).slice(2, 8);
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="Cumulative spend against the monthly limit">' +
      '<defs><linearGradient id="' + id + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" style="stop-color:var(--accent)" stop-opacity=".22"/><stop offset="1" style="stop-color:var(--accent)" stop-opacity="0"/></linearGradient></defs>' + grid +
      (area ? '<path d="' + area + '" fill="url(#' + id + ')"/>' : '') +
      (capPath ? '<path d="' + capPath + '" fill="none" stroke-dasharray="6 5" stroke-width="1.6" style="stroke:var(--red)" opacity=".85"/>' : '') +
      proj + (line ? '<path d="' + line + '" fill="none" style="stroke:var(--accent)" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>' : '') +
      labels + '</svg>';

    var M = function (v) { return v == null ? '—' : money(v); };
    var state = cap == null ? { k: 'flat', t: 'no limit to compare against' }
      : !LT.isCurrent ? (pctCap >= 100 ? { k: 'down', t: 'Finished over the limit' }
        : pctCap >= 80 ? { k: 'flat', t: 'Finished close to the limit' } : { k: 'up', t: 'Stayed within the limit' })
        : pctCap >= 100 ? { k: 'down', t: 'Over the limit' }
          : projPct >= 100 ? { k: 'down', t: 'Projected to exceed the limit' }
            : projPct >= 80 ? { k: 'flat', t: 'Projected to land close to the limit' }
              : { k: 'up', t: 'On track' };
    $('#claude-cap-stats').innerHTML = '<div class="kpi-row">' +
      '<div class="kpi hashelp"><div class="v">' + M(ptd) + '</div><div class="l">Spent' + (LT.isCurrent ? ', month to date' : ' this month') + '</div><div class="d flat">' + (cap == null ? 'no limit set' : (cap > 0 ? share(ptd, cap) : (ptd > 0 ? '&gt;100%' : '0%')) + ' of ' + M(cap)) + '</div>' + hx('k-cap-spent') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + M(rate) + '</div><div class="l">Run rate per day</div><div class="d flat">over ' + num(upto) + ' of ' + num(dim) + ' days</div>' + hx('k-cap-rate') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + M(LT.isCurrent ? projected : ptd) + '</div><div class="l">' + (LT.isCurrent ? 'Projected month end' : 'Month closed at') + '</div><div class="d ' + state.k + '">' + esc(state.t) + '</div>' + hx('k-cap-proj') + '</div>' +
      '</div>';
    $('#claude-cap-note').textContent = cap != null
      ? 'The dashed red line is the monthly limit; it steps if the limit changed during the month. Projection uses the same run-rate method the limit-increase ticket quotes.'
      : 'No monthly spend limit is on record for this person, so only actual spend is drawn.';
  }

  /* ── The drilled-in subject ────────────────────────────────────────────────
   *
   * Jeramy: "it needs to be more prominent that he is looking at a user's
   * usage ... use the same methods on the ai reporting site."
   *
   * The reporting site's method, read out of ai-usage-credits.html's
   * openReviewDrawer() (line 1944): a coloured STATUS BADGE, then the person's
   * NAME as the <h2> of the view, then `department · email` beneath it.
   *
   * It gets away with a slim version of this because it opens the employee in a
   * drawer over a scrim -- the page behind it visually recedes. This page drills
   * IN PLACE, so the profile header above keeps showing the VIEWER's face and
   * name. That is precisely why the subject header here has to be louder than
   * the reference's, not quieter: it is competing with a photo of the wrong
   * person. Hence the face, the accent rule down the left edge and the tint. */
  /* ── '?' help affordances ──────────────────────────────────────────────────
   *
   * One dictionary and one delegated listener. The tiles, the drill header and
   * the team roll-up are repainted on every month change and every step-in, so
   * per-element wiring would have to be re-run from six painters and would
   * silently miss the seventh the day somebody adds it.
   *
   * Every sentence below was traced to the code that produces the figure, not
   * to the field's name. Where the provenance is genuinely two feeds on two
   * schedules, or a total that cannot be added from the rows beneath it, the
   * text says so -- a helper that explains a number more confidently than the
   * number deserves is worse than no helper.
   *
   * Deliberately NOT said anywhere here: that these amounts are Anthropic list
   * prices. The card's own footnote claims it, but the collector stores the
   * cost report's `amount` (post-discount) and that table has no list column,
   * so the claim is unsupported. Rather than repeat it or contradict it on the
   * same card, the copy describes what the figure demonstrably is.
   */
  var HELP = {
    /* Wording mirrors the reporting site's term definitions (TERM_DESC in
     * ai-usage-credits.html) and Anthropic's Enterprise Analytics API docs
     * (platform.claude.com/docs/en/manage-claude/analytics-api), 2026-09-24.
     * Say what the number IS first; add one caveat only where it stops a misread. */
    /* sections */
    'sec-mytools': 'Whether you hold a Claude seat and a Microsoft 365 Copilot licence. "Can’t confirm" means we could not check right now — it never means no.',
    'sec-usage': 'Your Claude usage for the month in the picker, as reported by Anthropic. Amounts are usage charges after discount and before credits; seat fees are not included. A month that was never collected shows a notice instead of zeros.',
    'sec-daily': 'Your Claude usage spend per day over the last 90 days (UTC days). Days with no usage are left out rather than drawn as $0. This chart does not follow the month picker.',
    'sec-activity': 'What you did in each Claude product this month, as reported by Anthropic’s analytics. Counted per UTC day and usually one day behind, so today is not in it yet. Hover the ? on any figure for what it counts.',
    'sec-mix': 'This month’s spend split by Claude product; the shares add up to your spend total. "Other" is spend Anthropic reported without a product. Open a product to see its activity figures.',
    'sec-models': 'This month’s spend and tokens by Claude model. Larger models cost more per token, so which model you use moves the cost more than how much you use it. Only usage Anthropic tagged with a model is counted, so the total can be slightly under your month spend.',
    'sec-cap': 'Your spend this month against your monthly Claude spend limit, which is set in Anthropic. At 100% Anthropic stops Claude, Cowork and Claude Code for you until the 1st of next month (UTC) or until the limit is raised. "Request increase" opens a Service Desk ticket for IT to action.',
    'sec-limit': 'Your monthly Claude spend limit in Anthropic, and how to raise it. +$100 once a month is automatic: no approval needed, and it applies straight away. More than +$100, or a second raise that month, goes to your manager. More than +$500 over the limit you started the month with goes to your manager, then your functional leader. Each approval is logged on a Service Desk ticket and emailed from Enterprise Approvals. Raises made here end on the 1st (UTC), back to the limit you started the month with.',
    'sec-approvals': 'Claude limit requests from people who report to you (or, above the manager limit, people you are functional leader for). Approving the last step changes their limit in Anthropic straight away, logs it on a closed Service Desk ticket and emails them and their manager. Denying needs a reason, which they are sent.',
    'sec-queue': 'Claude limit requests, one at a time: flip with the arrows or pick from the list. Waiting on me: requests you can approve or deny now, and approved changes of yours that did not reach Anthropic (Try again). My team: requests from everyone under you in the reporting line; view only unless a request is waiting on you. All (Claude seat owners): every request. A seat owner can try again any approved change that did not reach Anthropic, and can approve or deny requests that went to the Service Desk (listed under Waiting on me) and approve their own; otherwise they cannot approve or deny for a manager or functional leader. My team and All go back the period shown on the tab, and always include open requests.',
    'sec-recent': 'Your last 14 days, one row per UTC day: usage spend, billable requests, Claude Code sessions, accepted Claude Code edits and the products used. This table does not follow the month picker.',
    'sec-team': 'Everyone in your reporting line at every level, from the Manager field in Active Directory. Your own usage is not included. People without a Claude seat are still listed, so the counts cover the whole team.',
    'sec-alert': 'People in your reporting line who have used at least the percentage you set here of their monthly Claude spend limit, read from Anthropic’s spend-limit data. At 100% Anthropic stops their Claude use until the limit is raised or the month resets.',
    'sec-org': 'Your team grouped by manager. A manager’s row includes everyone beneath them, so do not add rows from different levels together. "At least" means some usage below that row could not be included.',
    /* my usage tiles */
    'k-spend': 'Usage-based (metered) Claude spend for the month across every Claude product, from Anthropic’s cost report — after discount, before credits. Seat fees are not included. Anthropic can revise a day for up to 30 days as late usage lands.',
    'k-proj': 'A straight-line projection — this month’s spend so far divided by days elapsed, multiplied by the days in the month. It assumes the current daily pace continues. Once the month is over the tile shows the Final total instead.',
    'k-req': 'Billable requests to Claude’s models this month. One prompt can make many requests — Claude Code and Cowork send several per task — so this is not a count of messages. "Active days" are days with at least one billed request.',
    'k-tok': 'The unit Claude uses to measure and bill usage — pieces of text, roughly 4 characters each. Underneath: output tokens (Claude’s replies, the most expensive per token) and the share read from cache (context reused from a recent request, billed at a small fraction of the normal input rate).',
    'k-cc': 'Claude Code sessions — distinct coding sessions in the terminal or IDE, as reported by Anthropic, counted per UTC day. Chat and Cowork work is not counted here. "Last active" is the most recent day with any Claude activity.',
    /* spend-against-limit tiles */
    'k-cap-spent': 'Your spend so far this month as a share of your monthly spend limit. A $0 limit means no usage beyond what the plan includes, so any spend reads as over. "No limit set" means Anthropic has no limit on record for you.',
    'k-cap-rate': 'Spend so far this month divided by calendar days elapsed (UTC) — including days you did not use Claude.',
    'k-cap-proj': 'The daily run rate carried to the end of the month and compared with your limit: on track under 80%, near the limit from 80%, over at 100%. A closed month shows its actual total instead.',
    /* team tiles */
    'k-team-spend': 'Usage-based Claude spend for everyone in your reporting line this period, after discount and before credits. Includes people whose seat has since been removed. Your own usage is not included.',
    'k-team-access': 'People under you who hold a Claude seat, out of everyone in your reporting line. "Unconfirmed" means we could not check — it does not mean they have no seat.',
    'k-team-used': 'People with any Claude activity or spend this period — a single conversation counts. Everyone else is split into "with a seat and no usage" and "without a seat".',
    'k-team-copilot': 'People in your reporting line with a Microsoft 365 Copilot licence, from the Microsoft 365 licence report, which can lag up to ten days. Not related to Claude.',
    'k-team-sessions': 'Claude Code sessions, chat conversations and Cowork sessions added together. They are different units, which is why the split is shown underneath.',
    /* activity figures (What you did with it) -- Anthropic analytics/users fields */
    'a-cc-sessions': 'Claude Code sessions — distinct coding sessions in the terminal or IDE, as reported by Anthropic, counted per UTC day.',
    'a-commits': 'Git commits made through Claude Code.',
    'a-prs': 'Pull requests created through Claude Code.',
    'a-loc-added': 'Lines of code added through Claude Code.',
    'a-loc-removed': 'Lines of code removed through Claude Code.',
    'a-edits-acc': 'Claude Code file edits you accepted — its proposals to edit, write or change a file.',
    'a-edits-rej': 'Claude Code file edits you rejected. Anthropic currently reports no rejections for our organization, so this reads 0 and no acceptance rate is shown.',
    'a-cw-sessions': 'Cowork sessions — Claude working through files and tasks in a shared workspace, counted per UTC day.',
    'a-cw-edits': 'Files Claude edited or wrote for you in Cowork.',
    'a-chat-conv': 'Chat conversations you took part in, counted per UTC day — a conversation you returned to on three days counts three times.',
    'a-chat-msgs': 'Messages you sent in Claude chat.',
    'a-web': 'Server-side web searches Claude performed on your behalf as part of answering a request — a tool call, not a separate product.',
    'a-cw-actions': 'Tool actions Claude completed for you in Cowork — reading, searching, editing and running things.',
    'a-cw-msgs': 'Messages you sent in Cowork.',
    'a-chat-artifacts': 'Artifacts Claude created for you in chat — documents, code, pages and diagrams shown beside the conversation.',
    'a-chat-proj-used': 'Claude Projects you worked in — shared spaces that hold instructions and files for a set of chats.',
    'a-chat-proj-new': 'Claude Projects you created.',
    'a-chat-skills': 'Skills Claude used in your chats — packaged instructions that teach Claude a specific task.',
    /* drill-down header */
    'drill-status': 'One reading for the person you are viewing, checked in order: not measured, no seat, then spend against their monthly limit — over at 100%, near at 75%. A $0 limit counts as over as soon as there is any spend. With no limit on record the badge says so rather than guessing.'
  };
  /* The label carries the full text so a screen reader never has to open
   * anything; the visible glyph is decorative next to it. */
  function helpLabel(k) { return 'What is this? ' + (HELP[k] || ''); }
  function hx(k) {
    if (!HELP[k]) return '';   // never emit a control with nothing to say
    return '<button type="button" class="help" data-h="' + esc(k) + '" aria-label="' + esc(helpLabel(k)) + '">?</button>';
  }
  function labelHelp(root) {
    $$('.help[data-h]', root || document).forEach(function (el) {
      if (!el.getAttribute('aria-label')) el.setAttribute('aria-label', helpLabel(el.getAttribute('data-h')));
    });
  }
  function helpTip(el) {
    var tip = el.querySelector('.htip');
    if (!tip) {
      tip = document.createElement('span');
      tip.className = 'htip';
      /* aria-hidden: the same words are already on the button's own label, and
       * announcing them twice is how a tooltip becomes noise. */
      tip.setAttribute('aria-hidden', 'true');
      tip.textContent = HELP[el.getAttribute('data-h')] || '';
      el.appendChild(tip);
    }
    return tip;
  }
  /* Measured, not assumed: the same button sits in the first tile of a
   * five-across grid and in the last, and a 292px panel anchored to one edge
   * runs off the screen in one of those two places whatever you pick.
   *
   * The nudge rides on `right`, a LAYOUT property, and not on the transform.
   * A custom property feeding a transform is not a layout input, so the
   * getBoundingClientRect() that follows setting it is NOT guaranteed to force
   * the recalc -- measured in Chrome: set --hx, read the rect, get the previous
   * box back. The reset-then-measure below would then be measuring the panel's
   * already-shifted position and computing a correction against it. Setting
   * `right` invalidates layout, so the read after it is honest.
   * A larger `right` pushes the panel further left, so moving it right by d
   * means subtracting d. */
  function placeTip(el) {
    var tip = helpTip(el), pad = 8;
    tip.style.right = '-4px';
    var r = tip.getBoundingClientRect(), d = 0;
    if (r.left < pad) d = pad - r.left;
    else if (r.right > window.innerWidth - pad) d = (window.innerWidth - pad) - r.right;
    if (d) tip.style.right = Math.round(-4 - d) + 'px';
  }
  function closeHelp(except) {
    $$('.help.open').forEach(function (o) { if (o !== except) o.classList.remove('open'); });
  }
  /* See the .hush note in the stylesheet: Escape must get the panel out of the
   * way without stealing the user's place in the tab order. */
  function hushHelp() {
    var a = document.activeElement;
    if (a && a.classList && a.classList.contains('help')) a.classList.add('hush');
  }
  function unhush(el) { if (el) el.classList.remove('hush'); }
  function helpTarget(e) { return e.target && e.target.closest ? e.target.closest('.help[data-h]') : null; }
  document.addEventListener('mouseover', function (e) { var el = helpTarget(e); if (el) { unhush(el); placeTip(el); } });
  document.addEventListener('focusin', function (e) { var el = helpTarget(e); if (el) { unhush(el); placeTip(el); } });
  document.addEventListener('focusout', function (e) { unhush(helpTarget(e)); });
  document.addEventListener('click', function (e) {
    var el = helpTarget(e);
    closeHelp(el);
    if (!el) return;
    /* The tiles and section headings sit inside rows that are themselves
     * clickable (a team row steps into a person); the helper must not navigate. */
    e.preventDefault();
    e.stopPropagation();
    if (el.classList.contains('open')) { el.classList.remove('open'); return; }
    placeTip(el);
    el.classList.add('open');
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeHelp(null); hushHelp(); } });
  window.addEventListener('resize', function () { closeHelp(null); });
  document.addEventListener('DOMContentLoaded', function () { labelHelp(document); });

  function drillHeadHtml(o) {
    var sub = [o.title, o.department, o.email].filter(Boolean).map(esc).join(' · ');
    return '<div class="drillhd">'
      + '<a class="btn ghost sm drillhd-back" href="' + esc(o.back) + '">' + ic('arrow-left') + esc(o.backLabel) + '</a>'
      + '<div class="drillhd-id">'
      + '<span class="drillhd-av" data-photo="' + esc(o.email) + '" aria-hidden="true">' + esc(initials(o.name || o.email)) + '</span>'
      + '<div class="drillhd-txt">'
      + (o.status ? '<span class="chip ' + o.status.k + ' drillhd-sev">' + esc(o.status.t) + '</span>' + hx('drill-status') : '')
      + '<h2>' + esc(o.name) + '</h2>'
      + (sub ? '<div class="drillhd-sub">' + sub + '</div>' : '')
      + '</div></div>'
      + '<div id="ai-drill-act" hidden></div>'
      + '<div class="drillhd-foot">You are viewing <b>' + esc(o.name) + '’s</b> usage for ' + esc(AI.period.label)
      + ' — not your own. Every lookup of another person’s usage is written to the audit log.</div>'
      + '</div>';
  }
  /* The reference's ladder, in the reference's order (openReviewDrawer:1904):
   *   NO LIMIT SET / OVER LIMIT >=100% / NEAR LIMIT >=75% / NO USAGE / ON TRACK.
   * Three rungs sit ABOVE it that the reporting sheet has no need for. That
   * sheet is only ever opened for somebody already in the Claude roster with a
   * measured period; this one is reached for anyone in a manager's org, seat or
   * no seat, in any month the collector may not have covered. A green ON TRACK
   * over a person with no access, or over a month nobody measured, is a false
   * all-clear -- the one thing this section is not allowed to say. The wording
   * of those three is accessCell()'s, so the badge and the team table agree. */
  function drillStatus(c) {
    var cov = c.periodCoverage;
    if (cov && !cov.zeroIsMeasured) return { t: 'NOT MEASURED', k: 'amber' };
    var acc = c.access && c.access.claude ? c.access.claude : null;
    if (acc && acc.access === 'unavailable') return { t: 'ACCESS CAN’T BE CONFIRMED', k: 'amber' };
    if (acc && acc.access === 'none') return { t: 'NO CLAUDE ACCESS', k: '' };
    var L = c.limitRequest, cur = L ? L.current : null;
    // cur === 0 is a real $0 limit, not "no limit" — only cur == null is unlimited.
    var pct = (cur != null && L.ptdSpend != null)
      ? (cur > 0 ? (L.ptdSpend / cur * 100) : (L.ptdSpend > 0 ? Infinity : 0)) : null;
    if (pct == null) return { t: 'NO LIMIT SET', k: 'blue' };
    if (pct >= 100) return { t: 'OVER LIMIT', k: 'red' };
    if (pct >= 75) return { t: 'NEAR LIMIT', k: 'amber' };
    if (!c.daysWithUsage && !c.requests && !c.spend) return { t: 'NO USAGE', k: '' };
    return { t: 'ON TRACK', k: 'green' };
  }
  /* Repaint with the authoritative name -- CLAUDE.subject.displayName comes from
   * the route, whereas the skeleton could only use the team payload, which is
   * empty when somebody opens #claude/u/<email> directly. */
  /* One resolver for the subject's name, because there are now three places
   * that need it and they must not disagree. `displayName` is claude_members'
   * -- NULL for anyone without a seat (profile-routes.js:1029) -- so the team
   * roster is the fallback and the raw address is the last resort. Resolving
   * this twice is how the header said "Oscar Benitez" in 20px while the
   * section heading below it said "ic.tax2@auction.com". */
  function subjectName(c) {
    var known = TEAM && TEAM.members ? TEAM.members.filter(function (m) { return m.email === c.subject.email; })[0] : null;
    return c.subject.displayName || (known && known.name) || c.subject.email || aiDrill;
  }
  /* Every place on the page that names the subject, repainted together. They
     have to move as one: on a direct hit of #claude/u/<email> the team payload
     lands AFTER /claude, and repainting only the header left the section
     heading below it still addressing the person by raw email address. */
  function paintSubjectCopy(c) {
    var isSelf = c.subject.isSelf, name = subjectName(c);
    /* On a drill-down the subject header above already states, in the largest
       type on the page, whose usage this is. Repeating it here in 11px is the
       kind of quiet second mention that let the old layout read as the viewer's
       own figures. The view-as banner still needs its copy. */
    $('#claude-subject').textContent = (isSelf || aiDrill) ? '' : 'Viewing ' + name + ' · audited';
    paintDrillSubject(c);
    /* "What you did with it" is addressed to the reader. On a drill-down the
       reader is not the person the card counts. */
    var actHd = $('#claude-activity-hd');
    if (actHd) actHd.textContent = isSelf ? 'What you did with it' : 'What ' + String(name).split(' ')[0] + ' did with it';
  }
  function paintDrillSubject(c) {
    if (!aiDrill) return;
    var known = TEAM && TEAM.members ? TEAM.members.filter(function (m) { return m.email === aiDrill; })[0] : null;
    $('#ai-drillbar').innerHTML = drillHeadHtml({
      back: '#claude/' + aiTab, backLabel: 'Back to ' + (aiTab === 'team' ? 'team usage' : 'my usage'),
      email: c.subject.email || aiDrill,
      name: subjectName(c),
      title: known ? known.title : '', department: known ? known.department : '',
      status: drillStatus(c),
    });
    hydrate($('#ai-drillbar'));
    hydratePhotos($('#ai-drillbar'));
  }

  function paintDrillLimit(c) {
    var slot = $('#ai-drill-act');
    if (!slot) return;
    var L = c.limitRequest;
    // Your own page: the limit is your manager's to raise, not yours.
    if (!L || L.reason === 'self') { slot.innerHTML = ''; slot.hidden = true; return; }
    slot.hidden = false;
    var cur = L.current;
    var used = (cur != null && L.ptdSpend != null)
      ? ' <span class="note">· ' + money(L.ptdSpend) + ' used' + (cur > 0 ? ', ' + Math.round(L.ptdSpend / cur * 100) + '%' : '') + '</span>' : '';
    var head = cur == null ? '<span class="note">No monthly limit on record</span>'
      : '<span class="note">Monthly limit</span> <b class="mono">' + money(cur) + '</b>' + used;
    var ctl;
    if (L.can) ctl = '<button class="btn sm" data-drill-req>Request increase</button>';
    else if (L.reason === 'viewing-as' && cur != null) ctl = '<button class="btn sm" data-drill-req data-preview="1" title="Preview — a borrowed view cannot send the request">Request increase</button>';
    else if (L.reason === 'no-limit-row') ctl = '<span class="note">Nothing to raise until a limit is set.</span>';
    else ctl = '<span class="note">Only their own management line can raise this.</span>';
    slot.innerHTML = '<div class="drill-lim">' + head + ctl + '<div class="note" data-drill-msg></div></div>';
    var b = slot.querySelector('[data-drill-req]');
    if (b) b.addEventListener('click', function () {
      openLimitReq(c.subject.email, cur, '', b, slot.querySelector('[data-drill-msg]'), b.hasAttribute('data-preview'));
    });
  }

  function openLimitReq(email, curLimit, rec, btn, msg, preview) {
    var cur = Number(curLimit) || null;
    var def = Number(rec) || (cur ? Math.round(cur * 2) : '');
    var wrap = document.createElement('span');
    wrap.style.cssText = 'display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap';
    wrap.innerHTML = '<span class="note">Raise to \$</span>'
      + '<input type="number" min="1" step="1" value="' + esc(String(def)) + '" '
      + 'style="width:96px;padding:5px 8px;border:1px solid var(--line);border-radius:5px;background:var(--card);color:inherit">'
      + '<span class="note">/mo</span>'
      + '<button class="btn sm"' + (preview ? ' disabled title="A borrowed view is read-only"' : '') + '>Send request</button>'
      + '<button class="btn sm ghost">Cancel</button>';
    wrap.addEventListener('click', function (e) { e.stopPropagation(); });
    var input = wrap.querySelector('input');
    var btns = wrap.querySelectorAll('button');
    btn.parentNode.replaceChild(wrap, btn);
    try { input.focus(); } catch (e) {}
    if (preview && msg) { msg.textContent = 'Preview only \u2014 a borrowed view cannot send the request.'; msg.style.color = ''; }
    btns[0].addEventListener('click', function () { if (preview) return; requestLimitIncrease(email, input.value, btns[0], msg, cur); });
    btns[1].addEventListener('click', function () { wrap.parentNode.replaceChild(btn, wrap); if (preview && msg) msg.textContent = ''; });
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); btns[0].click(); } });
  }

  /* Files the Service Desk ticket with the manager's requested total. The email
   * and the amount are the only inputs; every other figure in the ticket is
   * recomputed server-side, because numbers a browser supplied would be quoted as
   * fact to whoever picks the ticket up. */
  function requestLimitIncrease(email, amount, btn, msg, curLimit) {
    var amt = parseFloat(amount);
    if (!isFinite(amt) || amt <= 0) {
      if (msg) { msg.textContent = 'Enter the new monthly total, e.g. 200.'; msg.style.color = 'var(--red-tx)'; }
      return;
    }
    if (curLimit && amt <= curLimit) {
      if (msg) { msg.textContent = 'Enter a total higher than the current ' + money(curLimit) + '/mo.'; msg.style.color = 'var(--red-tx)'; }
      return;
    }
    btn.disabled = true;
    var was = btn.textContent;
    btn.textContent = 'Raising\u2026';
    api('POST', '/ai-team/limit-request', { email: email, newLimit: amt }).then(function (r) {
      if (msg) {
        msg.innerHTML = 'Raised as <a href="' + esc(r.ticket.url) + '" target="_blank" rel="noopener">ticket '
          + esc(r.ticket.display) + '</a> \u2014 asking to raise to ' + money(r.recommended)
          + (r.filedUnder && r.filedUnder !== (ME && ME.email) ? ' (filed under ' + esc(r.filedUnder) + ')' : '') + '.';
        msg.style.color = 'var(--amber-tx)';
      }
      var wrap = btn.parentNode;
      var link = document.createElement('a');
      link.className = 'btn sm'; link.href = r.ticket.url; link.target = '_blank'; link.rel = 'noopener';
      link.textContent = 'Ticket ' + r.ticket.display;
      if (wrap && wrap.parentNode) wrap.parentNode.replaceChild(link, wrap);
    }).catch(function (e) {
      btn.disabled = false; btn.textContent = was;
      if (msg) { msg.textContent = e.message || 'The request could not be raised.'; msg.style.color = 'var(--red-tx)'; }
    });
  }

  /* ── the organisation, one rung at a time ──────────────────────────────
   *
   *   Your organisation  ›  David Wilson  ›  Finance  ›  Maria Chen  ›  …
   *
   * This is the drill on reporting/ai-usage-credits.html, rebuilt on this
   * page's own payload: crumbs, one table, invariant columns, a Total at the
   * foot. Jeramy asked for that flow by name -- "mirror as close to the
   * reporting ai flow as you can ... with user, and department".
   *
   * What it replaced, and why. The card before this had FIVE destinations
   * competing on one screen: a "Direct reports" table whose rows navigated to
   * a person while an "Open team" button inside the same row went somewhere
   * else entirely, a department bar chart that set a filter on a THIRD card, a
   * People list with a six-way state seg, a department <select> and a search
   * box. Reading his complaint literally -- "if i click on David wilson its nt
   * super clear that i am looking at that employee ... its also confusing when
   * i click on David Wilson and then below it is open team but there is no
   * distinction ... too many clicks" -- all three sentences are the same
   * defect: a row meant two things, so it could not say which one it meant.
   *
   * The rule here is one destination per row, and the rung says what a row
   * means. There are three:
   *
   *   root    rows are the viewer's DIRECT REPORTS, each standing for their
   *           whole team. They partition the organisation, so they add to the
   *           foot.
   *   dept    inside a person: their own row first, then the DEPARTMENTS of
   *           everyone below them. ("we need a team useage with david wilson
   *           in it, and the departmet flows below it.")
   *   person  inside a department -- or inside a person whose organisation is
   *           all one department, where a department rung would be the level
   *           restated -- rows are INDIVIDUALS.
   *
   * Two populations, one Spend column, and the rung is what distinguishes
   * them. At root a row's figure is a whole subtree; inside a department it is
   * one person, because that department already contains their reports and
   * counting their team here would count those people twice. The header
   * column and the card title both name the rung, so the reader is never
   * asked to infer which.
   *
   * Still no new endpoint, and still no fetch on a drill: /ai-team returns the
   * whole closure below the viewer, and every rung is an index over it.
   *
   * Three things about that payload drive the code below, and getting any of
   * them wrong yields a tree that looks right and is not:
   *   1. members is sorted by SPEND, not parent-before-child, so the index has
   *      to be built in full before anything is walked.
   *   2. the scope root's own email is not in the payload, so the top level is
   *      members.filter(direct) -- NOT "whoever has no manager here".
   *   3. directReports is AD's count, which can exceed the children actually
   *      present (the closure is depth-capped, and a rebuild can race the
   *      read). Where they disagree the node is NOT a leaf and must not be
   *      drawn as one -- see unresolved() below.
   */

  /* Alternating steps: {email,name} for a person, {dept} for a department.
   * The LAST entry decides what the table is showing. */
  var orgPath = [];

  function teamIndex() {
    var kids = Object.create(null), byEmail = Object.create(null);
    TEAM.members.forEach(function (m) {
      byEmail[String(m.email).toLowerCase()] = m;
      var k = m.managerEmail ? String(m.managerEmail).toLowerCase() : '';
      if (!k) return;
      (kids[k] || (kids[k] = [])).push(m);
    });
    /* Children keep the table's existing spend-descending order so a stepped-in
     * level reads like the list it came from. The name tiebreak is the same one
     * the server applies (ai-tools-lib.js teamReport), because the SQL behind it
     * has no ORDER BY -- without an explicit tiebreak here, two people on equal
     * spend would sit in whatever order MySQL happened to return. */
    Object.keys(kids).forEach(function (k) {
      kids[k].sort(function (a, b) {
        return (b.spend || 0) - (a.spend || 0) || String(a.name).localeCompare(String(b.name));
      });
    });
    return { kids: kids, byEmail: byEmail, sub: Object.create(null) };
  }
  function childrenOf(ix, m) { return ix.kids[String(m.email).toLowerCase()] || []; }

  /* AD says this person has N directs; the payload contains K of them. The gap
   * is people we know exist and cannot show. Reporting K as the whole truth is
   * the failure this returns a number for. */
  function unresolved(ix, m) {
    return Math.max(0, (m.directReports || 0) - childrenOf(ix, m).length);
  }

  /* ai-tools-lib.js:154 is explicit about this: `spend` is the rounded display
   * value and `spendRaw` is full precision "for anything that adds". The team
   * KPI sums the same way (teamStats calls straight through to here), so a
   * roll-up cannot land on a different number than the tile above it. Anything
   * that ADDS goes through here; a single person's own figure is still
   * displayed from `spend`, which is what that field is for. */
  function spendOf(m) {
    var v = (m.spendRaw != null) ? m.spendRaw : m.spend;
    return v == null ? 0 : Number(v) || 0;
  }
  function hasSeat(p) { return p.claudeAccess === 'active' || p.claudeAccess === 'licensed'; }
  function hasCopilot(p) { return p.copilotAccess === 'active' || p.copilotAccess === 'licensed'; }
  function usedIt(p) { return p.usageState !== 'no-usage' && p.usageState !== 'no-access' && p.usageState !== 'unavailable'; }

  /* Every node at or below m, deduped. The `seen` guard is not decoration: a
   * manager cycle in AD would hang the walk and take the tab with it.
   *
   * Memoised per index build. teamAgg runs once per row per paint, and the
   * manager this card was designed around has 88 directs -- un-memoised, one
   * repaint of that level is 88 full subtree walks. */
  function subtreeOf(ix, m) {
    var key = String(m.email).toLowerCase();
    if (ix.sub[key]) return ix.sub[key];
    var out = [], seen = Object.create(null);
    (function walk(node) {
      var e = String(node.email).toLowerCase();
      if (seen[e]) return; seen[e] = 1;
      out.push(node);
      childrenOf(ix, node).forEach(walk);
    })(m);
    ix.sub[key] = out;
    return out;
  }

  /* The aggregate of an arbitrary SET of people. A department is a cut ACROSS
   * the reporting line, not a subtree -- two people in Tax can sit under
   * different directors -- so it cannot go through a tree walk. Everything
   * else is identical, and both paths add through spendOf, which is the only
   * way the two cuts of one population can be made to reconcile. */
  function setAgg(ix, list) {
    var a = { spend: 0, own: 0, people: 0, seats: 0, copilot: 0, used: 0, unmeasured: 0, partial: false };
    list.forEach(function (node) {
      a.people++;
      if (node.spendRaw != null || node.spend != null) a.spend += spendOf(node);
      else if (node.usageState === 'unavailable') a.unmeasured++;
      if (hasSeat(node)) a.seats++;
      if (hasCopilot(node)) a.copilot++;
      if (usedIt(node)) a.used++;
      if (unresolved(ix, node)) a.partial = true;
    });
    if (a.unmeasured) a.partial = true;
    return a;
  }

  /* A root row describes a WHOLE TEAM: the person's own usage plus everyone
   * beneath them. An individual contributor's team is just themselves, so the
   * column means the same thing on every row of that rung and the rows add to
   * the foot.
   *
   * Anything we cannot see makes the figure a FLOOR, not a total, and the
   * caller must say so: reports AD counts that the payload does not carry
   * (unresolved), and people whose usage was never collected. */
  function teamAgg(ix, m) {
    var a = setAgg(ix, subtreeOf(ix, m));
    a.own = spendOf(m);
    /* people counts the node itself; totalReports does not. */
    if (a.people < (m.totalReports || 0) + 1) a.partial = true;
    return a;
  }

  /* "Has a team" must mean what AD says, not what the payload happened to
   * carry. A node AD gives reports that the closure did not return has NO
   * children here -- and keying off children alone dropped it back to the
   * plain one-person cell, printing a bare total for a figure that is
   * provably a floor. That is the precise failure the floor marker exists to
   * prevent, so unresolved reports count as a team. */
  function isLeader(ix, m) { return childrenOf(ix, m).length > 0 || unresolved(ix, m) > 0; }

  /* Everyone in the payload who is not reachable from one of the viewer's own
   * directs. They are real people whose spend is in the KPI above but in none
   * of these rows, so the level would quietly under-count without saying so. */
  function orphanCount(ix) {
    var seen = Object.create(null), n = 0;
    TEAM.members.filter(function (m) { return m.direct; }).forEach(function (d) {
      subtreeOf(ix, d).forEach(function (x) { seen[String(x.email).toLowerCase()] = 1; });
    });
    TEAM.members.forEach(function (m) { if (!seen[String(m.email).toLowerCase()]) n++; });
    return n;
  }

  /* Departments of a set, in the server's own order (spend desc, then name),
   * keyed on the department NAME because that is what byDepartment groups on
   * (ai-tools-lib.js:934). Keying on deptCode instead would make this table
   * disagree with the departments[] in its own payload. */
  function deptsOf(ix, pool) {
    var by = Object.create(null);
    pool.forEach(function (m) {
      var k = m.department || 'Unassigned';
      (by[k] || (by[k] = [])).push(m);
    });
    return Object.keys(by).map(function (k) {
      return { dept: k, list: by[k], a: setAgg(ix, by[k]) };
    }).sort(function (x, y) {
      return (y.a.spend - x.a.spend) || String(x.dept).localeCompare(String(y.dept));
    });
  }

  /* Walk the path and report where we are. Returns the person whose
   * organisation we are inside (null at the root), the department stepped into
   * (null unless one was), and the POOL those two select. */
  function orgAt(ix) {
    var subject = null, dept = null,
        pool = TEAM.members.filter(function (m) { return m.direct; });
    for (var i = 0; i < orgPath.length; i++) {
      var st = orgPath[i];
      if (st.email) {
        var m = ix.byEmail[String(st.email).toLowerCase()];
        /* A stale path -- the payload changed under it, most often a month
         * switch -- is truncated rather than rendered as an empty table. */
        if (!m) { orgPath = orgPath.slice(0, i); break; }
        subject = m; dept = null;
        /* Their organisation is everyone below them. They are excluded here
         * because they get a row of their own at the top; leaving them in the
         * pool would put them in a department row as well and count them
         * twice against their own foot. */
        pool = subtreeOf(ix, m).filter(function (x) { return x !== m; });
      } else {
        dept = st.dept;
        pool = pool.filter(function (x) { return (x.department || 'Unassigned') === dept; });
      }
    }
    return { subject: subject, dept: dept, pool: pool };
  }

  /* Department is a rung only where there is more than one to choose from.
   * With a single department the row would be the whole level restated and
   * the click would tell the reader nothing they could not already see, so
   * the rung is skipped and the people are shown directly -- rather than
   * rendering a control that cannot do its job. */
  function orgShape(ix, at) {
    if (!at.subject) return 'root';
    if (at.dept) return 'person';
    return deptsOf(ix, at.pool).length > 1 ? 'dept' : 'person';
  }

  function floorPfx(partial) {
    return partial ? '<span class="tr-floor" title="Some people below are missing from this view or had no usage collected, so this is a floor, not a total">at least </span>' : '';
  }
  /* THE GUARD. In a month the collector never covered, zero is not a
   * measurement. Without this every group row and the foot printed "$0.00" --
   * or worse, "at least $0.00" -- directly below a KPI tile showing an
   * em-dash for exactly the same population. */
  function teamSpendCell(a, known) {
    if (!known) return '<span class="dim">—</span>';
    return floorPfx(a.partial) + money(a.spend);
  }
  function teamSeatCell(a) { return '<span class="chip">' + num(a.seats) + ' of ' + num(a.people) + '</span><div class="tr-sub">with a seat</div>'; }
  function teamUsageCell(a, known) {
    if (!known) return '<span class="chip amber">Not collected</span>';
    return a.used ? '<span class="chip blue">' + num(a.used) + ' used it</span><div class="tr-sub">of ' + num(a.people) + '</div>'
                  : '<span class="chip">No usage this period</span>';
  }
  function teamCopilotCell(a) { return '<span class="chip">' + num(a.copilot) + ' of ' + num(a.people) + '</span>'; }
  function goChev() { return '<span class="tr-go" aria-hidden="true">›</span>'; }
  /* The person's Microsoft 365 photo. INITIALS are what is rendered here; the
   * photo is swapped in later by hydratePhotos only if one actually loads, so
   * somebody Graph has no photo for keeps a readable box instead of a broken
   * image. /api/photo takes a upn and the member carries `email` -- the same
   * field profile-routes.js:651 builds the viewer's own photoUrl from. */
  function avCell(m) {
    return '<span class="tr-av" data-photo="' + esc(m.email) + '" aria-hidden="true">'
      + esc(initials(m.name || m.email)) + '</span>';
  }
  /* A department is not a person. It still needs the 28px box or the names
   * below it would sit at a different left edge from the person above them. */
  function deptAvCell() { return '<span class="tr-av tr-av-dept" data-icon="users" aria-hidden="true"></span>'; }

  /* ---- the three row shapes. Every one of them has ONE destination. ---- */

  /* A direct report, standing for their whole team. Drilling opens their
   * organisation; if they have no team it opens them. */
  function orgTeamRow(ix, m, known) {
    var lead = isLeader(ix, m), a = teamAgg(ix, m), un = unresolved(ix, m);
    /* isLeader counts reports AD knows about but the payload does not carry, so
       that the figure is marked a floor. It must NOT decide the destination:
       a node with nothing resolved below it would open a level containing only
       their own row. They keep the team cells (a team of one is still their
       figure) and the row opens THEM, with the gap stated on the row. */
    var canStep = childrenOf(ix, m).length > 0;
    return '<tr class="pick" role="button" tabindex="0"'
      + ' data-go="' + (canStep ? 'team' : 'user') + '" data-email="' + esc(m.email) + '"'
      + ' data-name="' + esc(m.name) + '"'
      + ' aria-label="' + esc(canStep ? 'Open ' + m.name + '’s organisation' : 'Open ' + m.name + '’s usage') + '">'
      + '<td><div class="tr-who">' + avCell(m) + '<div class="who"><span>' + esc(m.name) + goChev() + '</span><small>' + esc(m.title || m.email) + '</small>'
        + (un ? '<div class="tr-sub"><span class="tr-floor">' + num(un) + ' not in this view</span></div>' : '')
        + '</div></div></td>'
      /* canStep, not lead: a node with nothing resolved below it would print
         "0 direct" under a headcount of 1, which reads as a measurement. What
         is true about it is on the name cell — "2 not in this view". */
      + '<td class="num">' + (canStep ? '<b>' + num(a.people) + '</b>' : '<span class="dim">' + num(a.people) + '</span>') + '</td>'
      + '<td>' + (lead ? teamSeatCell(a) : accessCell(m.claudeAccess, m.claudeRole)) + '</td>'
      + '<td class="num">' + (lead ? teamSpendCell(a, known) : spendCell(m)) + '</td>'
      + '<td>' + (lead ? teamUsageCell(a, known) : usageCell(m)) + '</td>'
      + '<td>' + (lead ? teamCopilotCell(a) : accessCell(m.copilotAccess)) + '</td></tr>';
  }

  /* A department inside somebody's organisation. */
  function orgDeptRow(g, known) {
    return '<tr class="pick" role="button" tabindex="0" data-go="dept"'
      + ' data-dept="' + esc(g.dept) + '" data-name="' + esc(g.dept) + '"'
      + ' aria-label="' + esc('Open ' + g.dept) + '">'
      + '<td><div class="tr-who">' + deptAvCell() + '<div class="who"><span>' + esc(g.dept) + goChev() + '</span></div></div></td>'
      + '<td class="num"><b>' + num(g.a.people) + '</b></td>'
      + '<td>' + teamSeatCell(g.a) + '</td>'
      + '<td class="num">' + teamSpendCell(g.a, known) + '</td>'
      + '<td>' + teamUsageCell(g.a, known) + '</td>'
      + '<td>' + teamCopilotCell(g.a) + '</td></tr>';
  }

  /* One person, their own usage.
   *
   * `self` is the person whose organisation we are inside. It decides the
   * DESTINATION and nothing else: their row opens them, never their
   * organisation, because that is the level already on screen.
   *
   * It used to tint the row, rule-mark it and explain itself in a sub-line.
   * Jeramy, twice: "list David Wilson under as a user" / "MATCH the drill down
   * strict". The reference roll-up has no self row and no sub-lines under a
   * name -- a name, a chevron, numbers -- so neither does this one. He is
   * simply the first person in the list. */
  function orgPersonRow(ix, m, known, self, find) {
    /* childrenOf, not isLeader: a node whose reports AD knows about are all
       missing from the payload has nothing to open. */
    var lead = childrenOf(ix, m).length > 0;
    var go = (!self && lead) ? 'team' : 'user';
    return '<tr class="pick" role="button" tabindex="0"'
      + ' data-go="' + go + '"' + (find ? ' data-find="1"' : '') + ' data-email="' + esc(m.email) + '" data-name="' + esc(m.name) + '"'
      + ' aria-label="' + esc(go === 'team' ? 'Open ' + m.name + '’s organisation' : 'Open ' + m.name + '’s usage') + '">'
      + '<td><div class="tr-who">' + avCell(m) + '<div class="who"><span>' + esc(m.name) + goChev() + '</span><small>' + esc(m.title || m.email) + '</small>'
        /* Two rows that look identical must not go to different places
           unannounced: this is the only thing that says a row opens a TEAM. */
        + (!self && lead ? '<div class="tr-sub">' + num(childrenOf(ix, m).length) + ' report to them</div>'
                : find ? '<div class="tr-sub">' + esc(m.department || 'Unassigned') + (m.managerName ? ' · reports to ' + esc(m.managerName) : '') + '</div>' : '')
        + '</div></div></td>'
      + '<td class="num"><span class="dim">1</span></td>'
      + '<td>' + accessCell(m.claudeAccess, m.claudeRole) + '</td>'
      + '<td class="num">' + spendCell(m) + '</td>'
      + '<td>' + usageCell(m) + '</td>'
      + '<td>' + accessCell(m.copilotAccess) + '</td></tr>';
  }

  /* The foot is the SUM OF THE ROWS ON SCREEN -- not an independently computed
   * figure that happens to agree. Every rung is built as a partition, so if
   * the rows and the total ever disagree the partition is wrong and the foot
   * is what shows it. Stepped into somebody, this sum is their teamAgg to the
   * cent, which is the property orgtest.js asserts. */
  function sumAggs(list) {
    return list.reduce(function (s, a) {
      s.spend += a.spend; s.people += a.people; s.seats += a.seats;
      s.used += a.used; s.copilot += a.copilot;
      if (a.partial) s.partial = true;
      return s;
    }, { spend: 0, own: 0, people: 0, seats: 0, copilot: 0, used: 0, unmeasured: 0, partial: false });
  }

  /* The rows of the current rung, as {agg, html} so the foot can sum exactly
   * what was drawn. Kept separate from paintOrg so the tests can assert the
   * arithmetic without a DOM. */
  function orgLevel(ix, at, shape, known) {
    if (shape === 'root') {
      /* Ordered by the figure the row actually states — the TEAM total — the
         way the reporting roll-up orders its own rows. The payload arrives
         sorted by each person's OWN spend, which is a different number: a
         director spending nothing personally over a team spending the most
         would otherwise sort last on a table whose column says $40,000. */
      return TEAM.members.filter(function (m) { return m.direct; }).map(function (m) {
        return { a: teamAgg(ix, m), m: m };
      }).sort(function (x, y) {
        return (y.a.spend - x.a.spend) || String(x.m.name).localeCompare(String(y.m.name));
      }).map(function (r) {
        return { a: r.a, html: orgTeamRow(ix, r.m, known) };
      });
    }
    if (shape === 'dept') {
      return deptsOf(ix, at.pool).map(function (g) {
        return { a: g.a, html: orgDeptRow(g, known) };
      });
    }
    return at.pool.slice().sort(function (a, b) {
      return (spendOf(b) - spendOf(a)) || String(a.name).localeCompare(String(b.name));
    }).map(function (m) {
      return { a: setAgg(ix, [m]), html: orgPersonRow(ix, m, known, false) };
    });
  }

  /* "Your organisation" is a real crumb even at the root, the way the reporting
   * roll-up always shows "Company" — so a reader can see they are at the top
   * rather than infer it from an absent control.
   *
   * Labels come from the path, never from the cell text. The reference reads
   * row.querySelector('td')?.textContent.trim() and its chevron lives in that
   * same cell, so every crumb there reads "David Wilson ›" beside the
   * separator's own "›". Ours cannot: the name is on the row as data-name. */
  function orgCrumbs() {
    var box = $('#ai-org-crumbs');
    if (!box) return;
    var all = [{ name: 'Your organisation' }].concat(orgPath.map(function (st) {
      return { name: st.email ? st.name : st.dept };
    }));
    box.hidden = false;
    box.innerHTML = all.map(function (c, i) {
      return i === all.length - 1
        ? '<span class="tr-c cur" aria-current="true">' + esc(c.name) + '</span>'
        : '<button type="button" class="tr-c lnk" data-crumb="' + i + '">' + esc(c.name) + '</button>'
          + '<span class="tr-c sep" aria-hidden="true">›</span>';
    }).join('');
  }

  /* Stepping in replaces the table under the reader, so focus has to be placed
   * deliberately — otherwise a keyboard or screen-reader user is left on a row
   * that no longer exists and hears nothing about the new rung. */
  function orgFocus() {
    var c = $('#ai-org-crumbs .cur') || $('#ai-org-note');
    if (!c) return;
    c.setAttribute('tabindex', '-1');
    c.focus();
  }

  function orgToCrumb(i) {
    orgPath = orgPath.slice(0, i);   /* crumb 0 is "Your organisation", i.e. an empty path */
    paintOrg();
    orgFocus();
  }

  function orgStep(st) { orgPath = orgPath.concat([st]); paintOrg(); orgFocus(); }

  function paintOrg() {
    var card = $('#ai-org-card');
    if (!card) return;
    /* Nobody in scope: hide the card outright. This used to sit behind
       paintTeam's early return, so a month with no members left the PREVIOUS
       month's table on screen looking current. */
    if (!TEAM || !TEAM.members.length) { card.hidden = true; return; }
    var hasAny = TEAM.members.some(function (m) { return m.direct; });
    card.hidden = !hasAny;
    if (!hasAny) return;

    var known = TEAM.period.zeroIsMeasured;
    var ix = teamIndex();
    if (orgQ) return paintOrgFind(ix, known);

    var at = orgAt(ix);                 /* may truncate a stale path — crumbs come after */
    var shape = orgShape(ix, at);
    orgCrumbs();

    var rows = orgLevel(ix, at, shape, known);
    /* The subject is the first person in the list, and their aggregate joins
       the sum -- so their row plus the rows below it are exactly their team,
       which is what the foot states. They are first rather than sorted in
       because on a dept-shape rung the rows below are DEPARTMENTS, and
       ranking one person's spend against department totals would invite a
       comparison that is not one. */
    var selfA = at.subject ? setAgg(ix, [at.subject]) : null;
    var selfHtml = at.subject && !at.dept ? orgPersonRow(ix, at.subject, known, true, false) : '';
    var foot = sumAggs((selfA && selfHtml ? [selfA] : []).concat(rows.map(function (r) { return r.a; })));

    var who = at.subject ? at.subject.name : null;
    $('#ai-org-title').textContent = at.dept ? at.dept + ' — under ' + who
      : who ? who + '’s organisation' : 'Your organisation';
    /* The reference names the level in this header. Ours can too, except on
       the dept rung, where the subject's own row sits above the departments
       and "Department" would be wrong for the first line. */
    var colName = shape === 'root' ? 'Your direct reports' : shape === 'dept' ? 'Name' : 'Person';

    var note = $('#ai-org-note');
    if (at.dept) {
      note.textContent = num(rows.length) + ' ' + (rows.length === 1 ? 'person' : 'people')
        + ' in ' + at.dept + ' under ' + who;
    } else if (at.subject) {
      note.textContent = who + ' and the ' + num(foot.people - 1) + ' '
        + (foot.people - 1 === 1 ? 'person' : 'people') + ' below them'
        + (shape === 'dept' ? ' · ' + num(rows.length) + ' departments' : '');
    } else {
      var directs = TEAM.members.filter(function (m) { return m.direct; });
      note.textContent = num(directs.length) + ' report' + (directs.length === 1 ? '' : 's')
        + ' to you directly' + (TEAM.members.length > directs.length
          ? ' · ' + num(TEAM.members.length - directs.length) + ' more further down' : '');
    }

    /* People in the payload who hang off nobody visible here. Their spend is
       inside the KPI above and inside none of these rows, so the gap is named
       rather than silently swallowed by the foot. */
    var orph = at.subject ? 0 : orphanCount(ix);

    $('#ai-org').innerHTML = '<table class="tbl"><thead><tr>'
      + '<th>' + esc(colName) + '</th>'
      + '<th class="num" title="People this row covers, counting themselves">People</th>'
      + '<th>Claude</th>'
      + '<th class="num" title="Claude spend for the period, for everyone this row covers">Spend</th>'
      + '<th>Usage this period</th><th>Copilot</th></tr></thead><tbody>'
      + selfHtml + rows.map(function (r) { return r.html; }).join('')
      /* The reference's foot is one word. The card title and the crumbs
         already say what it is the total OF. */
      + '</tbody><tfoot><tr class="tr-tot grand"><td><b>Total</b></td>'
      + '<td class="num"><b>' + num(foot.people) + '</b></td>'
      + '<td class="dim">' + num(foot.seats) + ' with a seat</td>'
      + '<td class="num"><b>' + (known ? floorPfx(foot.partial) + money(foot.spend) : '—') + '</b></td>'
      + '<td class="dim">' + (known ? num(foot.used) + ' used it' : 'not collected') + '</td>'
      + '<td class="dim">' + num(foot.copilot) + ' licensed</td></tr></tfoot></table>'
      /* One line, the way the reference carries one line under its table. */
      + '<p class="note" style="margin-top:10px">'
      + (shape === 'root'
          ? 'Each row is that person’s <b>whole team</b>.'
          : at.subject && !at.dept
            ? esc(who) + '’s own usage is the first row.'
            : '')
      + ' From the <b>Manager</b> attribute in Active Directory.'
      + (orph ? ' <span class="tr-floor">' + num(orph) + ' ' + (orph === 1 ? 'person is' : 'people are')
          + ' under you but not beneath any of these reports, so their spend is in the totals above and not in this table.</span>' : '')
      + '</p>';
    hydrate($('#ai-org'));
    hydratePhotos($('#ai-org'));
  }

  /* Find is a MODE of the same table, not a rung: it answers "where is Jane
     Smith", which no rung can. It searches the whole payload, so the rows are
     not a partition of anything and the foot states a COUNT, never a total —
     summing an arbitrary set of matches would produce a figure that looks like
     a subtotal and is not one. */
  function paintOrgFind(ix, known) {
    var q = orgQ;
    var hits = TEAM.members.filter(function (m) {
      return (m.name + ' ' + m.email + ' ' + (m.title || '') + ' ' + (m.department || '')).toLowerCase().indexOf(q) >= 0;
    }).sort(function (a, b) {
      return (spendOf(b) - spendOf(a)) || String(a.name).localeCompare(String(b.name));
    });
    orgCrumbs();
    $('#ai-org-title').textContent = 'Find a person';
    $('#ai-org-note').textContent = hits.length
      ? num(hits.length) + ' of ' + num(TEAM.members.length) + ' people match'
      : 'Nobody matches';
    if (!hits.length) {
      $('#ai-org').innerHTML = '<div class="empty"><b>Nobody matches “' + esc(q) + '”</b>'
        + 'Clear the box to go back to ' + esc(orgPath.length ? 'where you were' : 'your organisation') + '.</div>';
      return;
    }
    $('#ai-org').innerHTML = '<table class="tbl"><thead><tr>'
      + '<th>Person</th><th class="num">People</th><th>Claude</th>'
      + '<th class="num">Spend</th><th>Usage this period</th><th>Copilot</th></tr></thead><tbody>'
      + hits.map(function (m) { return orgPersonRow(ix, m, known, false, true); }).join('')
      /* A COUNT, never a total: these matches are an arbitrary set, not a
         partition of anything, so the money cell is an em-dash. */
      + '</tbody><tfoot><tr class="tr-tot grand"><td><b>' + num(hits.length) + ' matching '
      + (hits.length === 1 ? 'person' : 'people') + '</b></td>'
      + '<td class="num"><b>' + num(hits.length) + '</b></td><td></td><td class="num dim">—</td>'
      + '<td></td><td></td></tr></tfoot></table>'
      + '<p class="note" style="margin-top:10px">Anyone under you, wherever they sit. People without Claude access are listed too, marked <b>No access</b>.</p>';
    hydrate($('#ai-org'));
    hydratePhotos($('#ai-org'));
  }

  /* One delegated pair of listeners for the whole card, so a repaint never
     leaves a stale handler behind and there is nothing focusable inside a row
     to fight with it. */
  function bindOrgCard() {
    var card = $('#ai-org-card');
    if (!card || card.getAttribute('data-bound')) return;
    card.setAttribute('data-bound', '1');
    var act = function (row) {
      var go = row.getAttribute('data-go');
      if (go === 'dept') { orgStep({ dept: row.getAttribute('data-dept') }); return; }
      var email = row.getAttribute('data-email');
      if (go === 'team') {
        /* From a search result the path is wherever the reader last was, which
           has nothing to do with this person — so their organisation is opened
           from the root instead of appended to a path they did not walk. */
        if (row.getAttribute('data-find')) { orgPath = []; orgQ = ''; var box = $('#ai-org-q'); if (box) box.value = ''; }
        orgStep({ email: email, name: row.getAttribute('data-name') });
        return;
      }
      location.hash = '#claude/u/' + encodeURIComponent(email);
    };
    card.addEventListener('click', function (e) {
      var b = e.target.closest('[data-crumb]');
      if (b) { orgToCrumb(Number(b.getAttribute('data-crumb'))); return; }
      var row = e.target.closest('tr[data-go]');
      if (row) act(row);
    });
    card.addEventListener('keydown', function (e) {
      var row = e.target.closest('tr[data-go]');
      /* Only when the ROW itself has focus. The guard predates this rewrite:
         without it the handler also fired for controls inside a row and its
         preventDefault() suppressed their native activation. Nothing focusable
         is left in a row now, and the guard stays anyway — that assumption is
         exactly what broke last time. */
      if (!row || e.target !== row) return;
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); act(row); }
    });
  }

  /* The KPI row. Lifted OUT of the old People painter, which is why it is a
     function of its own: the tiles, the live-API starburst, TEAM.viewerNote,
     the not-collected callout and the feed-freshness disclosure were all
     painted inside the body of a card this rewrite deletes, so deleting that
     card would have taken every one of them with it — silently, no error, just
     a missing row. The tiles cover everyone under the viewer; there is nothing
     left on the page that can filter them, so a filtered denominator can no
     longer appear under an unfiltered numerator. */
  function paintTeamKpis() {
    if (!TEAM) return;
    var known = TEAM.period.zeroIsMeasured, t = teamStats(TEAM.members, known);
    var mom = t.momPct == null ? '<div class="d flat">no comparable prior period</div>'
      : '<div class="d ' + (t.momPct > 0 ? 'down' : 'up') + '">' + pct(t.momPct) + ' vs last month' + (TEAM.summary.momBasis === 'same-span' ? ', same span' : '') + '</div>';
    $('#ai-team-kpis').innerHTML = '<div class="kpi-row">' +
      '<div class="kpi hashelp"><div class="v">' + (known ? liveIf(TEAM.feeds, 'claudeCost', 'Live from the Claude Enterprise Analytics API', true) + money(t.spend) : '—') + '</div><div class="l">Claude spend' + (TEAM.period.isCurrent ? ', period to date' : ' for the period') + '</div>' + (known ? mom : '<div class="d flat">not collected for this period</div>') + '' + hx('k-team-spend') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + num(t.claudeActive) + ' / ' + num(t.people) + '</div><div class="l">With Claude access</div><div class="d flat">' + num(t.claudeNone) + ' without' + (t.claudeUnknown ? ' · ' + num(t.claudeUnknown) + ' unconfirmed' : '') + '</div>' + hx('k-team-access') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (known ? num(t.active) : '—') + '</div><div class="l">Used Claude this period</div><div class="d flat">' + (known ? num(t.idle) + ' with a seat and no usage · ' + num(t.noAccess) + ' without a seat' : 'usage not collected') + '</div>' + hx('k-team-used') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + num(t.copilotLicensed) + ' / ' + num(t.people) + '</div><div class="l">Microsoft 365 Copilot licences</div><div class="d flat">' + (t.copilotUnknown ? num(t.copilotUnknown) + ' unconfirmed' : 'from the licence report') + '</div>' + hx('k-team-copilot') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (known ? num(t.sessions + t.chats + t.cowork) : '—') + '</div><div class="l">Sessions &amp; conversations</div><div class="d flat">' + (known ? num(t.sessions) + ' Claude Code · ' + num(t.chats) + ' chat · ' + num(t.cowork) + ' Cowork' : 'activity not collected') + '</div>' + hx('k-team-sessions') + '</div>' +
      '</div>' +
      (TEAM.viewerNote ? '<p class="note" style="margin-top:10px">' + esc(TEAM.viewerNote) + '</p>' : '') +
      (!known ? '<div class="callout" style="margin-top:10px">' + ic('alert') + '<div><b>Usage for ' + esc(TEAM.period.label) + ' is not available.</b> ' + esc(TEAM.period.note || '') + ' Access status below is still current.</div></div>' : '') +
      /* Spend and seat counts here come from different feeds on different
       * schedules, so the roll-up is only ever as current as its slowest one. */
      anthropicNote(TEAM.feeds, 'claudeCost', ['claudeActivity', 'claudeRoster', 'claudeLimits']);
    hydrate($('#ai-team-kpis'));
  }

  /* A person with no Claude seat has no spend — not zero spend. The footnote under
   * the table has always said so; the cell now agrees with it. */
  function spendCell(m) {
    if (m.usageState === 'no-access' || m.usageState === 'unavailable') return '<span class="dim">—</span>';
    return m.spend == null ? '<span class="dim">—</span>' : money(m.spend);
  }
  function accessCell(state, role) {
    if (state === 'active') return '<span class="chip green">Active</span>' + (role && role !== 'user' ? ' <span class="note">' + esc(role.replace(/_/g, ' ')) + '</span>' : '');
    if (state === 'licensed') return '<span class="chip green">Licensed</span>';
    if (state === 'none') return '<span class="chip">No access</span>';
    return '<span class="chip amber">Can’t confirm</span>';
  }
  function usageCell(m) {
    if (m.usageState === 'unavailable') return '<span class="chip amber">Not collected</span>';
    if (m.usageState === 'no-access') return '<span class="note">No Claude access</span>';
    if (m.usageState === 'no-usage') return '<span class="chip">No usage this period</span>';
    return '<span class="chip blue">' + num(m.activeDays) + ' active day' + (m.activeDays === 1 ? '' : 's') + '</span>' + (m.lastActivity ? ' <span class="note">last ' + esc(fmtMD(m.lastActivity)) + '</span>' : '');
  }

  function paintClaude() {
    var c = CLAUDE, cov = c.periodCoverage, acc = c.access && c.access.claude ? c.access.claude : null;
    var isSelf = c.subject.isSelf, name = subjectName(c);
    $('#claude-admin').hidden = !(ME && (ME.viewer ? ME.viewer.isSuperAdmin : ME.isSuperAdmin)) || !!aiDrill;
    /* On a drill-down the subject header above already states, in the largest
       type on the page, whose usage this is. Repeating it here in 11px is the
       kind of quiet second mention that let the old layout read as the viewer's
       own figures. The view-as banner still needs its copy. */
    paintSubjectCopy(c);
    paintDrillLimit(c);

    // A period the collector never covered has no numbers to draw. Rendering it as
    // zeroes would be a claim we cannot support, so the panes say so and stay empty.
    if (cov && !cov.zeroIsMeasured) {
      $('#claude-kpis').innerHTML = '<div class="callout">' + ic('alert') + '<div><b>No usage data for ' + esc(cov.label) + '.</b> ' + esc(cov.note || '') + '</div></div>';
      hydrate($('#claude-kpis'));
      ['#claude-chart', '#claude-mix', '#claude-activity', '#claude-recent'].forEach(function (sel) { $(sel).innerHTML = '<div class="empty">Not available for this period.</div>'; });
      if ($('#claude-cap-card')) $('#claude-cap-card').hidden = true;
      if ($('#claude-models-card')) $('#claude-models-card').hidden = true;
      return;
    }
    var banner = '';
    if (acc && acc.access === 'none') {
      banner = '<div class="callout" style="margin-bottom:12px">' + ic('info') + '<div><b>' + (isSelf ? 'You don\'t currently have Claude access.' : esc(name) + ' does not have Claude access.') +
        '</b> ' + (isSelf ? 'Anything below is historical usage only.' : 'Any figures below are historical usage only.') + '</div></div>';
    } else if (acc && acc.access === 'unavailable') {
      banner = '<div class="callout" style="margin-bottom:12px">' + ic('alert') + '<div>' + esc(CLAUDE_REASON[acc.reason] || 'Claude access could not be confirmed.') + '</div></div>';
    }
    var mom = c.momPct == null ? '<span class="d flat">no prior month</span>' : '<span class="d ' + (c.momPct > 0 ? 'down' : 'up') + '">' + pct(c.momPct) + ' vs last month' + (c.momBasis === 'same-span' ? ', same span' : '') + '</span>';
    // No seat and nothing recorded is not a measured zero — there is no meter to read.
    // A seat removed mid-month still shows its real figures, so this checks both.
    var noSeat = !!(acc && acc.access === 'none') && !c.requests && !c.spend;
    var dash = '<span class="dim">—</span>', why = '<div class="d flat">no Claude access</div>';
    $('#claude-kpis').innerHTML = banner + '<div class="kpi-row">' +
      '<div class="kpi hashelp"><div class="v">' + (noSeat ? dash : liveIf(c.feeds, 'claudeCost', 'Live from the Claude Enterprise Analytics API', true) + money(c.spend)) + '</div><div class="l">Spend ' + (c.isCurrent ? 'month to date' : 'for the month') + '</div>' + (noSeat ? why : mom) + '' + hx('k-spend') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (noSeat ? dash : (c.projectedMonthEnd != null ? money(c.projectedMonthEnd) : money(c.spend))) + '</div><div class="l">' + (noSeat ? 'Projected month end' : (c.projectedMonthEnd != null ? 'Projected month end' : 'Final')) + '</div>' + (noSeat ? why : '<div class="d flat">' + money(c.runRatePerDay) + ' / day</div>') + '' + hx('k-proj') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (noSeat ? dash : num(c.requests)) + '</div><div class="l">Requests</div>' + (noSeat ? why : '<div class="d flat">' + num(c.daysWithUsage) + ' active day' + (c.daysWithUsage === 1 ? '' : 's') + '</div>') + '' + hx('k-req') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (noSeat ? dash : compact(c.tokens.total)) + '</div><div class="l">Tokens</div>' + (noSeat ? why : '<div class="d flat">' + compact(c.tokens.output) + ' out · ' + (c.tokens.total ? Math.round(c.tokens.cacheRead / c.tokens.total * 100) : 0) + '% cache reads</div>') + '' + hx('k-tok') + '</div>' +
      '<div class="kpi hashelp"><div class="v">' + (noSeat ? dash : num(c.activity.ccSessions || 0)) + '</div><div class="l">Claude Code sessions</div>' + (noSeat ? why : '<div class="d flat">' + (c.activity.lastActivity ? 'last active ' + esc(fmtD(c.activity.lastActivity)) : 'no activity') + '</div>') + '' + hx('k-cc') + '</div>' +
      '</div><p class="note" style="margin-top:10px">' + (isSelf ? 'Only you and people authorized to report on you can see this.' : 'You are authorized to report on this person; the lookup is audited.') +
      ' Amounts are Anthropic usage charges, after any discount and before credits' + (c.subject.firstSeen ? ' · usage since ' + esc(fmtD(c.subject.firstSeen)) : '') + '.</p>'
      + anthropicNote(c.feeds, 'claudeCost', ['claudeActivity', 'claudeRoster', 'claudeLimits']);
    hydrate($('#claude-kpis'));
    areaChart($('#claude-chart'), c.series, {});
    var maxP = Math.max.apply(null, c.products.map(function (p) { return p.spend; }).concat([0.01]));
    var a = c.activity;
    var cells = [['Claude Code sessions', a.ccSessions, 'a-cc-sessions'], ['Commits', a.ccCommits, 'a-commits'], ['Pull requests', a.ccPrs, 'a-prs'], ['Lines added', a.locAdded, 'a-loc-added'], ['Lines removed', a.locRemoved, 'a-loc-removed'], ['Edits accepted', a.editsAccepted, 'a-edits-acc'], ['Edits rejected', a.editsRejected, 'a-edits-rej'], ['Cowork sessions', a.coworkSessions, 'a-cw-sessions'], ['Cowork file edits', a.coworkFileEdits, 'a-cw-edits'], ['Chat conversations', a.chatConversations, 'a-chat-conv'], ['Chat messages', a.chatMessages, 'a-chat-msgs'], ['Web searches', a.webSearches, 'a-web']];
    $('#claude-activity').innerHTML = noSeat ? '<div class="empty"><b>No Claude access</b>There is nothing to count for ' + esc(cov ? cov.label : 'this period') + '.</div>' : '<div class="actgrid">' + cells.map(function (x) { return '<div class="a"><div class="v">' + num(x[1] || 0) + '</div><div class="l">' + x[0] + ' ' + hx(x[2]) + '</div></div>'; }).join('') + '</div>' + /* Anthropic reports 0 rejections for this org, so accepted/(accepted+0) always read 100%: only show a rate once rejections are actually reported. */ (a.editsRejected > 0 ? '<p class="note" style="margin-top:8px">Edit acceptance ' + Math.round(a.editsAccepted / (a.editsAccepted + a.editsRejected) * 100) + '% this month.</p>' : '');
    $('#claude-recent').innerHTML = c.recent.length ? '<table class="tbl"><thead><tr><th>Day</th><th class="num">Spend</th><th class="num">Requests</th><th class="num">CC sessions</th><th class="num">Edits</th><th>Products</th></tr></thead><tbody>' + c.recent.map(function (r) { return '<tr><td class="mono">' + esc(r.day) + '</td><td class="num">' + money(r.spend) + '</td><td class="num">' + num(r.requests) + '</td><td class="num">' + num(r.ccSessions) + '</td><td class="num">' + num(r.edits) + '</td><td class="dim">' + esc((r.products || '').split(',').map(prodName).join(', ')) + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">' + (noSeat ? 'No Claude access, so no daily usage.' : 'No usage in the last 14 days.') + '</div>';
    /* This card answers for the person whose drill-down is open, not the org.
     * Per-product detail is whatever the Admin API actually reports for them; a
     * product with nothing reported gets no line rather than an invented one. */
    var subj = isSelf ? 'You' : (c.subject.displayName || c.subject.email);
    var DETAIL = {
      cowork: [['coworkSessions', 'session', 'sessions'], ['coworkActions', 'action', 'actions'], ['coworkFileEdits', 'file edit', 'file edits'], ['coworkMessages', 'message', 'messages']],
      chat: [['chatConversations', 'conversation', 'conversations'], ['chatMessages', 'message', 'messages'], ['chatArtifacts', 'artifact', 'artifacts']],
      claude_code: [['ccSessions', 'session', 'sessions'], ['editsAccepted', 'edit accepted', 'edits accepted'], ['ccCommits', 'commit', 'commits'], ['ccPrs', 'PR', 'PRs'], ['locAdded', 'line added', 'lines added']],
      claude_design: [['designSessions', 'session', 'sessions']],
      office: [['officeSessions', 'session', 'sessions']],
      research: [['scienceSessions', 'session', 'sessions']]
    };
    /* The whole reported column set for a product, zeros included -- once somebody
     * has opened the row, "0 pull requests" is an answer. Products whose full set is
     * already the summary line are not expandable: an empty disclosure is a dead control. */
    var FULL = {
      cowork: [['coworkSessions', 'Sessions', 'a-cw-sessions'], ['coworkActions', 'Actions', 'a-cw-actions'], ['coworkFileEdits', 'File edits', 'a-cw-edits'], ['coworkMessages', 'Messages', 'a-cw-msgs']],
      chat: [['chatConversations', 'Conversations', 'a-chat-conv'], ['chatMessages', 'Messages', 'a-chat-msgs'], ['chatArtifacts', 'Artifacts', 'a-chat-artifacts'], ['chatProjectsUsed', 'Projects used', 'a-chat-proj-used'], ['chatProjectsCreated', 'Projects created', 'a-chat-proj-new'], ['chatSkillsUsed', 'Skills used', 'a-chat-skills']],
      claude_code: [['ccSessions', 'Sessions', 'a-cc-sessions'], ['ccCommits', 'Commits', 'a-commits'], ['ccPrs', 'Pull requests', 'a-prs'], ['locAdded', 'Lines added', 'a-loc-added'], ['locRemoved', 'Lines removed', 'a-loc-removed'], ['editsAccepted', 'Edits accepted', 'a-edits-acc'], ['editsRejected', 'Edits rejected', 'a-edits-rej']]
    };
    function detail(p) {
      var d = DETAIL[p];
      if (!d) return '';
      return d.filter(function (x) { return (Number(a[x[0]]) || 0) > 0; })
        .map(function (x) { var v = Number(a[x[0]]); return num(v) + ' ' + (v === 1 ? x[1] : x[2]); })
        .join(' · ');
    }
    var pbody = c.products.length ? c.products.map(function (p, i) {
      var d = detail(p.product), full = FULL[p.product], pid = 'pmx-' + prodClass(p.product);
      var figs = '<span class="pmix-v">' + money(p.spend) + '</span>' +
        '<span class="pmix-p">' + share(p.spend, c.spend) + '</span>' +
        '<span class="pmix-r">' + num(p.requests) + ' req</span>';
      var nm = '<span class="pmix-name"><i class="pdot ' + prodClass(p.product) + '"></i>' + esc(prodName(p.product)) +
        (full ? '<span class="pmix-chev">' + ic('chevron-right') + '</span>' : '') + '</span>';
      var top = full
        ? '<button class="pmix-top" type="button" aria-expanded="false" aria-controls="' + pid + '">' + nm + figs + '</button>'
        : '<div class="pmix-top">' + nm + figs + '</div>';
      var more = full ? '<div class="pmix-more" id="' + pid + '"><div class="pmix-more-in"><div class="pmix-stats">' +
        full.map(function (x) { return '<div class="s"><div class="v">' + num(Number(a[x[0]]) || 0) + '</div><div class="l">' + x[1] + ' ' + hx(x[2]) + '</div></div>'; }).join('') +
        '</div></div></div>' : '';
      return '<div class="pmix-row">' + top +
        '<div class="pmix-track"><span data-w="' + (p.spend / maxP * 100).toFixed(1) + '" style="transition-delay:' + Math.min(i * 40, 200) + 'ms"></span></div>' +
        (d ? '<div class="pmix-sub">' + d + '</div>' : '') + more + '</div>';
    }).join('') : '<div class="empty">' + (acc && acc.access === 'none' ? 'No Claude access, so no product usage.' : 'No product usage this month.') + '</div>';

    var T = c.tokens || {};
    var tok = Number(T.total) > 0 ? '<div class="pmix-tok"><span class="pmix-tok-l">Tokens</span>' +
      '<span><b>' + compact(T.total) + '</b> total</span>' +
      '<span><b>' + compact(T.cacheRead) + '</b> cache read, ' + share(T.cacheRead, T.total) + '</span>' +
      '<span><b>' + compact(T.cacheCreated) + '</b> cache write</span>' +
      '<span><b>' + compact(T.output) + '</b> output</span>' +
      (Number(T.webSearches) > 0 ? '<span><b>' + num(T.webSearches) + '</b> web searches</span>' : '') + '</div>' : '';

    $('#claude-mix').innerHTML =
      '<div class="pmix-hd"><span>' + esc(subj) + ' · ' + esc(AI.period.label) + '</span>' +
      '<span class="pmix-tot"><b>' + money(c.spend) + '</b> · ' + num(c.requests) + ' requests · ' +
      num(c.products.length) + ' product' + (c.products.length === 1 ? '' : 's') + '</span></div>' + pbody + tok;
    // Width is applied after insertion so each bar transitions in from zero instead
    // of being painted at its final length.
    hydrate($('#claude-mix'));
    requestAnimationFrame(function () {
      $$('#claude-mix .pmix-track > span').forEach(function (s) { s.style.width = s.getAttribute('data-w') + '%'; });
    });
    $$('#claude-mix .pmix-top[aria-controls]').forEach(function (b) {
      b.addEventListener('click', function () {
        var open = b.getAttribute('aria-expanded') === 'true';
        b.setAttribute('aria-expanded', open ? 'false' : 'true');
        var panel = document.getElementById(b.getAttribute('aria-controls'));
        if (panel) panel.toggleAttribute('data-open', !open);
      });
    });
    paintModels(c);
    paintCap(c);
  }

  /* ───────────── FAVORITES ───────────── */
  var dragState = null;
  function paintFavorites() {
    var bar = $('#pinbar'), links = PINS.links;
    $('#fav-count').textContent = links.length ? links.length + ' pinned' : (PINS.fromAdminDefaults ? 'Using Hub defaults · pin something to make it yours' : 'Nothing pinned');
    bar.innerHTML = links.length ? links.map(function (l, i) {
      return '<div class="pin" draggable="false" data-id="' + esc(l.id) + '" tabindex="0" aria-label="' + esc(l.title) + ', position ' + (i + 1) + '"><span class="ord">' + (i + 1) + '</span><div class="tools"><button data-mv="-1" title="Move left" aria-label="Move left">' + ic('left') + '</button><button data-mv="1" title="Move right" aria-label="Move right">' + ic('right') + '</button><button data-rm="1" title="Remove" aria-label="Remove">' + ic('x') + '</button></div>' + tileIcon(l, 'sq') + '<b>' + esc(l.title) + '</b><span class="host">' + esc(HOST_LABEL[l.host] || domain(l.url)) + '</span></div>';
    }).join('') : '<div class="empty" style="width:100%"><b>Your bar is empty</b>' + (PINS.fallback.length ? 'The Hub is showing its defaults (' + esc(PINS.fallback.map(function (f) { return f.title; }).join(', ')) + '). Pin tools below to replace them.' : 'Pin tools below.') + '</div>';
    $$('.pin', bar).forEach(function (p) {
      p.addEventListener('pointerdown', onPinDown);
      p.addEventListener('keydown', function (e) { var i = PINS.pins.indexOf(p.getAttribute('data-id')); if (e.key === 'ArrowLeft' && i > 0) { e.preventDefault(); movePin(i, i - 1, true); } if (e.key === 'ArrowRight' && i < PINS.pins.length - 1) { e.preventDefault(); movePin(i, i + 1, true); } if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); togglePin(p.getAttribute('data-id')); } });
      $$('[data-mv]', p).forEach(function (b) { b.addEventListener('pointerdown', function (e) { e.stopPropagation(); }); b.addEventListener('click', function (e) { e.stopPropagation(); var i = PINS.pins.indexOf(p.getAttribute('data-id')); movePin(i, i + Number(b.getAttribute('data-mv')), true); }); });
      var rm = $('[data-rm]', p); rm.addEventListener('pointerdown', function (e) { e.stopPropagation(); }); rm.addEventListener('click', function (e) { e.stopPropagation(); togglePin(p.getAttribute('data-id')); });
    });
    loadHub().then(paintHubGrid);
  }
  function movePin(from, to, focus) {
    if (to < 0 || to >= PINS.pins.length || from === to) return;
    var pins = PINS.pins.slice(); var id = pins.splice(from, 1)[0]; pins.splice(to, 0, id);
    commitPins(pins, function () { if (focus) { var el = $('.pin[data-id="' + id + '"]'); if (el) el.focus(); } });
  }
  function commitPins(pins, after) {
    flip($('#pinbar'), function () { PINS.pins = pins; PINS.links = pins.map(function (id) { return HUB ? HUB.links.find(function (l) { return l.id === id; }) : PINS.links.find(function (l) { return l.id === id; }); }).filter(Boolean); paintFavorites(); if (after) after(); });
    api('PUT', '/pins', { pins: pins }).then(function (r) { PINS.pins = r.pins; PINS.links = r.links; PINS.fromAdminDefaults = false; toast('Favorites saved'); if (loaded.overview) { paintOvFav(); paintRail(); } }).catch(function (e) { toast(e.message, true); loadPins().then(paintFavorites); });
  }
  function flip(container, mutate) {
    var before = {}; $$('.pin', container).forEach(function (p) { before[p.getAttribute('data-id')] = p.getBoundingClientRect(); });
    mutate();
    if (document.documentElement.getAttribute('data-reduce-motion') === 'on' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    $$('.pin', container).forEach(function (p) {
      var b = before[p.getAttribute('data-id')]; if (!b) return; var a = p.getBoundingClientRect(); var dx = b.left - a.left, dy = b.top - a.top; if (!dx && !dy) return;
      p.style.transition = 'none'; p.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
      requestAnimationFrame(function () { p.style.transition = ''; p.style.transform = ''; });
    });
  }
  function onPinDown(e) {
    if (e.button !== 0) return;
    var el = e.currentTarget; el.setPointerCapture(e.pointerId);
    dragState = { el: el, id: el.getAttribute('data-id'), x0: e.clientX, y0: e.clientY, moved: false };
    var onMove = function (ev) {
      if (!dragState) return;
      var dx = ev.clientX - dragState.x0, dy = ev.clientY - dragState.y0;
      if (!dragState.moved && Math.hypot(dx, dy) < 6) return;
      dragState.moved = true; el.classList.add('drag'); el.style.transform = 'translate(' + dx + 'px,' + dy + 'px) scale(1.04)';
      var over = document.elementFromPoint(ev.clientX, ev.clientY), target = over && over.closest ? over.closest('.pin') : null;
      if (target && target !== el) {
        var pins = PINS.pins.slice(), from = pins.indexOf(dragState.id), to = pins.indexOf(target.getAttribute('data-id'));
        if (from >= 0 && to >= 0 && from !== to) {
          pins.splice(from, 1); pins.splice(to, 0, dragState.id);
          var before = {}; $$('.pin').forEach(function (p) { if (p !== el) before[p.getAttribute('data-id')] = p.getBoundingClientRect(); });
          PINS.pins = pins; var bar = $('#pinbar'); pins.forEach(function (id) { var n = $('.pin[data-id="' + id + '"]', bar); if (n) bar.appendChild(n); });
          $$('.pin').forEach(function (p, i) { $('.ord', p).textContent = i + 1; if (p === el) return; var b = before[p.getAttribute('data-id')], a = p.getBoundingClientRect(); var ddx = b.left - a.left, ddy = b.top - a.top; if (!ddx && !ddy) return; p.style.transition = 'none'; p.style.transform = 'translate(' + ddx + 'px,' + ddy + 'px)'; requestAnimationFrame(function () { p.style.transition = ''; p.style.transform = ''; }); });
          // The dragged tile now sits in its new slot: re-anchor to the pointer so it keeps following from there.
          dragState.x0 = ev.clientX; dragState.y0 = ev.clientY; el.style.transform = 'translate(0,0) scale(1.04)';
        }
      }
    };
    var onUp = function () {
      el.removeEventListener('pointermove', onMove); el.removeEventListener('pointerup', onUp); el.removeEventListener('pointercancel', onUp);
      el.classList.remove('drag'); el.style.transform = '';
      var moved = dragState && dragState.moved; dragState = null;
      if (moved) { PINS.links = PINS.pins.map(function (id) { return PINS.links.find(function (l) { return l.id === id; }); }).filter(Boolean); api('PUT', '/pins', { pins: PINS.pins }).then(function (r) { PINS.pins = r.pins; PINS.links = r.links; PINS.fromAdminDefaults = false; paintFavorites(); toast('Favorites saved'); if (loaded.overview) { paintOvFav(); paintRail(); } }).catch(function (er) { toast(er.message, true); loadPins().then(paintFavorites); }); }
    };
    el.addEventListener('pointermove', onMove); el.addEventListener('pointerup', onUp); el.addEventListener('pointercancel', onUp);
  }
  function togglePin(id) {
    api('POST', '/pins/toggle', { id: id }).then(function (r) { PINS.pins = r.pins; PINS.links = r.links; PINS.fromAdminDefaults = false; paintFavorites(); toast(r.pinned ? 'Pinned' : 'Unpinned'); if (loaded.overview) { paintOvFav(); paintRail(); } }).catch(function (e) { toast(e.message, true); });
  }
  function paintHubGrid() {
    var q = ($('#hub-filter').value || '').trim().toLowerCase(), el = $('#hubgrid');
    var pinned = new Set(PINS.pins);
    el.innerHTML = HUB.sections.map(function (s) {
      var links = HUB.links.filter(function (l) { return l.sectionId === s.id && (!q || (l.title + ' ' + l.description).toLowerCase().indexOf(q) >= 0); });
      if (!links.length) return '';
      return '<div class="sec-lbl" style="margin-top:12px">' + esc(s.name) + '</div><div class="hubgrid">' + links.map(function (l) {
        return '<div class="hubtile">' + tileIcon(l, 'sq') + '<div class="txt"><b>' + esc(l.title) + '</b><span>' + esc(l.description || domain(l.url)) + '</span></div><button class="star" aria-pressed="' + pinned.has(l.id) + '" data-id="' + esc(l.id) + '" title="' + (pinned.has(l.id) ? 'Unpin' : 'Pin to favorites') + '" aria-label="' + (pinned.has(l.id) ? 'Unpin ' : 'Pin ') + esc(l.title) + '">' + ic('star') + '</button></div>';
      }).join('') + '</div>';
    }).join('') || '<div class="empty">No tools match.</div>';
    $$('.star', el).forEach(function (b) { b.addEventListener('click', function () { togglePin(b.getAttribute('data-id')); }); });
  }
  $('#hub-filter').addEventListener('input', function () { if (HUB) paintHubGrid(); });

  /* ───────────── MY ACCESS ───────────── */
  /* Every page the subject can open, as launch tiles. The list is the server's
   * answer from the real gates (site policy + the access matrix), never a copy of
   * the Hub: a tile here means the link will open, and the chip says how far in.
   * Sites are only known for the signed-in viewer (they come from the session's
   * group claims), so a borrowed view says so rather than showing yours. */
  function loadAccess(force) { if (ACCESS && !force) return Promise.resolve(ACCESS); return api('GET', '/my-access').then(function (a) { ACCESS = a; return a; }); }
  var PLATFORM_HOSTS = { corpit: 1, reporting: 1, accessportal: 1, itam: 1, subadmin: 1 };
  /* A page on one of our vhosts is only reachable if the site itself lets the
   * viewer in. With the site list unknown (a borrowed view) nothing is refused. */
  function accessAllowedHost(t) {
    if (!ACCESS.sites || !PLATFORM_HOSTS[t.host]) return true;
    return ACCESS.sites.some(function (s) { return s.family === t.host; });
  }
  function levelChip(t) {
    if (t.gate === 'page') return '<span class="lv ' + esc(t.level) + '" title="Your level in the access matrix">' + esc(t.level) + '</span>';
    if (t.gate === 'authenticated') return '<span class="lv open" title="Open to everyone signed in">signed in</span>';
    if (t.host === 'external') return '<span class="lv open" title="Not gated by CorpIT">external</span>';
    return '<span class="lv open" title="No matrix entry: opens for anyone allowed onto that site">site</span>';
  }
  function paintAccess() {
    var a = ACCESS, q = ($('#acc-filter').value || '').trim().toLowerCase();
    var sc = $('#acc-sites'), sn = $('#acc-sites-note');
    if (a.sites) {
      sn.textContent = a.sites.length + ' site' + (a.sites.length === 1 ? '' : 's') + ' · decided by your AD groups';
      sc.innerHTML = a.sites.length ? '<div class="site-tiles">' + a.sites.map(function (s) {
        var cur = s.host === a.currentHost;
        return '<a class="hubtile launch" href="' + esc(s.url) + '"' + (cur ? '' : ' target="_blank" rel="noopener noreferrer"') + '>'
          + '<span class="sq t-blue">' + ic('globe') + '</span><div class="txt"><b>' + esc(s.label && s.label !== s.host ? s.label : (HOST_LABEL[s.family] || s.host)) + '</b><span>' + esc(s.host) + (cur ? ' · you are here' : '') + '</span></div>'
          + ic(cur ? 'check-circle' : 'external', 'tail') + '</a>';
      }).join('') + '</div>' : '<div class="empty"><b>No site policy matched</b>Your session carries no group that opens a site.</div>';
    } else {
      sn.textContent = '';
      sc.innerHTML = a.sitesReason === 'view-as'
        ? '<div class="empty"><b>Not shown in a borrowed view</b>Site access is decided from the signed-in session’s AD groups, which are yours, not ' + esc(a.subject) + '’s.</div>'
        : '<div class="empty"><b>Not available for this session</b>This sign-in carries no group claims. Sign out and back in to refresh them.</div>';
    }
    var tiles = a.tiles.filter(accessAllowedHost);
    var shown = tiles.filter(function (t) { return !q || (t.title + ' ' + (t.description || '') + ' ' + t.url).toLowerCase().indexOf(q) >= 0; });
    $('#acc-count').textContent = (q ? shown.length + ' of ' + tiles.length : tiles.length + ' page' + (tiles.length === 1 ? '' : 's')) + (a.viewingAs ? ' · for ' + a.subject : '');
    $('#acc-pages').innerHTML = (a.sections.map(function (s) {
      var links = shown.filter(function (t) { return t.sectionId === s.id; });
      if (!links.length) return '';
      return '<div class="sec-lbl" style="margin-top:12px">' + esc(s.name) + '</div><div class="hubgrid">' + links.map(function (t) {
        return '<a class="hubtile launch" href="' + esc(safeHref(t.url)) + '"' + targetAttr(t) + ' data-link="' + esc(t.id) + '" title="' + esc(t.description || t.url) + '">'
          + tileIcon(t, 'sq') + '<div class="txt"><b>' + esc(t.title) + '</b><span>' + esc(t.description || HOST_LABEL[t.host] || domain(t.url)) + '</span></div>' + levelChip(t) + '</a>';
      }).join('') + '</div>';
    }).join('') || '<div class="empty">' + (q ? 'No pages match.' : '<b>No pages</b>Nothing in the access matrix is granted to ' + (a.viewingAs ? esc(a.subject) : 'you') + '.') + '</div>')
      + '<p class="note" style="margin-top:12px">Levels come from the access matrix: roles from Active Directory groups plus any per-person override. '
      + '<b>site</b> means the page has no matrix entry and opens for anyone allowed onto that site.'
      + (a.sites ? ' Pages on a site you cannot enter are not listed.' : '') + '</p>';
    $$('#acc-pages a.hubtile').forEach(function (el) {
      el.addEventListener('click', function () { var t = a.tiles.find(function (x) { return x.id === el.getAttribute('data-link'); }); if (t) recordOpen(t); });
    });
  }
  $('#acc-filter').addEventListener('input', function () { if (ACCESS) paintAccess(); });

  /* ───────────── ACTIVITY & STATS ───────────── */
  function paintStats() {
    var s = STATS, w = s.tickets, c = s.claude || {};
    $('#st-kpis').innerHTML = [
      ['Actions this week', s.totals.events7], ['Actions · 30 days', s.totals.events30], ['Tickets closed · 30 days', w ? w.closed30 : '—'], ['Tickets closed · 90 days', w ? w.closed90 : '—'], ['Claude Code sessions · 30 days', c.ccSessions || 0], ['Active AI days · 30 days', c.activeDays || 0]
    ].map(function (k) { return '<div class="kpi"><div class="v">' + (typeof k[1] === 'number' ? num(k[1]) : k[1]) + '</div><div class="l">' + k[0] + '</div></div>'; }).join('');
    var max = Math.max.apply(null, s.actions.map(function (a) { return a.count; }).concat([1]));
    $('#st-actions').innerHTML = s.actions.length ? '<div class="rank">' + s.actions.slice(0, 8).map(function (a) { return '<div class="r"><span>' + esc(a.label) + '</span><div class="track"><span style="width:' + (a.count / max * 100).toFixed(1) + '%"></span></div><span class="n">' + num(a.count) + '</span></div>'; }).join('') + '</div><p class="note" style="margin-top:10px">What you do most: <b>' + esc(s.actions[0].label.toLowerCase()) + '</b>' + (s.actions[1] ? ', then ' + esc(s.actions[1].label.toLowerCase()) : '') + '.</p>' : '<div class="empty"><b>No actions yet</b>Use the Hub and CorpIT tools; a picture forms within a few days.</div>';
    var mt = Math.max.apply(null, s.tools.map(function (t) { return t.count; }).concat([1]));
    $('#st-tools').innerHTML = s.tools.length ? '<div class="rank">' + s.tools.map(function (t) { return '<div class="r"><span title="' + esc(t.label) + '">' + esc(t.label || t.id) + '</span><div class="track"><span style="width:' + (t.count / mt * 100).toFixed(1) + '%"></span></div><span class="n">' + num(t.count) + '</span></div>'; }).join('') + '</div>' : '<div class="empty"><b>No tool opens recorded</b>Opening tiles on the Hub records them here.</div>';
    var weeks = []; var d = new Date(); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); for (var i = 11; i >= 0; i--) { var w0 = new Date(d.getTime() - i * 7 * 864e5); var key = w0.toISOString().slice(0, 10); var f = s.weekly.find(function (x) { return x.week === key; }); weeks.push({ week: key, count: f ? f.count : 0 }); }
    var mw = Math.max.apply(null, weeks.map(function (x) { return x.count; }).concat([1]));
    $('#st-weekly').innerHTML = '<div style="display:flex;align-items:flex-end;gap:5px;height:110px">' + weeks.map(function (x) { return '<div title="Week of ' + esc(x.week) + ': ' + x.count + '" style="flex:1;height:' + Math.max(3, x.count / mw * 100) + '%;background:var(--pblue);opacity:' + (x.count ? .9 : .25) + ';border-radius:4px 4px 2px 2px"></div>'; }).join('') + '</div><div style="display:flex;justify-content:space-between" class="note"><span>' + esc(weeks[0].week) + '</span><span>this week</span></div>' + (s.security.length ? '<div class="sec-lbl" style="margin-top:14px">Access &amp; security · 30 days</div><div class="chips">' + s.security.map(function (a) { return '<span class="chip">' + esc(a.label) + ' <span class="mono" style="opacity:.75">' + num(a.count) + '</span></span>'; }).join('') + '</div>' : '');
  }
  var trailKind = '', trailDays = 90;
  function loadTrail() {
    var el = $('#act-trail'); el.innerHTML = '<div class="empty">Loading…</div>';
    api('GET', '/activity?limit=200&days=' + trailDays + (trailKind ? '&kind=' + trailKind : '')).then(function (a) {
      if (!a.items.length) { el.innerHTML = '<div class="empty"><b>Nothing in this window</b>Try a longer range or a different filter.</div>'; return; }
      var html = '', lastDay = '';
      a.items.forEach(function (e) {
        var day = fmtDay(e.at); if (day !== lastDay) { html += '<div class="day">' + esc(day) + '</div>'; lastDay = day; }
        var meta = e.kind === 'security' ? (e.ip ? 'from ' + esc(e.ip) : 'security') : e.kind === 'signin' ? (e.ip ? esc(e.ip) : 'Microsoft') : (e.source ? esc(e.source) : '');
        html += '<div class="ev ' + esc(e.kind) + (e.ok === false ? ' fail' : '') + '"><span class="tm">' + esc(fmtT(e.at)) + '</span>' + ic(evIcon(e)) + '<span class="tx">' + (e.url ? '<a href="' + esc(safeHref(e.url)) + '"' + (e.url.startsWith('/') ? '' : ' target="_blank" rel="noopener"') + '>' + esc(e.text) + '</a>' : esc(e.text)) + '</span><span class="meta">' + meta + '</span></div>';
      });
      el.innerHTML = html + '<p class="note" style="margin-top:12px">Actions are recorded by CorpIT pages; access events come from the platform security log; sign-ins are synced from Entra ID. Tools still on ITAM are not included yet.</p>';
    }).catch(function (e) { el.innerHTML = errBox(e); });
  }
  $$('#act-kind button').forEach(function (b) { b.addEventListener('click', function () { $$('#act-kind button').forEach(function (x) { x.classList.toggle('on', x === b); }); trailKind = b.getAttribute('data-v'); loadTrail(); }); });
  $('#act-days').addEventListener('change', function () { trailDays = Number(this.value); loadTrail(); });

  /* ───────────── SUGGESTIONS (feature ideas) ───────────── */
  var sgScope = 'mine';
  function fillAreas() {
    loadHub().then(function (hub) { var sel = $('#sg-area'); if (sel.options.length > 1) return; hub.links.forEach(function (l) { sel.appendChild(new Option(l.title, l.title)); }); sel.appendChild(new Option('My Profile', 'My Profile')); });
  }
  function paintSugg() {
    var s = SUGG, el = $('#sg-list');
    // The email notice was hard-coded into the markup and promised a mail
    // this host could not send. It now states only what the API reports.
    var mn = $('#sg-mailnote');
    if (mn) mn.textContent = 'Status is set by a CorpIT super-admin.' + (s.mail
      ? ' You will get an email when it changes (turn this off under Notifications).'
      : ' Email notices are not configured on this host, so check back here for changes.');
    $('#sg-n-mine').textContent = s.counts.mine; $('#sg-n-all').textContent = s.counts.total;
    el.innerHTML = s.items.length ? s.items.map(function (x) {
      var adm = s.canModerate ? '<div class="adm"><select class="sel" data-st="' + x.id + '">' + s.statuses.map(function (st) { return '<option' + (st === x.status ? ' selected' : '') + '>' + st + '</option>'; }).join('') + '</select><input class="inp" data-note="' + x.id + '" placeholder="Note to the author (optional)" value="' + esc(x.adminNote || '') + '" style="flex:1;min-width:180px"><button class="btn sm" data-save="' + x.id + '">Update</button></div>' : '';
      return '<div class="sg" data-id="' + x.id + '"><button class="vote" aria-pressed="' + x.voted + '" data-vote="' + x.id + '" title="' + (x.voted ? 'Remove your vote' : 'Upvote') + '">' + ic('up') + num(x.votes) + '</button><div style="min-width:0"><div class="h"><b>' + esc(x.title) + '</b><span class="chip st-' + esc(x.status) + '">' + esc(x.status) + '</span>' + (x.area ? '<span class="chip">' + esc(x.area) + '</span>' : '') + (x.mine ? '<span class="chip green">yours</span>' : '') + '</div><div class="p">' + esc(x.details) + '</div>' + (x.adminNote ? '<div class="callout info" style="margin-top:8px">' + ic('info') + '<div><b>From CorpIT:</b> ' + esc(x.adminNote) + '</div></div>' : '') + '<div class="f"><span>' + esc(x.authorName) + ' · ' + esc(rel(x.createdAt)) + '</span>' + (x.statusChangedAt ? '<span>status set ' + esc(rel(x.statusChangedAt)) + '</span>' : '') + (x.mine && x.status === 'new' ? '<button class="btn sm ghost" data-del="' + x.id + '" style="color:var(--red)">Withdraw</button>' : '') + '</div>' + adm + '</div></div>';
    }).join('') : '<div class="empty"><b>' + (sgScope === 'mine' ? 'You have not submitted an idea yet' : 'No ideas yet') + '</b>' + (sgScope === 'mine' ? 'Use the form to suggest one.' : 'Be the first.') + '</div>';
    $$('[data-vote]', el).forEach(function (b) { b.addEventListener('click', function () { api('POST', '/suggestions/' + b.getAttribute('data-vote') + '/vote').then(function (r) { b.setAttribute('aria-pressed', r.voted); b.innerHTML = ic('up') + num(r.votes); }).catch(function (e) { toast(e.message, true); }); }); });
    $$('[data-del]', el).forEach(function (b) { b.addEventListener('click', function () { if (!confirm('Withdraw this suggestion?')) return; api('DELETE', '/suggestions/' + b.getAttribute('data-del')).then(function () { toast('Withdrawn'); return loadSugg(sgScope); }).then(paintSugg).catch(function (e) { toast(e.message, true); }); }); });
    $$('[data-save]', el).forEach(function (b) { b.addEventListener('click', function () { var id = b.getAttribute('data-save'); api('PATCH', '/suggestions/' + id, { status: $('[data-st="' + id + '"]').value, admin_note: $('[data-note="' + id + '"]').value }).then(function (r) { toast('Updated' + (r.notified ? ' · author emailed' : '')); return loadSugg(sgScope); }).then(paintSugg).catch(function (e) { toast(e.message, true); }); }); });
  }
  $$('#sg-tabs button').forEach(function (b) { b.addEventListener('click', function () { $$('#sg-tabs button').forEach(function (x) { x.classList.toggle('on', x === b); }); sgScope = b.getAttribute('data-v'); loadSugg(sgScope).then(paintSugg); }); });
  var draftT;
  function draftBody() { return { title: $('#sg-title').value, area: $('#sg-area').value, details: $('#sg-details').value }; }
  function saveDraft() { var d = draftBody(); if (!d.title && !d.details) return; clearTimeout(draftT); draftT = setTimeout(function () { api('PUT', '/drafts/suggestion:new', { title: d.title || 'Untitled idea', body: d, source: 'my-profile' }).then(function () { $('#sg-draft').textContent = 'Draft saved ' + fmtT(new Date().toISOString()); }).catch(function () {}); }, 900); }
  function restoreDraft() { api('GET', '/drafts/suggestion:new').then(function (d) { var b = d.body || {}; if (!$('#sg-title').value && !$('#sg-details').value) { $('#sg-title').value = b.title || ''; $('#sg-details').value = b.details || ''; if (b.area) { loadHub().then(function () { $('#sg-area').value = b.area; }); } $('#sg-draft').textContent = 'Draft restored from ' + rel(d.updated_at); } }).catch(function () {}); }
  ['#sg-title', '#sg-details'].forEach(function (s) { $(s).addEventListener('input', saveDraft); });
  $('#sg-area').addEventListener('change', saveDraft);
  $('#sg-clear').addEventListener('click', function () { $('#sg-title').value = ''; $('#sg-details').value = ''; $('#sg-draft').textContent = ''; api('DELETE', '/drafts/suggestion:new').catch(function () {}); });
  $('#sg-form').addEventListener('submit', function (e) {
    e.preventDefault(); var d = draftBody(), b = $('#sg-submit');
    if (d.title.trim().length < 4 || d.details.trim().length < 10) { toast('Add a title (4+ characters) and some details (10+)', true); return; }
    b.disabled = true;
    api('POST', '/suggestions', d).then(function () { toast('Idea submitted'); $('#sg-title').value = ''; $('#sg-details').value = ''; $('#sg-draft').textContent = ''; sgScope = 'mine'; $$('#sg-tabs button').forEach(function (x) { x.classList.toggle('on', x.getAttribute('data-v') === 'mine'); }); return loadSugg('mine'); }).then(function () { paintSugg(); paintRail(); }).catch(function (er) { toast(er.message, true); }).then(function () { b.disabled = false; });
  });

  /* ───────────── CHANGES ───────────── */
  var chKind = '', seenT;
  function paintChanges() {
    var c = CHANGES;
    $('#ch-version').textContent = c.version ? 'CorpIT v' + c.version : '';
    var HL = { corpit: 'On CorpIT', itam: 'Still on ITAM', reporting: 'On Reporting', accessportal: 'Access Portal', subadmin: 'Admin console', external: 'External', unknown: 'Unknown' };
    $('#ch-hosts').innerHTML = Object.keys(c.hosts).sort(function (a, b) { return c.hosts[b] - c.hosts[a]; }).map(function (h) { return '<div class="h"><div class="v">' + num(c.hosts[h]) + '</div><div class="l"><span class="tag-host ' + esc(h) + '">' + esc(HL[h] || h) + '</span></div></div>'; }).join('');
    $('#ch-tiles').innerHTML = '<table class="tbl"><thead><tr><th>Tool</th><th>Section</th><th>Where it runs</th><th></th></tr></thead><tbody>' + c.tiles.map(function (t) {
      return '<tr><td><b>' + esc(t.title) + '</b></td><td class="dim">' + esc(t.section) + '</td><td><span class="tag-host ' + esc(t.host) + '">' + esc(t.status) + '</span> <span class="mono dim" style="font-size:11px">' + esc(domain(t.url) || 'corpit.nrpi.local') + '</span></td><td style="text-align:right"><a href="' + esc(safeHref(t.url)) + '"' + (t.host === 'corpit' ? '' : ' target="_blank" rel="noopener"') + ' style="color:var(--pblue);font-weight:500">Open</a></td></tr>';
    }).join('') + '</tbody></table>' + (c.generated ? '<p class="note" style="margin-top:8px">Tile list published from the admin console ' + esc(rel(c.generated)) + '.</p>' : '');
    var notes = c.notes.filter(function (n) { return !chKind || n.kind === chKind; });
    $('#ch-notes').innerHTML = notes.length ? notes.map(function (n) {
      return '<div class="nt"><div class="k"><span class="chip k-' + esc(n.kind) + '">' + esc(n.kind) + '</span><span class="when">' + esc(n.effectiveOn || '') + '</span></div><div><b>' + (n.unseen ? '<span class="new" title="New since your last visit"></span>' : '') + esc(n.title) + (n.link ? ' <a href="' + esc(safeHref(n.link)) + '"' + (n.link.startsWith('/') ? '' : ' target="_blank" rel="noopener"') + ' title="Open">' + ic('external') + '</a>' : '') + '</b><p>' + esc(n.detail) + '</p>' + (n.itamState || n.corpitState ? '<div class="was"><div><em>ITAM</em>' + esc(n.itamState || '—') + '</div><div><em>CorpIT</em>' + esc(n.corpitState || '—') + '</div></div>' : '') + '</div></div>';
    }).join('') : '<div class="empty">No notes of this kind.</div>';
  }
  function markChangesSeenSoon() { clearTimeout(seenT); seenT = setTimeout(function () { api('POST', '/changes/seen').then(function () { CHANGES.notes.forEach(function (n) { n.unseen = false; }); paintRail(); }).catch(function () {}); }, 4000); }
  $$('#ch-kind button').forEach(function (b) { b.addEventListener('click', function () { $$('#ch-kind button').forEach(function (x) { x.classList.toggle('on', x === b); }); chKind = b.getAttribute('data-v'); if (CHANGES) paintChanges(); }); });
  $('#ch-seen').addEventListener('click', function () { api('POST', '/changes/seen').then(function () { CHANGES = null; return loadChanges(); }).then(function () { paintChanges(); paintRail(); toast('Marked as seen'); }).catch(function (e) { toast(e.message, true); }); });

  /* settings sub-nav follows the scroll position (a position indicator, so no motion) */
  (function scrollSpy() {
    var links = $$('#subnav a'); if (!links.length) return;
    var ids = links.map(function (a) { return a.getAttribute('href').split('/')[1]; });
    var t;
    window.addEventListener('scroll', function () {
      if (!$('#v-profile').classList.contains('on')) return;
      clearTimeout(t); t = setTimeout(function () {
        var cur = ids[0];
        ids.forEach(function (id) { var el = $('#s-' + id); if (el && el.getBoundingClientRect().top <= 90) cur = id; });
        links.forEach(function (a) { a.classList.toggle('on', a.getAttribute('href') === '#profile/' + cur); });
      }, 60);
    }, { passive: true });
  })();

  /* ───────────── boot ───────────── */
  /* The sidebar's three Hub links are written as href="/" in the markup. Off
   * corpit that is whatever this vhost serves at / -- on reporting, the page you
   * are already on. Rewrite them to the real Hub, then hand every Hub-bound link
   * on the page (these and the ones painted later from the API) to one delegated
   * guard: site access is per-vhost by AD group, and someone who belongs here
   * may not belong there. A click we know would be refused is cancelled and they
   * stay put rather than taking a sign-in round trip to a 403. */
  if (window.ITHubLink && !window.ITHubLink.isHome) {
    ['.nav-item[data-nav="hub"]', '.back-btn'].forEach(function (sel) {
      $$(sel).forEach(function (el) { window.ITHubLink.wire(el, 'You do not have access to the CorpIT Hub'); });
    });
    window.ITHubLink.guardDocument();
  }

  /* ───────────── how current the Anthropic figures are ─────────────
   *
   * THREE CLOCKS, and the page used to show at most one of them.
   *
   *   dataAsOf  Anthropic's OWN watermark (data_refreshed_at on their response).
   *             How current ANTHROPIC says the numbers were. Routinely hours
   *             behind the pull, and it is the one a person actually means when
   *             they ask "is this current?".
   *   asOf      when WE last pulled successfully. Not the same question. A pull
   *             a minute ago can still be carrying four-hour-old figures, and
   *             labelling the pull time as "data current as of" is exactly how
   *             that gets missed.
   *   cadence   how often the feed lands, MEASURED from its own run history in
   *             ai-tools-lib.js, plus the window the next one is expected in.
   *
   * The page previously carried the literal sentence "refreshed hourly". It was
   * true of spend and limits and FALSE of activity -- the hourly cron passes
   * --skip-activity, so user_activity_daily only lands at 05:40 and 13:25. A
   * hard-coded cadence is also unmaintainable from here: the schedule is in
   * root's crontab, which neither this file nor the API can read, so it would
   * start lying the moment anyone edited it and nothing would notice.
   *
   * ONE renderer, used by every surface that shows an Anthropic number. Two
   * renderers is how the team card and the drill-down end up claiming different
   * things about the same feed.
   */
  var FEED_LABEL = {
    claudeCost: 'Spend',
    claudeActivity: 'Sessions & activity',
    claudeRoster: 'Seats & roles',
    claudeLimits: 'Spend limits',
  };

  /* Time only when it lands today, date + time otherwise -- "next around 5:40 AM"
   * is ambiguous when the window crosses midnight, which the activity feed's
   * does every single day. */
  function fmtWhenSmart(iso) {
    if (!iso) return null;
    var d = new Date(iso); if (isNaN(d)) return null;
    var tz = tzName();
    var sameDay = d.toLocaleDateString('en-US', { timeZone: tz }) === new Date().toLocaleDateString('en-US', { timeZone: tz });
    return sameDay ? fmtT(iso) : fmt(iso, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  }

  /* One feed, in a sentence. Returns null when there is no feed object at all,
   * so a caller can drop the line rather than print a shape with holes in it. */
  function feedSentence(f) {
    if (!f) return null;
    if (!f.everSynced) {
      return 'never successfully pulled' + (f.lastError ? ' · last attempt failed: ' + esc(f.lastError) : '');
    }
    var parts = [];
    /* Anthropic's watermark first, because it is the one being asked about. When
     * they did not send one we say the pull time and label it as the pull time --
     * we do not silently promote it into a "current as of". */
    if (f.dataAsOf) parts.push('current to <b>' + esc(fmt(f.dataAsOf)) + '</b>');
    parts.push('pulled <b>' + esc(rel(f.asOf)) + '</b>');

    var c = f.cadence || {};
    if (c.confidence === 'unknown' || !c.label) {
      parts.push('update cadence not established yet');
    } else if (c.overdue) {
      /* Late is not the same as broken, and must not be drawn as either "fine"
       * or "failed". It says what was expected and that it has not arrived. */
      parts.push('updates ' + esc(c.label) + ' · <span class="fr-late">the next one was due by '
        + esc(fmtWhenSmart(c.nextExpectedTo)) + ' and has not landed</span>');
    } else if (c.confidence === 'rough' && c.nextExpectedFrom && c.nextExpectedTo) {
      /* An uneven schedule gets a window, not a false precision. */
      parts.push('updates ' + esc(c.label) + ' · next expected between <b>'
        + esc(fmtWhenSmart(c.nextExpectedFrom)) + '</b> and <b>' + esc(fmtWhenSmart(c.nextExpectedTo)) + '</b>');
    } else if (c.nextExpectedAt) {
      parts.push('updates ' + esc(c.label) + ' · next expected around <b>'
        + esc(fmtWhenSmart(c.nextExpectedAt)) + '</b>');
    } else {
      parts.push('updates ' + esc(c.label));
    }
    return parts.join(' · ');
  }

  var freshSeq = 0;
  /**
   * @param {object} feeds   the `feeds` object from any profile payload
   * @param {string} primary which feed backs the headline number on this card
   * @param {string[]} also  the other feeds this card's numbers rest on
   */
  /* ===== LIVE-DATA STARBURST — BEGIN ===================================
   * Marks a figure that came live from the Claude Enterprise Analytics API.
   * Ported verbatim from reporting.nrpi.local/ai-usage-credits.html (12 rays,
   * alternating length) so one glyph means one thing across the estate.
   *
   * It is a PROVENANCE mark, not the 8-ray "Claude can run this" burst used on
   * dhcp-consolidation.html -- do not merge the two.
   *
   * It only goes on data we actually pulled: liveIf() returns nothing for a
   * feed that has never synced, because a badge saying "live from the API" over
   * a figure the API never answered for is the exact lie the badge exists to
   * rule out. Set SHOW_LIVE_STAR=false to remove it everywhere.
   * ==================================================================== */
  var SHOW_LIVE_STAR = true;
  function liveStar(title, big) {
    if (!SHOW_LIVE_STAR) return '';
    var t = String(title || 'Live from the Claude Enterprise Analytics API').replace(/"/g, '&quot;');
    var rays = '';
    for (var i = 0; i < 12; i++) {
      var a = i * 30 * Math.PI / 180, inner = i % 2 ? 3.4 : 2.6, outer = i % 2 ? 8.2 : 11;
      rays += '<line x1="' + (12 + Math.cos(a) * inner).toFixed(2) + '" y1="' + (12 + Math.sin(a) * inner).toFixed(2) + '"'
            + ' x2="' + (12 + Math.cos(a) * outer).toFixed(2) + '" y2="' + (12 + Math.sin(a) * outer).toFixed(2) + '"/>';
    }
    return '<span class="live-star' + (big ? ' lg' : '') + '" title="' + t + '" role="img" aria-label="' + t + '">'
      + '<svg viewBox="0 0 24 24" fill="none"><g stroke="currentColor" stroke-width="1.7" stroke-linecap="round">'
      + rays + '</g></svg></span>';
  }
  /* Star a figure only when the feed behind it has actually answered. */
  function liveIf(feeds, key, title, big) {
    var f = feeds && feeds[key];
    return (f && f.everSynced) ? liveStar(title, big) : '';
  }
  /* ===== LIVE-DATA STARBURST — END ===================================== */

  function anthropicNote(feeds, primary, also) {
    if (!feeds) return '';
    var lead = feedSentence(feeds[primary]);
    if (!lead) return '';
    var keys = [primary].concat(also || []).filter(function (k, i, a) { return feeds[k] && a.indexOf(k) === i; });
    var id = 'fr' + (++freshSeq);
    var rows = keys.map(function (k) {
      return '<div class="fr-row"><span class="fr-k">' + esc(FEED_LABEL[k] || k) + '</span>'
        + '<span class="fr-v">' + (feedSentence(feeds[k]) || 'not reported') + '</span></div>';
    }).join('');
    /* The per-feed breakdown is behind a disclosure rather than always open: four
     * feeds spelled out in full is four lines of small print on every card, and
     * only one of them backs the number the reader came for. One click away, and
     * never a tooltip -- a tooltip is reachable by neither touch nor keyboard. */
    var more = keys.length > 1
      ? ' <button type="button" class="fr-btn" aria-expanded="false" aria-controls="' + id + '">Per feed'
        + '<span class="fr-chev">' + icon('chevron-right') + '</span></button>'
      : '';
    return '<p class="note fresh-note">' + liveIf(feeds, primary, 'Live from the Claude Enterprise Analytics API')
      + ic('refresh') + '<span>Anthropic figures ' + lead + '.' + more + '</span></p>'
      + (more ? '<div class="fr-list" id="' + id + '" hidden>' + rows + '</div>' : '');
  }

  /* Delegated once, so the note can be dropped into any card without each
   * renderer having to remember to wire it up. */
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('.fr-btn[aria-controls]');
    if (!b) return;
    var box = document.getElementById(b.getAttribute('aria-controls'));
    if (!box) return;
    var open = b.getAttribute('aria-expanded') === 'true';
    b.setAttribute('aria-expanded', open ? 'false' : 'true');
    box.hidden = open;
  });

  /* ───────────── office conditions in the greeting banner ─────────────
   * Irvine and Plano under "Good morning, <name>", the same readout the landing
   * page carries. Same route, same vocabulary, same refusal to invent a number.
   *
   * Three things this deliberately does NOT do:
   *  - It does not go to open-meteo. /api/weather is a server-side proxy that
   *    exists precisely so no internal page makes third-party egress with the
   *    signed-in user's IP on it (weather-routes.js has the history).
   *  - It never substitutes one office's reading for the other's, and never
   *    falls back to a hardcoded temperature. A site we could not read shows its
   *    name alone, with the reason in the tooltip. The old landing code had an
   *    empty catch() that left "73°F · Sunny" on screen as though measured.
   *  - It does not go through api(): that helper prefixes /api/profile and
   *    carries X-View-As. The weather in Irvine is not the borrowed user's
   *    weather, and there is no /api/profile/weather to call.
   *
   * On a host where /api/weather is not proxied the whole row simply does not
   * render (.gwx:empty is display:none), so the banner looks exactly as it did
   * before rather than leaving a hole or a spinner.
   */
  function loadGreetWeather() {
    var el = $('#greet-wx');
    if (!el) return;
    fetch('/api/weather', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        /* `d` IS the payload. weather-routes.js's envelope() is FLAT --
         * { ok, sites[], label, tempF, source } -- with no `data` wrapper.
         * The wrapper this used to read belongs to landing.html's get() helper,
         * which returns { ok, data:<body> }; nothing in this file wraps, so
         * `d.data` was always undefined and the row rendered empty on every
         * single load while /api/weather answered 200 the whole time. Jeramy
         * 09-23: "add the weather back". [[fixtures-must-carry-the-real-field-set]]
         * -- wxtest.js was green because every fixture in it was wrapped too. */
        if (!d) return;
        /* Deliberately NOT gated on d.ok. envelope() computes that as
         * `anyOk && first.ok !== false`, so one unreadable Irvine turns it false
         * even when Plano came back with a real temperature. Dropping the row on
         * that would throw away a reading we actually have. Readability is
         * decided per site below, which is also what landing.html does. */
        var sites = (Array.isArray(d.sites) && d.sites.length ? d.sites : [d])
          .filter(function (x) { return x && x.label; });
        if (!sites.length) return;
        el.innerHTML = sites.map(function (x) {
          var bad = x.ok === false || typeof x.tempF !== 'number';
          var why = bad
            ? 'Conditions unavailable: ' + (x.reason || d.reason || 'upstream error')
            : [x.text, x.observedAt ? 'observed ' + x.observedAt : '', 'open-meteo']
                .filter(Boolean).join(' \u00b7 ');
          return '<span class="wx-site' + (bad ? ' bad' : '') + '" title="' + esc(why) + '">' +
            (bad ? '' : '<span class="ic" data-icon="' + esc(x.icon || 'cloud') + '"></span>') +
            '<span>' + esc(x.label) + '</span>' +
            (bad ? '' : '<span class="wx-t">' + esc(x.tempF + '\u00b0F') + '</span>') +
            '</span>';
        }).join('<span class="wx-sep" aria-hidden="true">\u00b7</span>');
        hydrate(el);
      })
      .catch(function () { /* no reading is the honest answer; the row stays empty */ });
  }

  hydrate();
  hostThemeToggle();
  document.addEventListener('DOMContentLoaded', hostThemeToggle);
  window.addEventListener('load', function () { hostThemeToggle(); setTimeout(hostThemeToggle, 400); });
  window.addEventListener('itcolormodechange', function () { applyPrefsToDocument(); var seg = $('#seg-mode'); if (seg && window.itColorMode) { var pv = window.itColorMode.getPreference(); $$('button', seg).forEach(function (x) { x.classList.toggle('on', x.getAttribute('data-m') === pv); }); } });
  /* "My Profile" in the sidebar is the page itself, /my-profile.html with no hash
   * (Jeramy, 09-21) -- a real navigation back to the overview, keeping ?viewAs= so
   * a borrowed view stays borrowed. Settings (#profile) lives in the account menu. */
  (function () { var mp = $('.nav-item[data-nav="profile"]'); if (mp) mp.setAttribute('href', location.pathname + location.search); })();
  loadGreetWeather();
  loadMe().then(function () {
    route();
    loadAlertEmailNav();
    if (window.itProfile) window.itProfile.view('page', 'my-profile', 'Opened My Profile', '/my-profile.html');
  }).catch(function (e) { $('#hero-name').textContent = 'Could not load your profile'; $('#hero-title').textContent = e.message; toast(e.message, true); route(); });
})();
