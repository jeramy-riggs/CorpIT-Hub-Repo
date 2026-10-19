/* ============================================================================
   IT Asset Console — API endpoint configuration
   ----------------------------------------------------------------------------
   THE single source of truth for where this page's data comes from. Loaded in
   <head>, before every other app script. Nothing else may hardcode a host or
   an API prefix.

   Why this file exists. On the ITAM original the same two values were declared
   in THREE places — IT_Inventory_App.js:4-5 and two separate inline blocks in
   IT_Inventory_App.html — each carrying its own hardcoded
   'https://itam.nrpi.local' fallback. Those fallbacks were unreachable (the
   .js always parses first), so they could never be correct, only stale, and
   moving the app to another host meant finding all three. One of them being
   missed is a page that half-works against the wrong server.

   `origin` is read from the browser and never written down, so this console is
   correct on whatever vhost serves it — corpit today, another department's
   host as the platform grows — with no edit to this file at all. The only
   value actually configured here is the hub prefix.
   ========================================================================== */
(function () {
  'use strict';
  var origin = window.location.origin;

  window.INVENTORY_API = Object.freeze({
    /* Core inventory CRUD (:3000) — 11 inventory tables, served from this same
       origin under /api/. The registry that actually drives them is the `calls`
       array in IT_Inventory_App.js init(); getDataArr() in the same file maps
       each DATA key back to a table name. This comment used to name an
       API_ROUTES object instead — deleted 2026-09-03, because nothing read it
       and pointing readers at an inert list had already let it fall a table
       behind the real ones. Add a table in init()'s calls array and
       getDataArr(), not in a registry that only looks authoritative. */
    base: origin,

    /* Vendor-integration API (:3001, corpit-hub-api): warranty, Intune Graph,
       Kandji, ABM, endpoint sync, cross-reference. This prefix was '/beta-api'
       on ITAM — the service was never a beta, the name just stuck. */
    hub: origin + '/hub-api'
  });
})();
