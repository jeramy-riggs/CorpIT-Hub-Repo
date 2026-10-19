// ---------------------------------------------------------------------------
// obs-ingest-cap.js - make "Largest browser report accepted" a real limit.
//                                                                   2026-09-06
// The console publishes obs.client_max_body_kb, the root helper validates and
// writes it, obs-lib clamps it, stats() reports it, and observability.html
// prints it to the operator as the operative limit. Nothing enforced it. The
// body was already parsed by the global express.json (50 MB then; 1 MB since
// CHG-ARCH-13) long before the ingest route saw it, so the real cap was 780x
// the declared one.
//
// A control that is displayed, configurable, audited, published through a
// privileged root helper and inert is precisely the defect class this entire
// build exists to find. It is not acceptable for the build to contain one.
//
// MOUNT ORDER IS LOAD-BEARING: this must be registered BEFORE the global
// express.json in server.js, on the ingest path only. body-parser compares
// Content-Length against its limit before reading the stream, so an oversized
// report is refused without being buffered. Mounted after the global parser it
// would do nothing at all, because req._body is already set by then.
//
// Rejections are COUNTED (obs.noteOversize) and reported by /self and
// /summary. A cap that silently discards is a different kind of lie.
// ---------------------------------------------------------------------------
'use strict';

const express = require('express');
const obs = require('./obs-lib');

// The same bounds the console overlay clamps to (obs-lib OVERLAY_NUM), restated
// here rather than imported, so a future widening of the overlay cannot
// silently widen what this middleware admits.
const LO = 1024, HI = 1048576;

let cached = null, cachedCap = 0;

function capNow() {
  const v = Number(obs.CFG.clientMaxBody);
  if (!Number.isFinite(v)) return LO;
  return Math.min(HI, Math.max(LO, Math.round(v)));
}

module.exports = function obsIngestCap(req, res, next) {
  const cap = capNow();
  // Rebuilt only when the operator changes the value, not per request.
  if (cap !== cachedCap || !cached) {
    cachedCap = cap;
    cached = express.json({ limit: cap });
  }
  cached(req, res, function (err) {
    if (err && (err.status === 413 || err.statusCode === 413 ||
                err.type === 'entity.too.large')) {
      try { obs.noteOversize(1); } catch (e) { /* never break the ingest path */ }
      // 413, not the route's usual 204. The beacon has nobody to show an error
      // to, but a page told 204 will keep posting the same oversized payload
      // forever; 413 is the one answer that means "stop sending this".
      res.status(413);
      return res.json({ error: 'report too large', maxBytes: cap });
    }
    return next(err);
  });
};

// Exposed for the self-test on /observability.html.
module.exports.capBytes = capNow;
