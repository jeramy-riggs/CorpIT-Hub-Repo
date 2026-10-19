#!/usr/bin/env node
/**
 * sdp-taxonomy-apply.js — Phase 2: create approved taxonomy in ServiceDesk Plus
 *
 * Reads the APPROVED taxonomy from /home/ubuntu/taxonomy-proposal.json and
 * creates any missing Categories / Subcategories in SDP. Idempotent: existing
 * names (case-insensitive) are skipped, so re-runs are safe.
 *
 * MODES
 *   --check              READ-ONLY. Auth + list existing SDP categories/subcats.
 *                        Run this FIRST to confirm creds and API shape.
 *   (no flag)            SIMULATION (default). Computes and prints the exact
 *                        create plan; writes /home/ubuntu/phase2-plan.json.
 *                        NO changes made to SDP.
 *   --apply              Executes the plan. Writes a rollback manifest
 *                        /home/ubuntu/phase2-rollback-<ts>.json and appends to
 *                        /home/ubuntu/phase2-audit.log.
 *   --rollback <file>    Deletes exactly what a prior --apply created, using the
 *                        named rollback manifest (subcategories first).
 *
 * OPTIONS
 *   --exclude "A,B"      Skip these top-level category names (case-insensitive).
 *   --taxonomy <path>    Override taxonomy file (default taxonomy-proposal.json).
 *
 * SDP conventions (match existing sdp-lookup.js on this box):
 *   - OAuth2 refresh-token (Zoho). Header: Authorization: Zoho-oauthtoken <tok>
 *   - GET  → input_data as query param, NO Content-Type header
 *   - POST → application/x-www-form-urlencoded, body input_data=<JSON string>
 *
 * ENV (from /var/www/corpit-hub-api/.env):
 *   SDP_CLIENT_ID, SDP_CLIENT_SECRET, SDP_REFRESH_TOKEN, SDP_PORTAL
 *   Optional overrides: SDP_BASE_URL (default https://sdpondemand.manageengine.com)
 *                       SDP_ACCOUNTS_URL (default https://accounts.zoho.com)
 */

'use strict';
const fs = require('fs');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const valOf = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };

const MODE = has('--rollback') ? 'rollback' : has('--apply') ? 'apply' : has('--check') ? 'check' : 'sim';
const ROLLBACK_FILE = valOf('--rollback', null);
const TAXONOMY_PATH = valOf('--taxonomy', '/home/ubuntu/taxonomy-proposal.json');
const EXCLUDE = new Set((valOf('--exclude', '') || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));

const BASE = (process.env.SDP_BASE_URL || 'https://sdpondemand.manageengine.com').replace(/\/+$/, '');
const PORTAL = process.env.SDP_PORTAL || 'itdesk';
const ACCOUNTS = (process.env.SDP_ACCOUNTS_URL || 'https://accounts.zoho.com').replace(/\/+$/, '');
const API = `${BASE}/app/${PORTAL}/api/v3`;
const AUDIT = '/home/ubuntu/phase2-audit.log';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function audit(line) { fs.appendFileSync(AUDIT, `${new Date().toISOString()}\t${line}\n`); }

// ---------- OAuth ----------
async function getToken() {
  const { SDP_CLIENT_ID, SDP_CLIENT_SECRET, SDP_REFRESH_TOKEN } = process.env;
  if (!SDP_CLIENT_ID || !SDP_CLIENT_SECRET || !SDP_REFRESH_TOKEN) {
    console.error('[config] Missing SDP_CLIENT_ID / SDP_CLIENT_SECRET / SDP_REFRESH_TOKEN in .env'); process.exit(1);
  }
  const body = new URLSearchParams({
    refresh_token: SDP_REFRESH_TOKEN, client_id: SDP_CLIENT_ID,
    client_secret: SDP_CLIENT_SECRET, grant_type: 'refresh_token',
  });
  const r = await fetch(`${ACCOUNTS}/oauth/v2/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    console.error(`[auth] token request failed (${r.status}): ${JSON.stringify(j)}`);
    console.error(`[auth] accounts URL used: ${ACCOUNTS}. If your Zoho DC differs (.eu/.in/.com.au/.jp), set SDP_ACCOUNTS_URL.`);
    process.exit(1);
  }
  return j.access_token;
}

// ---------- SDP requests ----------
async function sdpGet(token, path, inputData) {
  const url = new URL(`${API}${path}`);
  if (inputData) url.searchParams.set('input_data', JSON.stringify(inputData));
  const r = await fetch(url, { method: 'GET', headers: { Authorization: `Zoho-oauthtoken ${token}`, Accept: 'application/vnd.manageengine.sdp.v3+json' } });
  const text = await r.text();
  let j; try { j = JSON.parse(text); } catch { j = { _raw: text }; }
  return { ok: r.ok, status: r.status, j };
}
async function sdpPost(token, path, obj) {
  const body = new URLSearchParams({ input_data: JSON.stringify(obj) });
  const r = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { Authorization: `Zoho-oauthtoken ${token}`, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/vnd.manageengine.sdp.v3+json' },
    body,
  });
  const text = await r.text();
  let j; try { j = JSON.parse(text); } catch { j = { _raw: text }; }
  return { ok: r.ok, status: r.status, j };
}
async function sdpDelete(token, path) {
  const r = await fetch(`${API}${path}`, { method: 'DELETE', headers: { Authorization: `Zoho-oauthtoken ${token}`, Accept: 'application/vnd.manageengine.sdp.v3+json' } });
  const text = await r.text();
  let j; try { j = JSON.parse(text); } catch { j = { _raw: text }; }
  return { ok: r.ok, status: r.status, j };
}

// ---------- fetch existing categories + subcategories ----------
async function fetchExisting(token) {
  const out = await sdpGet(token, '/categories', { list_info: { row_count: 200, get_total_count: true } });
  if (!out.ok) {
    console.error(`[api] GET /categories failed (${out.status}): ${JSON.stringify(out.j).slice(0, 600)}`);
    console.error(`[api] API root used: ${API}`);
    console.error('[api] If this 404s, the base URL or portal path may differ. Grep the working module:');
    console.error("      grep -iE 'sdpondemand|manageengine|api/v3|/app/' /var/www/corpit-hub-api/sdp-lookup.js");
    console.error('      then set SDP_BASE_URL (and confirm SDP_PORTAL) to match, and re-run --check.');
    process.exit(1);
  }
  const cats = out.j.categories || [];
  const result = [];
  for (const c of cats) {
    const sub = await sdpGet(token, `/categories/${c.id}/subcategories`, { list_info: { row_count: 200 } });
    const subs = sub.ok ? (sub.j.subcategories || []) : [];
    result.push({ id: c.id, name: c.name, subcategories: subs.map(s => ({ id: s.id, name: s.name })) });
    await sleep(120);
  }
  return result;
}

function loadTaxonomy() {
  if (!fs.existsSync(TAXONOMY_PATH)) { console.error(`[taxonomy] not found: ${TAXONOMY_PATH}`); process.exit(1); }
  const data = JSON.parse(fs.readFileSync(TAXONOMY_PATH, 'utf8'));
  const tax = (data.taxonomy || []).filter(c => !EXCLUDE.has(String(c.name).toLowerCase()));
  if (!tax.length) { console.error('[taxonomy] no categories after exclusions'); process.exit(1); }
  return tax;
}

// diff desired vs existing (case-insensitive)
function buildPlan(taxonomy, existing) {
  const exByName = new Map(existing.map(c => [c.name.toLowerCase(), c]));
  const plan = { createCategories: [], createSubcategories: [] };
  for (const cat of taxonomy) {
    const ex = exByName.get(String(cat.name).toLowerCase());
    const desiredSubs = (cat.subcategories || []).map(s => s.name);
    if (!ex) {
      plan.createCategories.push({ name: cat.name, subcategories: desiredSubs });
    } else {
      const exSub = new Set(ex.subcategories.map(s => s.name.toLowerCase()));
      const missing = desiredSubs.filter(s => !exSub.has(String(s).toLowerCase()));
      if (missing.length) plan.createSubcategories.push({ categoryName: cat.name, categoryId: ex.id, subcategories: missing });
    }
  }
  return plan;
}

function printPlan(plan) {
  const nNewCat = plan.createCategories.length;
  const nNewCatSub = plan.createCategories.reduce((a, c) => a + c.subcategories.length, 0);
  const nAddSub = plan.createSubcategories.reduce((a, c) => a + c.subcategories.length, 0);
  console.log('\n=== CREATE PLAN ===');
  if (nNewCat) {
    console.log(`\nNew categories (${nNewCat}) + their subcategories (${nNewCatSub}):`);
    for (const c of plan.createCategories) console.log(`  + ${c.name}\n      - ${c.subcategories.join('\n      - ')}`);
  }
  if (plan.createSubcategories.length) {
    console.log(`\nSubcategories to add under existing categories (${nAddSub}):`);
    for (const c of plan.createSubcategories) console.log(`  ~ ${c.categoryName}\n      - ${c.subcategories.join('\n      - ')}`);
  }
  if (!nNewCat && !nAddSub) console.log('\nNothing to create — SDP already matches the taxonomy.');
  console.log(`\nTOTAL: ${nNewCat} categories, ${nNewCatSub + nAddSub} subcategories`);
}

// ---------- apply ----------
async function apply(token, plan) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const manifest = { created_at: new Date().toISOString(), api: API, categories: [], subcategories: [] };
  audit(`APPLY START api=${API}`);

  for (const c of plan.createCategories) {
    const res = await sdpPost(token, '/categories', { category: { name: c.name } });
    if (!res.ok || !res.j.category) { console.error(`[apply] FAILED create category "${c.name}" (${res.status}): ${JSON.stringify(res.j).slice(0, 400)}`); audit(`FAIL create-category name="${c.name}" status=${res.status}`); continue; }
    const cid = res.j.category.id;
    manifest.categories.push({ id: cid, name: c.name });
    audit(`OK create-category id=${cid} name="${c.name}"`);
    console.log(`  created category: ${c.name} (id ${cid})`);
    await sleep(150);
    for (const s of c.subcategories) {
      const sr = await sdpPost(token, `/categories/${cid}/subcategories`, { subcategory: { name: s } });
      if (!sr.ok || !sr.j.subcategory) { console.error(`[apply] FAILED subcat "${s}" under "${c.name}" (${sr.status})`); audit(`FAIL create-subcat cat=${cid} name="${s}" status=${sr.status}`); continue; }
      manifest.subcategories.push({ id: sr.j.subcategory.id, name: s, categoryId: cid, categoryName: c.name });
      audit(`OK create-subcat id=${sr.j.subcategory.id} cat=${cid} name="${s}"`);
      await sleep(120);
    }
  }
  for (const c of plan.createSubcategories) {
    for (const s of c.subcategories) {
      const sr = await sdpPost(token, `/categories/${c.categoryId}/subcategories`, { subcategory: { name: s } });
      if (!sr.ok || !sr.j.subcategory) { console.error(`[apply] FAILED subcat "${s}" under "${c.categoryName}" (${sr.status})`); audit(`FAIL create-subcat cat=${c.categoryId} name="${s}" status=${sr.status}`); continue; }
      manifest.subcategories.push({ id: sr.j.subcategory.id, name: s, categoryId: c.categoryId, categoryName: c.categoryName });
      audit(`OK create-subcat id=${sr.j.subcategory.id} cat=${c.categoryId} name="${s}"`);
      console.log(`  added subcategory: ${c.categoryName} / ${s} (id ${sr.j.subcategory.id})`);
      await sleep(120);
    }
  }
  const file = `/home/ubuntu/phase2-rollback-${ts}.json`;
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2));
  audit(`APPLY DONE categories=${manifest.categories.length} subcategories=${manifest.subcategories.length} manifest=${file}`);
  console.log(`\n[done] created ${manifest.categories.length} categories, ${manifest.subcategories.length} subcategories`);
  console.log(`[rollback] manifest: ${file}`);
  console.log(`[rollback] to undo: node sdp-taxonomy-apply.js --rollback ${file}`);
}

// ---------- rollback ----------
async function rollback(token, file) {
  if (!file || !fs.existsSync(file)) { console.error(`[rollback] manifest not found: ${file}`); process.exit(1); }
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  audit(`ROLLBACK START manifest=${file}`);
  // subcategories first
  for (const s of (m.subcategories || [])) {
    const r = await sdpDelete(token, `/categories/${s.categoryId}/subcategories/${s.id}`);
    console.log(`  ${r.ok ? 'deleted' : 'FAILED'} subcategory ${s.categoryName}/${s.name} (id ${s.id})${r.ok ? '' : ' status ' + r.status}`);
    audit(`${r.ok ? 'OK' : 'FAIL'} delete-subcat id=${s.id}`);
    await sleep(120);
  }
  for (const c of (m.categories || [])) {
    const r = await sdpDelete(token, `/categories/${c.id}`);
    console.log(`  ${r.ok ? 'deleted' : 'FAILED'} category ${c.name} (id ${c.id})${r.ok ? '' : ' status ' + r.status}`);
    audit(`${r.ok ? 'OK' : 'FAIL'} delete-category id=${c.id}`);
    await sleep(150);
  }
  audit('ROLLBACK DONE');
  console.log('\n[done] rollback complete.');
}

(async () => {
  console.log(`[mode] ${MODE}  api=${API}  portal=${PORTAL}`);
  const token = await getToken();
  console.log('[auth] token OK');

  if (MODE === 'check') {
    const existing = await fetchExisting(token);
    console.log(`\n=== EXISTING SDP CATEGORIES (${existing.length}) ===`);
    for (const c of existing) console.log(`  ${c.name} (id ${c.id}) — ${c.subcategories.length} subcategories`);
    console.log('\n[check] OK — auth + category API verified. Run without flags for a simulation plan.');
    return;
  }

  if (MODE === 'rollback') { await rollback(token, ROLLBACK_FILE); return; }

  const taxonomy = loadTaxonomy();
  const existing = await fetchExisting(token);
  const plan = buildPlan(taxonomy, existing);
  printPlan(plan);

  if (MODE === 'sim') {
    fs.writeFileSync('/home/ubuntu/phase2-plan.json', JSON.stringify(plan, null, 2));
    console.log('\n[simulation] No changes made. Plan saved to /home/ubuntu/phase2-plan.json');
    console.log('[simulation] To execute: node sdp-taxonomy-apply.js --apply');
    return;
  }
  if (MODE === 'apply') { await apply(token, plan); return; }
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
