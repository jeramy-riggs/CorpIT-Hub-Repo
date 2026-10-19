#!/usr/bin/env node
/**
 * analyze-taxonomy.js — Phase 1 of SDP Classification Bot
 * READ-ONLY. Analyzes historical requests in sdops_request and produces a
 * proposed Category/Subcategory taxonomy for human review.
 *
 * Outputs:
 *   /home/ubuntu/taxonomy-proposal.json  (machine-readable, used by Phase 2)
 *   /home/ubuntu/taxonomy-proposal.md    (human review document)
 *
 * Usage (from /var/www/corpit-hub-api so node_modules resolves):
 *   node analyze-taxonomy.js            # full run
 *   node analyze-taxonomy.js --check    # verify DB + API config only, no calls
 *
 * Requires in /var/www/corpit-hub-api/.env:
 *   ANTHROPIC_API_KEY=sk-ant-...
 *   (existing DB credentials — auto-detected, see resolveDbConfig)
 */

'use strict';
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const CHECK_ONLY = process.argv.includes('--check');
const OUT_JSON = '/home/ubuntu/taxonomy-proposal.json';
const OUT_MD = '/home/ubuntu/taxonomy-proposal.md';
const MODEL = process.env.CLASSIFIER_MODEL || 'claude-sonnet-4-6';
const MAX_SUBJECT_LINES = parseInt(process.env.TAXONOMY_MAX_SUBJECTS || '700', 10);

// ---------- DB config resolution ----------
function resolveDbConfig() {
  const e = process.env;
  const host = e.DB_HOST || e.MYSQL_HOST || '127.0.0.1';
  const user = e.DB_USER || e.MYSQL_USER;
  const password = e.DB_PASS || e.DB_PASSWORD || e.MYSQL_PASSWORD;
  const database = e.DB_NAME || e.MYSQL_DATABASE || 'corpit_hub';
  const socketPath = e.DB_SOCKET || null;
  if (!user) {
    console.error('[config] No DB user found. Looked for DB_USER / MYSQL_USER in /var/www/corpit-hub-api/.env.');
    console.error('[config] Check what collect-requests.js uses and set matching vars, or add DB_USER/DB_PASS.');
    process.exit(1);
  }
  const cfg = { user, password, database };
  if (socketPath) cfg.socketPath = socketPath; else cfg.host = host;
  return cfg;
}

// ---------- helpers ----------
function normalizeSubject(s) {
  return String(s || '')
    .replace(/^\s*((re|fw|fwd|aw)\s*:\s*)+/i, '')
    .replace(/#?\d{4,}/g, '#')            // collapse ticket/asset numbers
    .replace(/\b[\w.+-]+@[\w.-]+\b/g, '@user')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

async function callClaude(system, userText) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) { console.error('[config] ANTHROPIC_API_KEY missing in .env'); process.exit(1); }
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 8000,
      system,
      messages: [{ role: 'user', content: userText }],
    }),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Anthropic API ${resp.status}: ${body.slice(0, 500)}`);
  }
  const data = await resp.json();
  const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
  return text.replace(/```json/gi, '').replace(/```/g, '').trim();
}

// ---------- main ----------
(async () => {
  const mysql = require('mysql2/promise');
  const cfg = resolveDbConfig();
  console.log(`[db] connecting as ${cfg.user}@${cfg.socketPath ? cfg.socketPath : cfg.host}/${cfg.database}`);
  const db = await mysql.createConnection(cfg);

  // Introspect available columns so we never assume schema
  const [cols] = await db.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'sdops_request'`, [cfg.database]);
  const available = new Set(cols.map(c => c.COLUMN_NAME.toLowerCase()));
  const pick = (...names) => names.find(n => available.has(n)) || null;

  const colSubject = pick('subject');
  const colTemplate = pick('request_template', 'template', 'template_name');
  const colCategory = pick('category');
  const colSubcat = pick('subcategory', 'sub_category');
  const colStatus = pick('status');
  const colCreated = pick('created_at', 'created_time');

  if (!colSubject) { console.error('[schema] sdops_request has no subject column — aborting.'); process.exit(1); }
  console.log('[schema] using columns:', { colSubject, colTemplate, colCategory, colSubcat, colStatus, colCreated });

  const [[{ total }]] = await db.query('SELECT COUNT(*) AS total FROM sdops_request');
  console.log(`[data] ${total} requests in sdops_request`);

  if (CHECK_ONLY) {
    console.log(`[check] ANTHROPIC_API_KEY present: ${!!process.env.ANTHROPIC_API_KEY}`);
    console.log('[check] OK — config and schema verified. Re-run without --check to generate proposal.');
    await db.end(); return;
  }

  // Existing taxonomy usage (if columns exist)
  let existingTax = [];
  if (colCategory) {
    const sub = colSubcat ? `, ${colSubcat} AS subcategory` : '';
    const [rows] = await db.query(
      `SELECT ${colCategory} AS category${sub}, COUNT(*) AS n
       FROM sdops_request GROUP BY 1${colSubcat ? ',2' : ''} ORDER BY n DESC LIMIT 200`);
    existingTax = rows;
  }

  // Template usage
  let templates = [];
  if (colTemplate) {
    const [rows] = await db.query(
      `SELECT ${colTemplate} AS template, COUNT(*) AS n FROM sdops_request GROUP BY 1 ORDER BY n DESC LIMIT 100`);
    templates = rows;
  }

  // Deduped normalized subjects with volume, most common first
  const [subjRows] = await db.query(`SELECT ${colSubject} AS subject FROM sdops_request`);
  const counts = new Map();
  for (const r of subjRows) {
    const k = normalizeSubject(r.subject);
    if (!k) continue;
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const topSubjects = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_SUBJECT_LINES);
  const covered = topSubjects.reduce((s, [, n]) => s + n, 0);
  console.log(`[data] ${counts.size} distinct normalized subjects; top ${topSubjects.length} cover ${covered}/${total} tickets (${Math.round(covered / total * 100)}%)`);

  const system = `You are an ITSM taxonomy architect designing a Category/Subcategory structure for ManageEngine ServiceDesk Plus at a mid-size company (~660 employees; corporate IT: identity/Entra/Okta, M365/Exchange, endpoints, VoIP via Vonage VBC, Zscaler, LOB apps).
Design rules:
- 8 to 14 top-level Categories, each with 2 to 8 Subcategories. MECE as far as practical.
- Names short (1-3 words), unambiguous to a helpdesk technician, no overlap.
- Include a "General / Other" catch-all category with minimal subcategories.
- Every proposed subcategory must be justified by observed ticket volume.
Respond with ONLY valid JSON, no markdown, matching exactly:
{"categories":[{"name":"","description":"","subcategories":[{"name":"","description":"","example_subjects":["",""],"est_share_pct":0}]}],"notes":["design decisions and mapping notes for the reviewer"]}`;

  const userText = [
    `Total requests: ${total}`,
    templates.length ? `\nRequest template usage (template<TAB>count):\n${templates.map(t => `${t.template || '(none)'}\t${t.n}`).join('\n')}` : '',
    existingTax.length ? `\nExisting category usage (category / subcategory<TAB>count):\n${existingTax.map(r => `${r.category || '(none)'}${r.subcategory !== undefined ? ' / ' + (r.subcategory || '(none)') : ''}\t${r.n}`).join('\n')}` : '',
    `\nDeduplicated normalized subjects (count<TAB>subject), most common first:\n${topSubjects.map(([s, n]) => `${n}\t${s}`).join('\n')}`,
  ].join('\n');

  console.log(`[ai] calling ${MODEL}...`);
  const raw = await callClaude(system, userText);
  let proposal;
  try { proposal = JSON.parse(raw); }
  catch (e) {
    fs.writeFileSync('/home/ubuntu/taxonomy-proposal.raw.txt', raw);
    console.error('[ai] Response was not valid JSON. Raw saved to /home/ubuntu/taxonomy-proposal.raw.txt');
    process.exit(1);
  }

  const out = {
    generated_at: new Date().toISOString(),
    model: MODEL,
    source: { table: 'sdops_request', total_requests: total, subjects_analyzed: topSubjects.length, coverage_pct: Math.round(covered / total * 100) },
    status: 'PROPOSED — pending human approval',
    taxonomy: proposal.categories || [],
    notes: proposal.notes || [],
  };
  fs.writeFileSync(OUT_JSON, JSON.stringify(out, null, 2));

  // Markdown review doc
  const md = [];
  md.push(`# Proposed SDP Category/Subcategory Taxonomy`);
  md.push(`Generated ${out.generated_at} · model ${MODEL} · ${total} requests analyzed (top-subject coverage ${out.source.coverage_pct}%)`);
  md.push(`\n**Status: PROPOSED — review, edit ${OUT_JSON} if needed, then approve for Phase 2 (creation in SDP).**\n`);
  for (const c of out.taxonomy) {
    md.push(`## ${c.name}`);
    if (c.description) md.push(c.description);
    md.push('');
    md.push('| Subcategory | Description | Est. share | Example subjects |');
    md.push('|---|---|---|---|');
    for (const s of (c.subcategories || [])) {
      md.push(`| ${s.name} | ${s.description || ''} | ${s.est_share_pct ?? ''}% | ${(s.example_subjects || []).join('; ')} |`);
    }
    md.push('');
  }
  if (out.notes.length) { md.push('## Design notes'); out.notes.forEach(n => md.push(`- ${n}`)); }
  fs.writeFileSync(OUT_MD, md.join('\n'));

  console.log(`[done] wrote ${OUT_JSON} and ${OUT_MD}`);
  await db.end();
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
