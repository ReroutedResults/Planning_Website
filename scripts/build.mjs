#!/usr/bin/env node
/**
 * RR Planning Intelligence: weekly data build
 *
 * 1. Queries Ireland's National Planning Applications database for every search
 *    phrase in config/categories.json, for applications received in the last 7 days
 *    ("daysBack"). The new applications are ADDED to those collected in earlier weeks,
 *    and nothing is removed. The very first run collects "firstRunMonths" of history.
 * 2. Keeps permission applications only: drops retention applications and any
 *    application whose description mentions retention. Also drops non-permission
 *    types like Section 5 declarations and extensions of duration.
 * 3. Encrypts each category's results with AES-256-GCM. Each category file opens
 *    with EITHER that category's password OR the master password.
 *
 * Passwords come from environment variables (GitHub Actions secrets):
 *   RR_PW_MASTER plus the "secret" name listed for each category.
 *
 * Needs Node 20+. No npm packages.
 * Test mode: RR_FIXTURE=path/to/features.json reads raw ArcGIS features from a file instead of the API.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = process.env.RR_OUT || join(ROOT, 'data');
const API = 'https://services.arcgis.com/NzlPQPKn5QF9v2US/arcgis/rest/services/IrishPlanningApplications/FeatureServer/0';
const ITERATIONS = 310000;
const FIELDS = [
  'OBJECTID', 'PlanningAuthority', 'ApplicationNumber', 'DevelopmentDescription', 'DevelopmentAddress',
  'ApplicationStatus', 'ApplicationType', 'Decision', 'ReceivedDate', 'DecisionDate', 'DecisionDueDate',
  'GrantDate', 'ExpiryDate', 'WithdrawnDate', 'AppealRefNumber', 'AppealStatus', 'AppealDecision',
  'NumResidentialUnits', 'FloorArea', 'AreaofSite', 'LinkAppDetails'
].join(',');

const config = JSON.parse(readFileSync(join(ROOT, 'config', 'categories.json'), 'utf8'));
const subtle = globalThis.crypto.subtle;

/* ---------- Passwords ---------- */
const missing = ['RR_PW_MASTER', ...config.categories.map((c) => c.secret)].filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing password secrets: ${missing.join(', ')}\nAdd them under Settings → Secrets and variables → Actions.`);
  process.exit(1);
}

/* ---------- Fetching ---------- */
const clean = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function arcgis(params, attempt = 1) {
  try {
    const res = await fetch(API + '/query', {
      method: 'POST',
      body: new URLSearchParams({ f: 'json', ...params }),
      signal: AbortSignal.timeout(120_000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
    return json;
  } catch (err) {
    if (attempt >= 4) throw err;
    console.warn(`  retry ${attempt} after error: ${err.message}`);
    await sleep(3000 * attempt);
    return arcgis(params, attempt + 1);
  }
}

async function fetchTerm(term, since) {
  const where = `UPPER(DevelopmentDescription) LIKE '%${term.toUpperCase().replace(/'/g, "''")}%' AND ReceivedDate >= DATE '${since}'`;
  const out = [];
  for (let offset = 0; ; offset += 2000) {
    const page = await arcgis({
      where, outFields: FIELDS, outSR: '4326', returnGeometry: 'true',
      orderByFields: 'OBJECTID', resultOffset: String(offset), resultRecordCount: '2000'
    });
    out.push(...(page.features || []));
    if (!page.exceededTransferLimit || !page.features?.length) break;
  }
  return out;
}

/* ---------- Permission-only filter ---------- */
const EXCLUDE_TYPE = /RETENTION|DURATION|EXEMPT|SECTION 5|SECT\. ?5|COMPLIANCE|PRE-APPLICATION|OUTDOOR EVENT|QUARRY|CONTINUATION OF USE|LOCAL AREA PLAN|NAMING|SUB-ARTICLE|PART V\b|PART 8|PART VIII|PART VLLL|SECTION 179|PART X\b|PART 10/;
function isPermission(a) {
  const type = clean(a.ApplicationType).toUpperCase();
  const desc = clean(a.DevelopmentDescription).toUpperCase();
  if (EXCLUDE_TYPE.test(type)) return false;
  if (/RETENTION/.test(desc)) return false;
  return true;
}

/* ---------- Record shape sent to the browser (short keys keep files small) ---------- */
function slim(f, terms) {
  const a = f.attributes;
  const g = f.geometry && Number.isFinite(f.geometry.x) && Number.isFinite(f.geometry.y) ? f.geometry : null;
  const num = (v) => (v > 0 ? Math.round(v * 100) / 100 : undefined);
  const r = {
    id: a.OBJECTID,
    ref: clean(a.ApplicationNumber),
    council: clean(a.PlanningAuthority),
    desc: clean(a.DevelopmentDescription),
    addr: clean(a.DevelopmentAddress),
    type: clean(a.ApplicationType),
    status: clean(a.ApplicationStatus),
    decision: clean(a.Decision),
    received: a.ReceivedDate || undefined,
    decided: a.DecisionDate || undefined,
    due: a.DecisionDueDate || undefined,
    granted: a.GrantDate || undefined,
    expires: a.ExpiryDate || undefined,
    withdrawn: a.WithdrawnDate || undefined,
    appeal: clean(a.AppealRefNumber) || undefined,
    appealStatus: clean(a.AppealDecision) || clean(a.AppealStatus) || undefined,
    units: num(a.NumResidentialUnits),
    floor: num(a.FloorArea),
    site: num(a.AreaofSite),
    link: clean(a.LinkAppDetails).replace(/^http:/, 'https:') || undefined,
    lat: g ? Math.round(g.y * 1e6) / 1e6 : undefined,
    lng: g ? Math.round(g.x * 1e6) / 1e6 : undefined,
    terms: [...terms]
  };
  return JSON.parse(JSON.stringify(r)); // drop undefined
}

/* ---------- Encryption ---------- */
const b64 = (buf) => Buffer.from(buf).toString('base64');
const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

async function deriveKey(password, salt, iterations = ITERATIONS) {
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function seal(key, bytes) {
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: b64(iv), ct: b64(ct) };
}

/* ---------- Existing data (kept and added to each week) ---------- */
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
async function unseal(key, box) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct)));
}
function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}
// Opens last week's file with the category password, or the master password if that changed.
async function loadExisting(cat, oldManifest) {
  const file = readJson(join(OUT, `${cat.id}.json`));
  if (!file || !oldManifest) return null;
  const tries = [
    [process.env[cat.secret], file.salt, file.wraps.category],
    [process.env.RR_PW_MASTER, oldManifest.masterSalt, file.wraps.master]
  ];
  for (const [pw, salt, box] of tries) {
    try {
      const key = await deriveKey(pw, unb64(salt), oldManifest.iterations);
      const raw = await unseal(key, box);
      const dataKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
      return JSON.parse(gunzipSync(await unseal(dataKey, file.data)).toString('utf8'));
    } catch { /* try the next password */ }
  }
  console.warn(`  ! Couldn't open the existing ${cat.name} data. Both its password and the master password have changed, so this section starts again from this week.`);
  return null;
}

/* ---------- Main ---------- */
const today = process.env.RR_TODAY ? new Date(process.env.RR_TODAY) : new Date();
const oldManifest = readJson(join(OUT, 'manifest.json'));
const firstRun = !oldManifest;
const since = (() => {
  const d = new Date(today);
  if (firstRun && config.firstRunMonths > 0) d.setUTCMonth(d.getUTCMonth() - config.firstRunMonths);
  else d.setUTCDate(d.getUTCDate() - (config.daysBack || 7));
  return d.toISOString().slice(0, 10);
})();
const addedOn = today.toISOString().slice(0, 10);
console.log(firstRun ? `First run: collecting applications received since ${since}` : `Weekly run: collecting applications received since ${since}`);

let fixture = null;
if (process.env.RR_FIXTURE) {
  fixture = JSON.parse(readFileSync(process.env.RR_FIXTURE, 'utf8'));
  console.log(`TEST MODE: using ${fixture.length} fixture features`);
}

mkdirSync(OUT, { recursive: true });

const masterSalt = rand(16);
const masterKey = await deriveKey(process.env.RR_PW_MASTER, masterSalt);
const summary = [];
const outFiles = new Map();

for (const cat of config.categories) {
  console.log(`\n${cat.name}`);
  const byApp = new Map(); // council|ref → { feature, terms }
  for (const term of cat.terms) {
    const feats = fixture
      ? fixture.filter((f) => clean(f.attributes.DevelopmentDescription).toUpperCase().includes(term.toUpperCase()))
      : await fetchTerm(term, since);
    let kept = 0;
    for (const f of feats) {
      if (!isPermission(f.attributes)) continue;
      kept++;
      const key = `${clean(f.attributes.PlanningAuthority)}|${clean(f.attributes.ApplicationNumber)}`;
      const hit = byApp.get(key);
      if (hit) {
        hit.terms.add(term);
        if (!hit.feature.geometry && f.geometry) hit.feature = f;
      } else {
        byApp.set(key, { feature: f, terms: new Set([term]) });
      }
    }
    console.log(`  "${term}": ${feats.length} found, ${kept} permissions`);
  }

  // Start from everything collected in earlier weeks
  const existing = await loadExisting(cat, oldManifest);
  const merged = new Map((existing?.records || []).map((r) => [`${r.council}|${r.ref}`, r]));
  const before = merged.size;
  let added = 0, refreshed = 0;
  for (const [key, { feature, terms }] of byApp) {
    const rec = slim(feature, terms);
    const old = merged.get(key);
    if (old) {
      // Seen before: take the latest details (e.g. a new decision), keep the first-seen date
      rec.added = old.added;
      rec.terms = [...new Set([...(old.terms || []), ...rec.terms])];
      refreshed++;
    } else {
      rec.added = addedOn;
      added++;
    }
    merged.set(key, rec);
  }

  const records = [...merged.values()].sort((a, b) => (b.received || 0) - (a.received || 0));
  const payload = gzipSync(Buffer.from(JSON.stringify({ category: cat.id, terms: cat.terms, records })));
  const dataKeyRaw = rand(32);
  const dataKey = await subtle.importKey('raw', dataKeyRaw, 'AES-GCM', false, ['encrypt']);
  const catSalt = rand(16);
  const catKey = await deriveKey(process.env[cat.secret], catSalt);

  outFiles.set(cat.id, {
    v: 1,
    salt: b64(catSalt),
    wraps: {
      category: await seal(catKey, dataKeyRaw),
      master: await seal(masterKey, dataKeyRaw)
    },
    data: await seal(dataKey, payload)
  });
  summary.push(`${cat.name}: ${added} new, ${refreshed} updated, ${records.length} in total (was ${before})`);
  console.log(`  → ${added} new, ${records.length} in total`);
}

// Write everything only after every category has succeeded, so a failed run never leaves half-updated data
for (const f of readdirSync(OUT)) if (f.endsWith('.json')) unlinkSync(join(OUT, f));
for (const [id, file] of outFiles) writeFileSync(join(OUT, `${id}.json`), JSON.stringify(file));
writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({
  v: 1,
  updated: today.toISOString(),
  latestBatch: addedOn,
  started: oldManifest?.started || since,
  iterations: ITERATIONS,
  masterSalt: b64(masterSalt),
  categories: config.categories.map(({ id, name }) => ({ id, name })) // search phrases stay inside the encrypted files
}, null, 2));

console.log(`\nDone. Collected applications received since ${since}.\n${summary.join('\n')}`);
