/* RR Planning Intelligence
 * Static site. Each category's data lives in data/<id>.json, encrypted with AES-256-GCM.
 * A file opens with its own category password or with the master password
 * (PBKDF2-SHA256 key derivation). Every week the GitHub Action in .github/workflows adds
 * the last 7 days of applications to these files.
 */
(() => {
  'use strict';

  const PAGE_SIZE = 50;
  const KEY_STORE = 'rr.keys.v1';
  const ICONS = {
    dairy: '<path d="M8 2h8l1 5H7zM7 7h10v13a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2z"/><path d="M7 12h10"/>',
    'cow-housing': '<path d="M3 21V10l9-6 9 6v11"/><path d="M7 21v-7h10v7M7 17h10"/>',
    slurry: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    'farm-buildings': '<path d="M2 21h20M4 21V11l8-7 8 7v10"/><path d="M9 21v-6h6v6"/>',
    calving: '<path d="M12 21c-4 0-7-3-7-7 0-3 2-5 3-7l2 2h4l2-2c1 2 3 4 3 7 0 4-3 7-7 7z"/><circle cx="10" cy="13" r=".5"/><circle cx="14" cy="13" r=".5"/>',
    feed: '<path d="M6 3h12v11l-6 7-6-7z"/><path d="M6 9h12"/>',
    'milk-storage': '<rect x="3" y="7" width="18" height="11" rx="5.5"/><path d="M7 18v3M17 18v3M12 4v3"/>',
    yards: '<path d="M3 20V8M21 20V8M3 11h18M3 16h18M9 8v12M15 8v12"/>',
    renewables: '<rect x="3" y="4" width="18" height="11" rx="1"/><path d="M3 9.5h18M9 4v11M15 4v11M12 15v5M8 20h8"/>'
  };
  const LOCK_SVG = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';
  const OPEN_SVG = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/></svg>';

  const $ = (id) => document.getElementById(id);
  const els = {
    home: $('home'), gate: $('gate'), explorer: $('explorer'), cards: $('cards'), homeMsg: $('homeMsg'),
    crumb: $('crumb'), freshness: $('freshness'), lockAll: $('lockAll'), masterBtn: $('masterBtn'),
    gateForm: $('gateForm'), gateTitle: $('gateTitle'), gateHint: $('gateHint'), pw: $('pw'), gateErr: $('gateErr'), gateBtn: $('gateBtn'),
    q: $('q'), term: $('term'), council: $('council'), since: $('since'), outcome: $('outcome'), inView: $('inView'),
    reset: $('reset'), sort: $('sort'), csv: $('csv'), list: $('list'), summary: $('summary'),
    prev: $('prev'), next: $('next'), pageInfo: $('pageInfo')
  };

  const state = {
    manifest: null, files: new Map(), keys: loadKeys(), data: new Map(),
    cat: null, filtered: [], page: 0, terms: [], markers: new Map()
  };

  /* ---------- Small helpers ---------- */
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtDate = (ms) => ms ? new Date(ms).toLocaleDateString('en-IE', { day: 'numeric', month: 'short', year: 'numeric' }) : '';
  const titleCase = (s) => /[a-z]/.test(s || '') ? s : String(s || '').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
  const shortCouncil = (c) => c.replace(/ City and County Council| County Council| City Council/, '');
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (u8) => btoa(String.fromCharCode(...u8));

  function loadKeys() {
    try { return JSON.parse(sessionStorage.getItem(KEY_STORE)) || {}; } catch { return {}; }
  }
  function saveKeys() {
    try { sessionStorage.setItem(KEY_STORE, JSON.stringify(state.keys)); } catch { /* private mode: stay in memory */ }
  }

  function outcomeOf(r) {
    const d = (r.decision || '').toUpperCase();
    if (/REFUS/.test(d) && !/GRANT/.test(d)) return 'refused';
    if (/GRANT|CONDITIONAL|APPROV/.test(d) && !/^DISAPPROV|^REFUSE/.test(d)) return 'granted';
    if (/WITHDRAW|INVALID/.test(d) || r.withdrawn) return 'other';
    if (!r.decided && (!d || d === 'N/A')) return 'pending';
    return 'other';
  }
  function outcomeLabel(r) {
    if (r.decision && r.decision !== 'N/A') return titleCase(r.decision);
    return r.withdrawn ? 'Withdrawn' : 'Awaiting decision';
  }

  /* ---------- Crypto ---------- */
  const derived = new Map();
  async function deriveKey(password, saltB64) {
    if (!window.crypto?.subtle) throw new Error('This page must be opened over https:// to unlock sections.');
    const id = saltB64 + '\u0000' + password;
    if (derived.has(id)) return derived.get(id);
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64d(saltB64), iterations: state.manifest.iterations },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    derived.set(id, key);
    return key;
  }
  async function openBox(key, box) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(box.iv) }, key, b64d(box.ct)));
  }
  async function tryUnwrap(key, box) {
    try { return await openBox(key, box); } catch { return null; }
  }
  async function decryptCategory(file, rawKey) {
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const gz = await openBox(key, file.data);
    const stream = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }

  async function getFile(id) {
    if (!state.files.has(id)) {
      const res = await fetch(`data/${id}.json`, { cache: 'no-cache' });
      if (!res.ok) throw new Error(`Couldn't load data for this section (HTTP ${res.status}).`);
      state.files.set(id, await res.json());
    }
    return state.files.get(id);
  }

  // Returns decrypted data for a category if we hold a working key, else null
  async function getData(id) {
    if (state.data.has(id)) return state.data.get(id);
    const raw = state.keys[id];
    if (!raw) return null;
    try {
      const data = await decryptCategory(await getFile(id), b64d(raw));
      state.data.set(id, data);
      return data;
    } catch {
      delete state.keys[id]; saveKeys(); // data was rebuilt with new keys, so ask again
      return null;
    }
  }

  async function unlockWithMaster(password) {
    const mKey = await deriveKey(password, state.manifest.masterSalt);
    let opened = 0;
    for (const c of state.manifest.categories) {
      const file = await getFile(c.id);
      const raw = await tryUnwrap(mKey, file.wraps.master);
      if (!raw) { if (opened === 0) return false; continue; }
      state.keys[c.id] = b64e(raw); opened++;
    }
    saveKeys();
    return opened > 0;
  }

  async function unlockCategory(id, password) {
    const file = await getFile(id);
    const raw = await tryUnwrap(await deriveKey(password, file.salt), file.wraps.category);
    if (raw) { state.keys[id] = b64e(raw); saveKeys(); return true; }
    // Master password also works on any section, and unlocks the rest too
    return unlockWithMaster(password);
  }

  /* ---------- Views ---------- */
  function show(view) {
    for (const v of ['home', 'gate', 'explorer']) els[v].hidden = v !== view;
    els.lockAll.hidden = Object.keys(state.keys).length === 0;
  }

  function renderHome() {
    state.cat = null;
    els.crumb.textContent = 'Agricultural & renewables planning permissions across Ireland';
    document.title = 'RR Planning Intelligence';
    const allOpen = state.manifest.categories.every((c) => state.keys[c.id]);
    els.masterBtn.hidden = allOpen;
    els.cards.innerHTML = state.manifest.categories.map((c) => {
      const open = !!state.keys[c.id];
      return `<a class="card ${open ? 'unlocked' : ''}" href="#/c/${esc(c.id)}">
        <div class="card-top"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[c.id] || ICONS['farm-buildings']}</svg></span></div>
        <h3>${esc(c.name)}</h3>
        <span class="status">${open ? OPEN_SVG + ' Unlocked' : LOCK_SVG + ' Password required'}</span>
      </a>`;
    }).join('');
    show('home');
  }

  function renderGate(mode, cat) {
    els.gateTitle.textContent = mode === 'master' ? 'Master password' : cat.name;
    els.gateHint.textContent = mode === 'master'
      ? 'Unlocks every section for this browser session.'
      : 'Enter the password for this section.';
    els.crumb.textContent = mode === 'master' ? 'Unlock all sections' : cat.name;
    els.gateErr.hidden = true;
    els.pw.value = '';
    els.gateForm.dataset.mode = mode;
    els.gateForm.dataset.cat = cat ? cat.id : '';
    show('gate');
    setTimeout(() => els.pw.focus(), 30);
  }

  els.gateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = els.pw.value;
    if (!pw) return;
    els.gateBtn.disabled = true; els.gateBtn.textContent = 'Checking…'; els.gateErr.hidden = true;
    try {
      const { mode, cat } = els.gateForm.dataset;
      const ok = mode === 'master' ? await unlockWithMaster(pw) : await unlockCategory(cat, pw);
      if (ok) { location.hash = mode === 'master' ? '#/' : `#/c/${cat}`; route(); }
      else { els.gateErr.textContent = 'Incorrect password.'; els.gateErr.hidden = false; els.pw.select(); }
    } catch (err) {
      els.gateErr.textContent = err.message; els.gateErr.hidden = false;
    } finally {
      els.gateBtn.disabled = false; els.gateBtn.textContent = 'Unlock';
    }
  });

  /* ---------- Map ---------- */
  let map, cluster;
  const COLORS = { granted: '#1f8a5b', refused: '#c8453b', pending: '#d99a1e', other: '#7a8580' };
  function ensureMap() {
    if (map) { map.invalidateSize(); return; }
    map = L.map('map', { preferCanvas: true }).setView([53.4, -7.9], 7);
    const base = L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
      maxZoom: 19, subdomains: 'abcd',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
    }).addTo(map);
    const sat = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 19, attribution: 'Imagery &copy; Esri'
    });
    L.control.layers({ 'Map': base, 'Satellite': sat }, null, { position: 'topright' }).addTo(map);
    cluster = L.markerClusterGroup({ chunkedLoading: true, maxClusterRadius: 45, showCoverageOnHover: false });
    map.addLayer(cluster);
    let t;
    map.on('moveend', () => {
      if (!els.inView.checked || (map._popup && map.hasLayer(map._popup))) return;
      clearTimeout(t); t = setTimeout(() => apply({ refit: false }), 250);
    });
  }

  function popupHtml(r) {
    const rows = [
      ['Council', r.council], ['Type', titleCase(r.type)], ['Status', titleCase(r.status)],
      ['Received', fmtDate(r.received)], ['Decision due', fmtDate(r.due)], ['Decided', fmtDate(r.decided)],
      ['Permission expires', fmtDate(r.expires)], ['Floor area', r.floor ? `${Math.round(r.floor).toLocaleString()} m²` : ''],
      ['Site area', r.site ? `${r.site} ha` : ''], ['Appeal', r.appeal ? `${r.appeal} ${titleCase(r.appealStatus || '')}` : ''],
      ['Matched', (r.terms || []).join(', ')], ['Added to site', r.added ? fmtDate(Date.parse(r.added)) : '']
    ].filter(([, v]) => v);
    return `<div class="pop">
      <h3>${esc(r.ref)}</h3>
      <div class="muted">${esc(r.addr)}</div>
      <div style="margin-top:6px"><span class="badge ${outcomeOf(r)}">${esc(outcomeLabel(r))}</span></div>
      <p>${esc(r.desc)}</p>
      <dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      ${r.link ? `<a class="btn" href="${esc(r.link)}" target="_blank" rel="noopener">Open council file ↗</a>` : ''}
    </div>`;
  }

  function renderMap(records, refit) {
    cluster.clearLayers(); state.markers.clear();
    const ms = [];
    for (const r of records) {
      if (r.lat == null) continue;
      const m = L.circleMarker([r.lat, r.lng], { radius: 7, weight: 2, color: '#fff', fillColor: COLORS[outcomeOf(r)], fillOpacity: .95 });
      m.bindPopup(() => popupHtml(r), { maxWidth: 340, minWidth: 260 });
      m.on('popupopen', () => setActive(r.id));
      state.markers.set(r.id, m); ms.push(m);
    }
    cluster.addLayers(ms);
    if (refit && ms.length) {
      const b = cluster.getBounds();
      if (b.isValid()) map.fitBounds(b, { padding: [30, 30], maxZoom: 14 });
    }
  }

  /* ---------- Explorer ---------- */
  async function renderCategory(cat) {
    els.crumb.textContent = cat.name;
    document.title = `${cat.name} · RR Planning Intelligence`;
    const data = await getData(cat.id);
    if (!data) { renderGate('category', cat); return; }
    show('explorer');
    ensureMap();
    if (state.cat !== cat.id) {
      state.cat = cat.id;
      resetFilters(false);
      const councils = [...new Set(data.records.map((r) => r.council))].sort();
      els.council.innerHTML = '<option value="">All councils</option>' + councils.map((c) => `<option>${esc(c)}</option>`).join('');
      els.term.innerHTML = '<option value="">All phrases</option>' + data.terms.map((t) => {
        const n = data.records.filter((r) => r.terms.includes(t)).length;
        return `<option value="${esc(t)}">${esc(t)} (${n})</option>`;
      }).join('');
      apply({ refit: true });
    } else {
      map.invalidateSize();
    }
  }

  function resetFilters(run = true) {
    els.q.value = ''; els.term.value = ''; els.council.value = ''; els.since.value = '';
    els.outcome.value = ''; els.inView.checked = false; els.sort.value = 'received-desc';
    if (run) apply({ refit: true });
  }

  function parseTerms(q) {
    const out = []; const re = /"([^"]+)"|(\S+)/g; let m;
    while ((m = re.exec(q))) { const t = (m[1] || m[2]).trim().toLowerCase(); if (t) out.push(t); }
    return out;
  }

  function apply({ refit = false } = {}) {
    const data = state.data.get(state.cat);
    if (!data) return;
    state.terms = parseTerms(els.q.value);
    const term = els.term.value, council = els.council.value, outcome = els.outcome.value;
    const onlyNew = els.since.value === 'new';
    const since = els.since.value && !onlyNew ? Date.now() - +els.since.value * 864e5 : 0;
    const bounds = els.inView.checked ? map.getBounds() : null;

    const rows = data.records.filter((r) => {
      if (term && !r.terms.includes(term)) return false;
      if (council && r.council !== council) return false;
      if (since && (r.received || 0) < since) return false;
      if (onlyNew && r.added !== state.manifest.latestBatch) return false;
      if (outcome && outcomeOf(r) !== outcome) return false;
      if (bounds && (r.lat == null || !bounds.contains([r.lat, r.lng]))) return false;
      if (state.terms.length) {
        const hay = `${r.desc} ${r.addr} ${r.ref} ${r.council}`.toLowerCase();
        if (!state.terms.every((t) => hay.includes(t))) return false;
      }
      return true;
    });

    const [field, dir] = els.sort.value.split('-');
    const sgn = dir === 'asc' ? 1 : -1;
    rows.sort((a, b) => field === 'council'
      ? a.council.localeCompare(b.council) || (b.received || 0) - (a.received || 0)
      : sgn * ((a[field] || 0) - (b[field] || 0)));

    state.filtered = rows; state.page = 0;
    const mapped = rows.filter((r) => r.lat != null).length;
    els.summary.innerHTML = `<strong>${rows.length.toLocaleString()}</strong> of ${data.records.length.toLocaleString()} permissions` +
      (mapped < rows.length ? ` · ${rows.length - mapped} not mapped` : '');
    renderPage();
    if (!bounds) renderMap(rows, refit);
  }

  function highlight(text) {
    let html = esc(text);
    for (const t of state.terms) {
      const r = new RegExp(esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      html = html.replace(r, (m) => `<mark>${m}</mark>`);
    }
    return html;
  }

  function renderPage() {
    const rows = state.filtered;
    const start = state.page * PAGE_SIZE;
    const pageRows = rows.slice(start, start + PAGE_SIZE);
    els.list.innerHTML = pageRows.length ? pageRows.map((r) => `
      <li class="item" data-id="${r.id}" tabindex="0">
        <div class="row1"><span class="ref">${highlight(r.ref)}</span><span class="date">${fmtDate(r.received)}</span></div>
        <div class="addr">${highlight(r.addr || 'Address not given')}</div>
        <div class="desc">${highlight(r.desc)}</div>
        <div class="meta">${r.added && r.added === state.manifest.latestBatch ? '<span class="badge new">New</span>' : ''}<span class="badge ${outcomeOf(r)}">${esc(outcomeLabel(r))}</span>
          <span>${esc(shortCouncil(r.council))}</span>
          ${(r.terms || []).slice(0, 2).map((t) => `<span class="chip">${esc(t)}</span>`).join('')}
          ${r.lat == null ? '<span class="nomap">· not mapped</span>' : ''}</div>
      </li>`).join('')
      : '<li class="state">No permissions match these filters.<br>Try fewer keywords or clear the filters.</li>';
    const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    els.pageInfo.textContent = rows.length ? `Page ${state.page + 1} of ${pages}` : '';
    els.prev.disabled = state.page === 0;
    els.next.disabled = state.page + 1 >= pages;
    els.list.scrollTop = 0;
  }

  function setActive(id) {
    els.list.querySelectorAll('.item.active').forEach((n) => n.classList.remove('active'));
    const li = els.list.querySelector(`.item[data-id="${id}"]`);
    if (li) { li.classList.add('active'); li.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
  }

  function focusItem(id) {
    const r = state.filtered.find((x) => x.id === id);
    if (!r) return;
    const m = state.markers.get(id);
    if (m && cluster.hasLayer(m)) { cluster.zoomToShowLayer(m, () => m.openPopup()); return; }
    const pos = r.lat != null ? [r.lat, r.lng] : map.getCenter();
    if (r.lat != null) map.setView(pos, 15);
    L.popup({ maxWidth: 340, minWidth: 260 }).setLatLng(pos).setContent(popupHtml(r)).openOn(map);
    setActive(id);
  }

  function downloadCsv() {
    const cat = state.manifest.categories.find((c) => c.id === state.cat);
    const cols = [
      ['Application number', (r) => r.ref], ['Council', (r) => r.council], ['Address', (r) => r.addr],
      ['Description', (r) => r.desc], ['Type', (r) => r.type], ['Status', (r) => r.status], ['Decision', (r) => r.decision],
      ['Outcome', (r) => outcomeOf(r)], ['Received', (r) => iso(r.received)], ['Added to site', (r) => r.added], ['Decision due', (r) => iso(r.due)],
      ['Decided', (r) => iso(r.decided)], ['Expires', (r) => iso(r.expires)], ['Appeal', (r) => r.appeal],
      ['Floor area m2', (r) => r.floor], ['Site area ha', (r) => r.site], ['Matched phrases', (r) => (r.terms || []).join('; ')],
      ['Latitude', (r) => r.lat], ['Longitude', (r) => r.lng], ['Council file', (r) => r.link]
    ];
    function iso(ms) { return ms ? new Date(ms).toISOString().slice(0, 10) : ''; }
    const cell = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const csv = [cols.map((c) => c[0]).join(','), ...state.filtered.map((r) => cols.map(([, f]) => cell(f(r))).join(','))].join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' }));
    a.download = `RR-${cat.id}-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* ---------- Routing ---------- */
  async function route() {
    if (!state.manifest) return;
    const h = location.hash.replace(/^#\/?/, '');
    if (h === 'master') return renderGate('master');
    const m = h.match(/^c\/([\w-]+)/);
    const cat = m && state.manifest.categories.find((c) => c.id === m[1]);
    if (cat) {
      try { await renderCategory(cat); } catch (err) { renderHome(); els.homeMsg.textContent = err.message; els.homeMsg.hidden = false; }
    } else renderHome();
  }

  /* ---------- Events ---------- */
  let qTimer;
  els.q.addEventListener('input', () => { clearTimeout(qTimer); qTimer = setTimeout(() => apply({ refit: true }), 200); });
  document.getElementById('searchForm').addEventListener('submit', (e) => { e.preventDefault(); apply({ refit: true }); });
  ['term', 'council', 'since', 'outcome'].forEach((k) => els[k].addEventListener('change', () => apply({ refit: true })));
  els.sort.addEventListener('change', () => apply({ refit: false }));
  els.inView.addEventListener('change', () => apply({ refit: false }));
  els.reset.addEventListener('click', () => resetFilters());
  els.csv.addEventListener('click', downloadCsv);
  els.prev.addEventListener('click', () => { state.page--; renderPage(); });
  els.next.addEventListener('click', () => { state.page++; renderPage(); });
  els.list.addEventListener('click', (e) => { const li = e.target.closest('.item'); if (li) focusItem(+li.dataset.id); });
  els.list.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const li = e.target.closest('.item'); if (li) focusItem(+li.dataset.id); } });
  els.masterBtn.addEventListener('click', () => { location.hash = '#/master'; });
  els.lockAll.addEventListener('click', () => {
    state.keys = {}; state.data.clear(); state.cat = null; derived.clear();
    try { sessionStorage.removeItem(KEY_STORE); } catch {}
    location.hash = '#/'; route();
  });
  window.addEventListener('hashchange', route);

  /* ---------- Start ---------- */
  (async () => {
    try {
      const res = await fetch('data/manifest.json', { cache: 'no-cache' });
      if (!res.ok) throw new Error('not built');
      state.manifest = await res.json();
      els.freshness.textContent = `Updated ${fmtDate(Date.parse(state.manifest.updated))}`;
      route();
    } catch {
      show('home');
      els.masterBtn.hidden = true;
      els.homeMsg.hidden = false;
      els.homeMsg.innerHTML = 'No data yet. On GitHub, open the <strong>Actions</strong> tab, choose <strong>Weekly data update</strong> and click <strong>Run workflow</strong>. The data will appear here a few minutes later.';
    }
  })();
})();
