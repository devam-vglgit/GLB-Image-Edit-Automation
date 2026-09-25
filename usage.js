// ─────────────────────────────────────────────────────────────
// Generation log
//
// Records every SUCCESSFUL generation as one event: who ran it, when, how
// long it took, which engine/model/size, the token counts the provider
// reported, and the estimated cost. Regenerations are events too — they go
// through the same /api/generate route — so a batch of 5 followed by 2
// regenerations logs 7, i.e. images produced (and paid for).
//
// Stored as JSON Lines in data/usage.jsonl: one object per line, appended.
// Appending is O(1) regardless of how large the log grows, unlike rewriting
// a single JSON document on every generation.
//
// data/usage.json (the older aggregate format, which had no user
// attribution) is still read if present so historical counts aren't lost.
// Those rows surface under the user "(before tracking)".
// ─────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');
const pricing = require('./pricing');

const DATA_DIR = path.join(__dirname, 'data');
const EVENTS_FILE = path.join(DATA_DIR, 'usage.jsonl');
const LEGACY_FILE = path.join(DATA_DIR, 'usage.json');

const LEGACY_USER = '(before tracking)';

// Local calendar date as YYYY-MM-DD — string-comparable, so range filtering
// is a plain >= / <= on the key.
function dayKey(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function recordGeneration({ user, engine, model, size, durationMs, usage }) {
  if (!engine || !model) return;
  const now = new Date();
  const row = {
    ts: now.toISOString(),
    day: dayKey(now),
    user: user || 'unknown',
    engine,
    model,
    size: size || '',
    ms: Number(durationMs) || 0,
    inTok: (usage && usage.promptTokens) || 0,
    outTok: (usage && usage.outputTokens) || 0,
    cost: pricing.pricePerImage(engine, model, size)
  };
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.appendFileSync(EVENTS_FILE, JSON.stringify(row) + '\n', 'utf8');
  } catch (e) {
    // Never let a logging failure break an actual generation.
    console.error('[usage] could not append event:', e.message);
  }
}

function readEvents() {
  let raw;
  try { raw = fs.readFileSync(EVENTS_FILE, 'utf8'); }
  catch (e) {
    if (e.code !== 'ENOENT') console.warn('[usage] could not read event log:', e.message);
    return [];
  }
  const rows = [];
  raw.split('\n').forEach(line => {
    if (!line.trim()) return;
    // One malformed line shouldn't sink the whole report.
    try { rows.push(JSON.parse(line)); } catch (e) { /* skip */ }
  });
  return rows;
}

// Older aggregate format: { "2026-09-16": { gemini: { model: count } } }.
// Expanded into event-shaped rows so the report can treat everything the
// same way. No user, timing or token data existed back then.
function readLegacy() {
  let log;
  try { log = JSON.parse(fs.readFileSync(LEGACY_FILE, 'utf8')); }
  catch (e) { return []; }
  const rows = [];
  Object.entries(log).forEach(([day, engines]) => {
    Object.entries(engines || {}).forEach(([engine, models]) => {
      Object.entries(models || {}).forEach(([model, count]) => {
        for (let i = 0; i < count; i++) {
          rows.push({
            ts: '', day, user: LEGACY_USER, engine, model, size: '',
            ms: 0, inTok: 0, outTok: 0,
            cost: pricing.pricePerImage(engine, model, '')
          });
        }
      });
    });
  });
  return rows;
}

// Filtered aggregation for the UI.
//   from/to  — YYYY-MM-DD, inclusive; omit either for an open-ended range
//   engines  — engine names; each means EVERY model of that engine,
//              including ones no longer offered in the UI
//   models   — specific "engine:model" strings
//   users    — usernames; omit for everyone
//
// engines and models are a UNION (ticking the Gemini header plus two GPT
// models means "all Gemini plus those two"). The user filter is applied on
// top of that, as an AND.
function query({ from, to, models, engines, users } = {}) {
  const wantedModels = Array.isArray(models) && models.length ? new Set(models) : null;
  const wantedEngines = Array.isArray(engines) && engines.length ? new Set(engines) : null;
  const wantedUsers = Array.isArray(users) && users.length ? new Set(users) : null;
  const filteringModels = !!(wantedModels || wantedEngines);

  const matchesModel = (engine, model) =>
    !filteringModels
    || (wantedEngines && wantedEngines.has(engine))
    || (wantedModels && wantedModels.has(`${engine}:${model}`));

  const rows = readEvents().concat(readLegacy());

  const days = {};
  const byModel = {};
  const byUser = {};
  let total = 0, cost = 0, msTotal = 0, timedCount = 0;

  rows.forEach(r => {
    if (from && r.day < from) return;
    if (to && r.day > to) return;
    if (!matchesModel(r.engine, r.model)) return;
    if (wantedUsers && !wantedUsers.has(r.user)) return;

    const id = `${r.engine}:${r.model}`;
    total += 1;
    cost += r.cost || 0;
    if (r.ms > 0) { msTotal += r.ms; timedCount += 1; }

    if (!days[r.day]) days[r.day] = { day: r.day, total: 0, cost: 0, models: {} };
    days[r.day].total += 1;
    days[r.day].cost += r.cost || 0;
    days[r.day].models[id] = (days[r.day].models[id] || 0) + 1;

    if (!byModel[id]) byModel[id] = 0;
    byModel[id] += 1;

    if (!byUser[r.user]) byUser[r.user] = { user: r.user, total: 0, cost: 0, ms: 0, timed: 0 };
    byUser[r.user].total += 1;
    byUser[r.user].cost += r.cost || 0;
    if (r.ms > 0) { byUser[r.user].ms += r.ms; byUser[r.user].timed += 1; }
  });

  const byDay = Object.values(days).sort((a, b) => (a.day < b.day ? 1 : -1));
  const users_ = Object.values(byUser)
    .map(u => ({
      user: u.user,
      total: u.total,
      cost: u.cost,
      avgMs: u.timed ? Math.round(u.ms / u.timed) : 0
    }))
    .sort((a, b) => b.total - a.total);

  return {
    total,
    cost,
    currency: pricing.currency(),
    avgMs: timedCount ? Math.round(msTotal / timedCount) : 0,
    byDay,
    byModel,
    byUser: users_
  };
}

// Every username that appears in the log — lets the report offer a user
// filter that includes people who have since been deleted.
function knownUsers() {
  const set = new Set();
  readEvents().forEach(r => set.add(r.user));
  if (fs.existsSync(LEGACY_FILE)) set.add(LEGACY_USER);
  return [...set].sort();
}

module.exports = { recordGeneration, query, dayKey, knownUsers, LEGACY_USER };
