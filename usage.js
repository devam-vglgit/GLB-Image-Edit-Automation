// ─────────────────────────────────────────────────────────────
// Daily generation counter
//
// Records every SUCCESSFUL image generation, bucketed by calendar day and
// by engine + model. Regenerations are counted too — they go through the
// same /api/generate route, so a batch of 5 followed by 2 regenerations
// records 7, which is the intent: this counts images produced (and paid
// for), not images uploaded.
//
// Stored as JSON in data/usage.json. That directory is git-ignored, so the
// log is per-deployment runtime data and survives `git pull` / restarts.
//
// Shape:
//   { "2026-09-16": { "gemini": { "gemini-3-pro-image": 12 },
//                     "openai": { "gpt-image-1": 5 } } }
// ─────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const USAGE_FILE = path.join(DATA_DIR, 'usage.json');

let usage = null;   // in-memory mirror of the file, loaded once at startup

function load() {
  if (usage) return usage;
  try {
    usage = JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn('[usage] could not read log, starting fresh:', e.message);
    usage = {};
  }
  return usage;
}

// Read-modify-write is done synchronously and without awaiting in between,
// so concurrent generations (3 workers per user, several users) can't
// interleave and lose each other's increments.
function save() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(USAGE_FILE, JSON.stringify(usage, null, 2), 'utf8');
  } catch (e) {
    // Never let a logging failure break an actual generation.
    console.error('[usage] could not write log:', e.message);
  }
}

// Local calendar date as YYYY-MM-DD (string-comparable, so range filtering
// is a plain >= / <= on the key).
function dayKey(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function recordGeneration(engine, model) {
  if (!engine || !model) return;
  const log = load();
  const key = dayKey();
  if (!log[key]) log[key] = {};
  if (!log[key][engine]) log[key][engine] = {};
  log[key][engine][model] = (log[key][engine][model] || 0) + 1;
  save();
}

// Filtered aggregation for the UI.
//   from/to  — YYYY-MM-DD, inclusive; omit either for an open-ended range
//   models   — array of "engine:model" strings; omit/empty means all
// Returns totals plus per-day and per-model breakdowns, days newest first.
function query({ from, to, models } = {}) {
  const log = load();
  const wanted = Array.isArray(models) && models.length ? new Set(models) : null;

  const byDay = [];
  const byModel = {};
  let total = 0;

  Object.keys(log).sort().reverse().forEach(day => {
    if (from && day < from) return;
    if (to && day > to) return;

    let dayTotal = 0;
    const dayModels = {};
    Object.entries(log[day]).forEach(([engine, modelCounts]) => {
      Object.entries(modelCounts).forEach(([model, count]) => {
        const id = `${engine}:${model}`;
        if (wanted && !wanted.has(id)) return;
        dayTotal += count;
        dayModels[id] = (dayModels[id] || 0) + count;
        byModel[id] = (byModel[id] || 0) + count;
      });
    });

    if (dayTotal > 0) byDay.push({ day, total: dayTotal, models: dayModels });
    total += dayTotal;
  });

  return { total, byDay, byModel };
}

module.exports = { recordGeneration, query, dayKey };
