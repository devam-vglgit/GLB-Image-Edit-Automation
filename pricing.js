// ─────────────────────────────────────────────────────────────
// Per-image price table
//
// Expenses are estimated as (images generated x price per image), which is
// how the providers actually bill for image generation and therefore the
// easiest figure to reconcile against a real invoice.
//
// Seeded into data/pricing.json on first run so rates can be corrected
// without a code change — prices move, and the OpenAI figures in particular
// are estimates that should be checked against a real bill.
//
// Shape (USD per image):
//   { "gemini:gemini-3-pro-image": { "default": 0.134, "4K": 0.24 } }
// Lookup order: exact size match -> "default" -> 0 (unpriced).
// ─────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const PRICING_FILE = path.join(DATA_DIR, 'pricing.json');

// Gemini figures match Google's published per-image prices (and line up with
// the token maths: 1,290 output tokens x $30/1M = $0.039 for Nano Banana).
// OpenAI does not publish a flat per-image price the same way — these are
// working estimates and should be confirmed against an invoice.
const DEFAULT_PRICING = {
  _readme: 'USD per generated image. "default" applies unless a size key (1K/2K/4K) matches. Edit and restart to update. OpenAI values are estimates — confirm against a real invoice.',
  currency: 'USD',
  rates: {
    'gemini:gemini-3-pro-image':          { default: 0.134, '1K': 0.134, '2K': 0.134, '4K': 0.24 },
    'gemini:gemini-3.1-flash-image':      { default: 0.067 },
    'gemini:gemini-2.5-flash-image':      { default: 0.039 },
    'gemini:gemini-3.1-flash-lite-image': { default: 0.034 },
    'openai:gpt-image-1':                 { default: 0.04 },
    'openai:gpt-image-1-mini':            { default: 0.02 },
    'openai:gpt-image-2.5-sunburst':      { default: 0.04 },
    'openai:gpt-image-2.5-flare':         { default: 0.02 }
  }
};

let cache = null;

function load() {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(PRICING_FILE, 'utf8'));
    if (!cache.rates) cache.rates = {};
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn('[pricing] could not read table, using defaults:', e.message);
    cache = DEFAULT_PRICING;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(PRICING_FILE, JSON.stringify(DEFAULT_PRICING, null, 2), 'utf8');
    } catch (err) { console.warn('[pricing] could not write default table:', err.message); }
  }
  return cache;
}

// USD for one image on this engine/model at this output size. Unknown models
// return 0 rather than guessing, so an unpriced model shows as zero cost
// instead of silently inventing a number.
function pricePerImage(engine, model, size) {
  const rates = load().rates || {};
  const entry = rates[`${engine}:${model}`];
  if (!entry) return 0;
  if (size && typeof entry[size] === 'number') return entry[size];
  return typeof entry.default === 'number' ? entry.default : 0;
}

function currency() { return load().currency || 'USD'; }

// Exposed so the report can flag models it couldn't price.
function isPriced(engine, model) {
  return !!(load().rates || {})[`${engine}:${model}`];
}

module.exports = { pricePerImage, currency, isPriced };
