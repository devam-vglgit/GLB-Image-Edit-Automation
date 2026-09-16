// ─────────────────────────────────────────────────────────────
// AI-VGL-Studio backend
// Holds provider API keys in server env ONLY and proxies image
// generation requests to Google Gemini and OpenAI.
// The browser never sees or sends an API key.
// ─────────────────────────────────────────────────────────────
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Jimp = require('jimp');
const { padToSquare } = require('./squarepad');
const { liftMetalBlacks } = require('./metalfix');
const usageLog = require('./usage');

const app = express();
const PORT = process.env.PORT || 3000;
// Trust one reverse-proxy hop (Cloudflare / nginx in front of this server)
// so req.secure correctly reflects the original client's protocol via
// X-Forwarded-Proto, instead of always reading as HTTP at the origin.
app.set('trust proxy', 1);

// ── Security headers (CSP, X-Frame-Options, X-Content-Type-Options,
// Referrer-Policy, Permissions-Policy, HSTS, etc.) ──
// CSP is scoped to what this app actually uses: the frontend is single
// self-contained HTML files with inline <script>/<style> (hence
// 'unsafe-inline' on script/style — tightening that would mean splitting
// out every inline block into external files with nonces, a larger
// follow-up change), Google Fonts, and the Cloudflare Turnstile widget
// (script + the iframe it renders + the API calls it makes).
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://challenges.cloudflare.com'],
      // The UI wires its buttons/icons with inline onclick="..." attributes.
      // Helmet defaults this to 'none', which silently kills every click —
      // 'unsafe-inline' on scriptSrc alone does NOT cover event-handler attrs.
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'", 'https://challenges.cloudflare.com'],
      frameSrc: ['https://challenges.cloudflare.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));

// Permissions-Policy — helmet does NOT set this one, so it must be added
// explicitly (its absence was flagged in the VAPT reassessment). This app
// only uploads image files and renders the Turnstile widget; it needs none
// of the powerful browser features below, so all are denied outright.
// Only features current browsers actually recognise are listed — including
// unsupported ones (ambient-light-sensor, battery, document-domain) makes
// Chrome log "Unrecognized feature" warnings without adding any protection.
const PERMISSIONS_POLICY = [
  'accelerometer=()', 'autoplay=()', 'camera=()', 'display-capture=()',
  'encrypted-media=()', 'gamepad=()', 'geolocation=()', 'gyroscope=()',
  'magnetometer=()', 'microphone=()', 'midi=()', 'payment=()',
  'picture-in-picture=()', 'screen-wake-lock=()', 'serial=()', 'usb=()',
  'xr-spatial-tracking=()'
].join(', ');
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
  next();
});

// ── Auth (multiple fixed username/password pairs, defined in .env) ──
// Format: AUTH_USERS="alice:pass1,bob:pass2,admin:studioe69" — add or
// remove a "user:pass" entry and restart the server to add/remove a login.
// If AUTH_USERS isn't set, falls back to the single legacy AUTH_USERNAME/
// AUTH_PASSWORD pair (or admin/studioe69) so existing setups keep working.
function loadAuthUsers() {
  const raw = process.env.AUTH_USERS || '';
  const users = new Map();
  raw.split(',').map(s => s.trim()).filter(Boolean).forEach(pair => {
    const idx = pair.indexOf(':');
    if (idx > -1) users.set(pair.slice(0, idx), pair.slice(idx + 1));
  });
  if (users.size === 0) {
    users.set(process.env.AUTH_USERNAME || 'admin', process.env.AUTH_PASSWORD || 'studioe69');
  }
  return users;
}
const AUTH_USERS = loadAuthUsers();
const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000; // 12 hours
// A random secret per process start is fine for signing — it just means
// everyone is logged out on restart. Set SESSION_SECRET in .env to persist
// sessions across restarts instead.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function signSession(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  const a = Buffer.from(sig || ''), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
// Adds the Secure flag only when the request actually arrived over HTTPS
// (directly, or via X-Forwarded-Proto from the trusted proxy hop above) —
// so login still works over plain HTTP during local/IP-based testing, but
// automatically hardens itself once served over HTTPS in production.
function sessionCookie(req, value, maxAgeSeconds) {
  const secure = req.secure ? '; Secure' : '';
  return `session=${value}; HttpOnly; Path=/; Max-Age=${maxAgeSeconds}; SameSite=Lax${secure}`;
}

function requireAuth(req, res, next) {
  const session = verifySession(parseCookies(req).session);
  if (session) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated.' });
  return res.redirect('/login.html');
}

// ── Cloudflare Turnstile (bot-check on the login form) ──
// Not enforced until TURNSTILE_SECRET_KEY is set in .env — until then
// /api/login skips verification entirely, so login keeps working as-is.
// Get both keys from the Cloudflare dashboard → Turnstile → add a widget.
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

async function verifyTurnstile(token, remoteIp) {
  if (!TURNSTILE_SECRET_KEY) return true; // not configured yet — allow through
  if (!token) return false;
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token, remoteip: remoteIp || '' })
    });
    const data = await resp.json();
    return !!data.success;
  } catch (e) {
    console.error('[turnstile] verification request failed:', e.message);
    return false;
  }
}

// ── Prompt storage ──────────────────────────────────────────
// Each prompt's text lives in its own .md file under public/prompts/, and
// public/prompts.json maps id → title/file/keepScene. The .md file IS the
// live store: the app reads straight from it every time /api/prompts is
// requested, and any edit made from the UI is written straight back to it.
// New prompts created from the UI get a fresh .md file auto-created here.
const PUBLIC_DIR = path.join(__dirname, 'public');
const PROMPTS_DIR = path.join(PUBLIC_DIR, 'prompts');
const MANIFEST_FILE = path.join(PUBLIC_DIR, 'prompts.json');

function loadManifest() {
  try { return JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8')); }
  catch (e) { console.warn('No/invalid prompts.json manifest:', e.message); return { gemini: [], openai: [] }; }
}
function saveManifest(manifest) {
  fs.writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2), 'utf8');
}

// Read the current library straight from the .md files on disk.
function readLibraryFromFiles() {
  const manifest = loadManifest();
  const hydrate = list => (list || []).map(item => {
    let text = '';
    try { text = fs.readFileSync(path.join(PUBLIC_DIR, item.file), 'utf8').trim(); }
    catch (e) { console.warn('Cannot read prompt file', item.file, e.message); }
    return { id: item.id, title: item.title, text, keepScene: !!item.keepScene };
  });
  return { gemini: hydrate(manifest.gemini), openai: hydrate(manifest.openai) };
}

// Write an edited library back out: each prompt's text is saved to its .md
// file, and title/keepScene changes update prompts.json. A prompt with no
// existing manifest entry (newly added from the UI) gets a new .md file.
// Any prompt that was REMOVED from the list (deleted in the UI) has its
// .md file deleted too, so disk never keeps orphaned prompt files around.
function writeLibraryToFiles(lib) {
  const manifest = loadManifest();
  fs.mkdirSync(PROMPTS_DIR, { recursive: true });
  for (const engine of ['gemini', 'openai']) {
    const existingById = new Map((manifest[engine] || []).map(e => [e.id, e]));
    const keptIds = new Set((lib[engine] || []).map(p => p.id));

    for (const [id, entry] of existingById) {
      if (!keptIds.has(id)) {
        try { fs.unlinkSync(path.join(PUBLIC_DIR, entry.file)); }
        catch (e) { console.warn('Could not delete prompt file', entry.file, e.message); }
      }
    }

    manifest[engine] = (lib[engine] || []).map(p => {
      let entry = existingById.get(p.id);
      if (!entry) {
        const safeName = String(p.id).replace(/[^a-z0-9_-]/gi, '') || ('p' + Math.random().toString(36).slice(2, 9));
        entry = { id: p.id, title: p.title, file: `prompts/${engine}-${safeName}.md` };
      }
      entry.title = p.title;
      entry.keepScene = !!p.keepScene;
      fs.writeFileSync(path.join(PUBLIC_DIR, entry.file), p.text + '\n', 'utf8');
      return entry;
    });
  }
  saveManifest(manifest);
}
// Basic shape validation for an incoming library payload.
// ── Rate-limit-aware fetch ──
// Retries with exponential backoff on 429 (rate limit) and 503 (transient
// overload). Honours the API's Retry-After header when present. This is what
// lets a large batch survive hitting a per-minute quota instead of failing
// that image outright.
const RETRY_MAX = Number(process.env.GEMINI_RETRY_MAX) || 4;
const RETRY_BASE_MS = Number(process.env.GEMINI_RETRY_BASE_MS) || 2000;
async function fetchWithRetry(url, opts) {
  for (let attempt = 0; ; attempt++) {
    const resp = await fetch(url, opts);
    if (resp.ok || (resp.status !== 429 && resp.status !== 503) || attempt >= RETRY_MAX) return resp;
    const retryAfterHeader = Number(resp.headers.get('retry-after'));
    const wait = retryAfterHeader > 0 ? retryAfterHeader * 1000 : RETRY_BASE_MS * Math.pow(2, attempt);
    console.warn(`[rate-limit] status ${resp.status}, retry ${attempt + 1}/${RETRY_MAX} in ${wait}ms`);
    await new Promise(r => setTimeout(r, wait));
  }
}

function sanitizeLibrary(body) {
  const clean = eng => Array.isArray(body?.[eng])
    ? body[eng]
        .map(p => ({ id: String(p.id || ('p' + Math.random().toString(36).slice(2, 9))), title: String(p.title || '').slice(0, 200), text: String(p.text || '').slice(0, 40000), keepScene: !!p.keepScene }))
        .filter(p => p.title || p.text)
    : [];
  return { gemini: clean('gemini'), openai: clean('openai') };
}


// Model ids (override via env if the providers rename them)
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash-image';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-image-1';

// Output resolution for Gemini image models: "1K", "2K" or "4K" (Pro supports up to 4K).
// 2K gives sharp, zoom-friendly detail at a reasonable file size.
const GEMINI_IMAGE_SIZE = process.env.GEMINI_IMAGE_SIZE || '2K';
// Output aspect ratio for Gemini images (square by default, per team spec).
const GEMINI_ASPECT = process.env.GEMINI_ASPECT || '1:1';
const GEMINI_SIZE_OPTIONS = [
  { id: '1K', label: '1K', hint: 'Fastest & smallest files' },
  { id: '2K', label: '2K', hint: 'Sharp, zoom-friendly (recommended)' },
  { id: '4K', label: '4K', hint: 'Maximum detail — large files, pricier' }
];
const GEMINI_SIZE_IDS = GEMINI_SIZE_OPTIONS.map(s => s.id);

// Temperature: how much the model creatively reinterprets vs. sticks literally
// to the source image + prompt. Lower = more faithful (less re-posing/rotation/
// invented detail); higher = more variation. Default '' means "don't send it" —
// leaves the model's own default behaviour completely unchanged unless picked.
const GEMINI_TEMPERATURE_OPTIONS = [
  { id: '', label: 'Model default', hint: 'No override — current behaviour' },
  { id: '0.2', label: 'Low (0.2)', hint: 'Most faithful — least creative drift' },
  { id: '0.5', label: 'Medium (0.5)', hint: 'Balanced' },
  { id: '0.9', label: 'High (0.9)', hint: 'More creative — more variation' }
];
const GEMINI_TEMPERATURE_IDS = GEMINI_TEMPERATURE_OPTIONS.map(t => t.id);

// Gemini image models the user can pick from in the UI dropdown.
// Each: id (API model id) + label (friendly name) + hint (when to use).
// cost = approx per-image API price (standard, non-batch). Verify at
// https://ai.google.dev/gemini-api/docs/pricing — prices change.
const GEMINI_MODEL_OPTIONS = [
  { id: 'gemini-3-pro-image',        label: 'Nano Banana Pro',      cost: '≈$0.134/img (2K) · $0.24 (4K)', hint: 'Highest quality — best for hero shots (slower, pricier)' },
  { id: 'gemini-3.1-flash-image',    label: 'Nano Banana 2',        cost: '≈$0.067/img (1K)',              hint: 'Newer flash — strong quality, faster' },
  { id: 'gemini-2.5-flash-image',    label: 'Nano Banana',          cost: '≈$0.039/img · retires Oct 2026', hint: 'Fast & economical — great for large batches' },
  { id: 'gemini-3.1-flash-lite-image', label: 'Nano Banana 2 Lite', cost: '≈$0.034/img (1K)',              hint: 'Fastest & cheapest — quick drafts' }
];
// Ensure the env-configured default is always a selectable option.
if (!GEMINI_MODEL_OPTIONS.some(m => m.id === GEMINI_MODEL)) {
  GEMINI_MODEL_OPTIONS.unshift({ id: GEMINI_MODEL, label: GEMINI_MODEL, hint: 'From server config' });
}
const GEMINI_MODEL_IDS = GEMINI_MODEL_OPTIONS.map(m => m.id);

// OpenAI image models the user can pick from in the UI dropdown. All four
// are confirmed to support the images/edits endpoint (image input + editing,
// which this app always uses) per OpenAI's API reference. gpt-image-1 and
// gpt-image-1-mini are being phased out in favour of the 2.5 models (exact
// shutdown date unconfirmed as of writing — check platform.openai.com/docs
// /deprecations before removing the older ones outright).
const OPENAI_MODEL_OPTIONS = [
  { id: 'gpt-image-1', label: 'GPT Image 1', hint: 'Current default — being deprecated, migrate when convenient' },
  { id: 'gpt-image-1-mini', label: 'GPT Image 1 Mini', hint: 'Cheaper/faster — also being deprecated' },
  { id: 'gpt-image-2.5-sunburst', label: 'GPT Image 2.5 Sunburst', hint: 'Most capable — generation and editing' },
  { id: 'gpt-image-2.5-flare', label: 'GPT Image 2.5 Flare', hint: 'Fast, high-quality everyday generation' }
];
if (!OPENAI_MODEL_OPTIONS.some(m => m.id === OPENAI_MODEL)) {
  OPENAI_MODEL_OPTIONS.unshift({ id: OPENAI_MODEL, label: OPENAI_MODEL, hint: 'From server config' });
}
const OPENAI_MODEL_IDS = OPENAI_MODEL_OPTIONS.map(m => m.id);

// Fidelity: OpenAI's input_fidelity parameter on /images/edits, controlling
// how faithfully the output preserves the input image's details. Default ''
// means "don't send it" — leaves the model's own default behaviour unchanged
// unless picked. 'high' is the one most likely to help this app's exact
// geometry/design preservation goals, at the cost of more tokens per image.
const OPENAI_FIDELITY_OPTIONS = [
  { id: '', label: 'Model default', hint: 'No override — current behaviour' },
  { id: 'low', label: 'Low', hint: 'Faster / cheaper — less faithful to the input image' },
  { id: 'high', label: 'High', hint: 'Most faithful to the input image — uses more tokens' }
];
const OPENAI_FIDELITY_IDS = OPENAI_FIDELITY_OPTIONS.map(f => f.id);

const GEMINI_KEY = process.env.GEMINI_API_KEY || '';
const OPENAI_KEY = process.env.OPENAI_API_KEY || '';

// Base64 jewellery images are large — allow a generous JSON body.
app.use(express.json({ limit: '25mb' }));

// ── Public auth routes (must come before the auth gate below) ──
// Lets the login page know whether to render the Turnstile widget, and with
// which site key. Site key is not secret — safe to expose to the browser.
app.get('/api/turnstile-config', (req, res) => {
  res.json({ enabled: Boolean(TURNSTILE_SECRET_KEY), siteKey: TURNSTILE_SITE_KEY });
});
app.post('/api/login', async (req, res) => {
  const { username, password, cfTurnstileToken } = req.body || {};
  const humanVerified = await verifyTurnstile(cfTurnstileToken, req.ip);
  if (!humanVerified) return res.status(401).json({ error: 'Bot check failed. Please retry the challenge.' });
  if (AUTH_USERS.has(username) && AUTH_USERS.get(username) === password) {
    const token = signSession({ user: username, exp: Date.now() + SESSION_MAX_AGE_MS });
    res.setHeader('Set-Cookie', sessionCookie(req, token, Math.floor(SESSION_MAX_AGE_MS / 1000)));
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Invalid username or password.' });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
  res.json({ ok: true });
});
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// Everything below this line requires a valid session.
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public')));

// Which engines have a key configured — lets the UI disable the rest.
app.get('/api/config', (req, res) => {
  res.json({
    engines: {
      gemini: Boolean(GEMINI_KEY),
      openai: Boolean(OPENAI_KEY)
    },
    models: { gemini: GEMINI_MODEL, openai: OPENAI_MODEL },
    geminiModels: GEMINI_MODEL_OPTIONS,      // selectable options for the dropdown
    geminiModelDefault: GEMINI_MODEL,        // the env default (pre-selected)
    geminiSizes: GEMINI_SIZE_OPTIONS,        // selectable output resolutions
    geminiSizeDefault: GEMINI_IMAGE_SIZE,
    geminiTemperatures: GEMINI_TEMPERATURE_OPTIONS,  // selectable temperature presets
    geminiTemperatureDefault: '',                    // '' = no override, model's own default
    openaiModels: OPENAI_MODEL_OPTIONS,      // selectable options for the dropdown
    openaiModelDefault: OPENAI_MODEL,        // the env default (pre-selected)
    openaiFidelities: OPENAI_FIDELITY_OPTIONS,  // selectable input_fidelity presets
    openaiFidelityDefault: ''                   // '' = no override, model's own default
  });
});

// Return the current editable prompt library, read straight from the .md files.
app.get('/api/prompts', (req, res) => {
  res.json(readLibraryFromFiles());
});

// Save the edited prompt library — writes each prompt's text back to its .md file.
app.put('/api/prompts', (req, res) => {
  try {
    const lib = sanitizeLibrary(req.body);
    writeLibraryToFiles(lib);
    res.json({ ok: true, library: readLibraryFromFiles() });
  } catch (e) {
    // Never relay e.message here — fs errors (ENOENT/EACCES) embed full
    // server file paths, which shouldn't reach the client. Full detail
    // still goes to the server log for debugging.
    console.error('[prompts:save]', e);
    res.status(500).json({ error: 'Could not save prompts. Check the server log for details.' });
  }
});

// The .md files are the live store now, so "reset" just re-reads them —
// kept for UI compatibility (the Settings modal calls this after a save).
app.post('/api/prompts/reset', (req, res) => {
  try {
    res.json({ ok: true, library: readLibraryFromFiles() });
  } catch (e) {
    console.error('[prompts:reset]', e);
    res.status(500).json({ error: 'Could not reset prompts. Check the server log for details.' });
  }
});

// Generation counts, filtered by date range, whole engine, and/or model.
//   ?from=YYYY-MM-DD&to=YYYY-MM-DD
//   &engines=gemini            → every Gemini model
//   &models=openai:gpt-image-1 → that specific model
// engines and models are a union, so "all Gemini + two GPT models" is
// engines=gemini&models=openai:gpt-image-1,openai:gpt-image-2.5-flare.
// All params optional — omitting them returns everything ever recorded.
app.get('/api/usage', (req, res) => {
  try {
    const { from, to, models, engines } = req.query;
    const isDate = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
    const csv = v => (typeof v === 'string' && v.trim())
      ? v.split(',').map(s => s.trim()).filter(Boolean)
      : [];
    res.json(usageLog.query({
      from: isDate(from) ? from : undefined,
      to: isDate(to) ? to : undefined,
      models: csv(models),
      // only real engine names — ignore anything else a client might send
      engines: csv(engines).filter(e => e === 'gemini' || e === 'openai')
    }));
  } catch (e) {
    console.error('[usage:query]', e);
    res.status(500).json({ error: 'Could not read usage data. Check the server log for details.' });
  }
});

app.post('/api/generate', async (req, res) => {
  try {
    const { engine, image, prompt, ratio, model, imageSize, temperature, fidelity, keepScene } = req.body || {};
    if (!image || !prompt) return res.status(400).json({ error: 'image and prompt are required.' });
    if (!engine || !['gemini', 'openai'].includes(engine)) return res.status(400).json({ error: 'engine must be "gemini" or "openai".' });

    // For Gemini, honour requested model/resolution/temperature only if in the allow-lists; else fall back to env defaults.
    const geminiModel = (model && GEMINI_MODEL_IDS.includes(model)) ? model : GEMINI_MODEL;
    const geminiSize = (imageSize && GEMINI_SIZE_IDS.includes(imageSize)) ? imageSize : GEMINI_IMAGE_SIZE;
    const geminiTemperature = GEMINI_TEMPERATURE_IDS.includes(temperature) ? temperature : '';
    // Same pattern for OpenAI: only honour the requested model/fidelity if it's in the allow-list.
    const openaiModel = (model && OPENAI_MODEL_IDS.includes(model)) ? model : OPENAI_MODEL;
    const openaiFidelity = OPENAI_FIDELITY_IDS.includes(fidelity) ? fidelity : '';

    const out = engine === 'gemini'
      ? await generateGemini(image, prompt, geminiModel, geminiSize, geminiTemperature)
      : await generateOpenAI(image, prompt, ratio, openaiModel, openaiFidelity);

    // On-model / worn shots (keepScene) keep their real scene, so the white-background
    // post-processing (metal black-lift) must be SKIPPED — those assume a
    // product-on-pure-white image and would damage a scene photo.
    // Square crop is disabled: output keeps the same aspect ratio as the input.
    if (!keepScene && out && out.image) {
      out.image = await liftMetalBlacks(out.image);   // lift near-black metal reflections
    }

    // Count it only once an image actually came back. Regenerations land here
    // too (they re-POST to this same route), so each one adds to the tally.
    if (out && out.image) {
      usageLog.recordGeneration(engine, engine === 'gemini' ? geminiModel : openaiModel);
    }

    res.json(out);
  } catch (err) {
    console.error('[generate]', err);
    // err.status/.message are only trusted when the error was deliberately
    // thrown via httpErr() with an intentional, user-safe message (e.g. "not
    // configured", an upstream provider error). Anything else is unexpected
    // (a bug, an fs error, etc.) and must not leak its raw message/paths.
    if (typeof err.status === 'number') {
      res.status(err.status).json({ error: err.message || 'Generation failed.' });
    } else {
      res.status(500).json({ error: 'Generation failed. Check the server log for details.' });
    }
  }
});

// ── Gemini image generation ──
async function generateGemini(imageDataUrl, prompt, model, size, temperature) {
  if (!GEMINI_KEY) throw httpErr(503, 'Gemini is not configured on the server (missing GEMINI_API_KEY).');
  const modelId = model || GEMINI_MODEL;
  const imageSize = size || GEMINI_IMAGE_SIZE;
  const { b64, mime } = splitDataUrl(imageDataUrl);
  const generationConfig = { imageConfig: { imageSize } };   // aspect handled by backend square-pad
  if (temperature !== '' && temperature != null) generationConfig.temperature = Number(temperature);
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(GEMINI_KEY)}`;
  const resp = await fetchWithRetry(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ inline_data: { mime_type: mime, data: b64 } }, { text: prompt }] }],
      generationConfig
    })
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    const msg = resp.status === 429
      ? 'Gemini rate limit reached — retried automatically but still limited. Try again shortly, or slow down the batch.'
      : (e.error?.message || `Gemini API error ${resp.status}`);
    throw httpErr(resp.status, msg);
  }
  const data = await resp.json();
  const parts = data.candidates?.[0]?.content?.parts || [];
  let imagePart = null, textPart = '';
  for (const part of parts) {
    const inl = part.inlineData || part.inline_data;
    if (inl && inl.data) imagePart = inl;
    else if (part.text) textPart += part.text;
  }
  if (!imagePart) throw httpErr(502, textPart || 'Gemini returned no image.');
  const outMime = imagePart.mimeType || imagePart.mime_type || 'image/png';
  const u = data.usageMetadata || {};
  const usage = {
    promptTokens: u.promptTokenCount || 0,
    outputTokens: u.candidatesTokenCount || 0,
    totalTokens: u.totalTokenCount || ((u.promptTokenCount || 0) + (u.candidatesTokenCount || 0))
  };
  return { image: `data:${outMime};base64,${imagePart.data}`, note: textPart, usage, model: modelId };
}

// ── OpenAI gpt-image-1 edits ──
async function generateOpenAI(imageDataUrl, prompt, ratio, model, fidelity) {
  if (!OPENAI_KEY) throw httpErr(503, 'OpenAI is not configured on the server (missing OPENAI_API_KEY).');
  const openaiModel = model || OPENAI_MODEL;
  const { b64 } = splitDataUrl(imageDataUrl);
  const buf = Buffer.from(b64, 'base64');
  // Re-encode to a proper RGBA PNG. OpenAI's edit endpoint rejects mismatched
  // formats/modes ("Invalid image file or mode"), e.g. a JPEG sent as .png, so
  // we normalise the input to a valid PNG before uploading.
  let pngBuf = buf;
  try { pngBuf = await (await Jimp.read(buf)).getBufferAsync(Jimp.MIME_PNG); }
  catch (e) { console.warn('[openai] PNG re-encode failed, sending raw:', e.message); }
  const fd = new FormData();
  fd.append('model', openaiModel);
  fd.append('image', new Blob([pngBuf], { type: 'image/png' }), 'input.png');
  fd.append('prompt', prompt);
  const sizeMap = { '1:1': '1024x1024', '4:5': '1024x1536', '16:9': '1536x1024' };
  if (sizeMap[ratio]) fd.append('size', sizeMap[ratio]);
  // input_fidelity: how faithfully the output preserves the input image's
  // details ('high'/'low'). Only sent when explicitly picked — omitting it
  // leaves the model's own default behaviour unchanged.
  if (fidelity) fd.append('input_fidelity', fidelity);

  const resp = await fetchWithRetry('https://api.openai.com/v1/images/edits', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_KEY}` },
    body: fd
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    const msg = resp.status === 429
      ? 'OpenAI rate limit reached — retried automatically but still limited. Try again shortly, or slow down the batch.'
      : (e.error?.message || `OpenAI API error ${resp.status}`);
    throw httpErr(resp.status, msg);
  }
  const data = await resp.json();
  const b64out = data.data?.[0]?.b64_json;
  if (!b64out) throw httpErr(502, 'OpenAI returned no image.');
  const u = data.usage || {};
  const usage = {
    promptTokens: u.input_tokens || 0,
    outputTokens: u.output_tokens || 0,
    totalTokens: u.total_tokens || ((u.input_tokens || 0) + (u.output_tokens || 0))
  };
  return { image: `data:image/png;base64,${b64out}`, note: '', usage, model: openaiModel };
}

// ── helpers ──
function splitDataUrl(dataUrl) {
  const comma = dataUrl.indexOf(',');
  const header = dataUrl.slice(0, comma);
  const b64 = dataUrl.slice(comma + 1);
  const mime = (header.match(/data:(.*?);/) || [])[1] || 'image/png';
  return { b64, mime };
}
function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// ── Catch-all error handler ──────────────────────────────
// Anything that escapes a route's own try/catch (a malformed JSON body,
// a synchronous throw, etc.) lands here. Full detail goes to the server
// log only — the client always gets a generic message, never a raw
// stack trace, file path, or internal error string.
app.use((err, req, res, next) => {
  console.error('[unhandled]', err);
  if (res.headersSent) return next(err);
  res.status(err.status || 400).json({ error: 'Request could not be processed.' });
});

app.listen(PORT, () => {
  console.log(`AI-VGL-Studio running on http://localhost:${PORT}`);
  console.log(`  Gemini: ${GEMINI_KEY ? 'configured' : 'MISSING key'} (${GEMINI_MODEL})`);
  console.log(`  OpenAI: ${OPENAI_KEY ? 'configured' : 'MISSING key'} (${OPENAI_MODEL})`);
});
