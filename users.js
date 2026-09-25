// ─────────────────────────────────────────────────────────────
// User store
//
// Users live in data/users.json so an admin can add/remove people from the
// UI without editing .env and restarting. Passwords are salted + hashed
// with scrypt (built into Node — no extra dependency); the plaintext is
// never stored and never leaves the login request.
//
// On first run the file is seeded from the existing AUTH_USERS env var so
// nobody is locked out by the upgrade. The first seeded account (or one
// literally named "admin") becomes the admin.
//
// Shape:
//   { "users": [ { username, salt, hash, role, createdAt } ] }
// ─────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const ROLES = ['admin', 'user'];
let store = null;

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(String(password), salt, 64).toString('hex') };
}

function passwordMatches(password, salt, hash) {
  let candidate;
  try { candidate = crypto.scryptSync(String(password), salt, 64); }
  catch (e) { return false; }
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

// Seed from AUTH_USERS="alice:pass1,bob:pass2" so the upgrade doesn't lock
// anyone out. Falls back to admin/studioe69, matching the previous default.
function seedFromEnv() {
  const raw = process.env.AUTH_USERS || '';
  const pairs = raw.split(',').map(s => s.trim()).filter(Boolean)
    .map(p => { const i = p.indexOf(':'); return i > -1 ? [p.slice(0, i), p.slice(i + 1)] : null; })
    .filter(Boolean);
  if (!pairs.length) {
    pairs.push([process.env.AUTH_USERNAME || 'admin', process.env.AUTH_PASSWORD || 'studioe69']);
  }
  const users = pairs.map(([username, password], i) => {
    const { salt, hash } = hashPassword(password);
    return {
      username,
      salt,
      hash,
      // Someone has to be able to manage users, so the account named "admin"
      // (or the first one listed) gets the admin role.
      role: (username === 'admin' || i === 0) ? 'admin' : 'user',
      createdAt: new Date().toISOString()
    };
  });
  // Guarantee at least one admin even if the naming above didn't pick one.
  if (!users.some(u => u.role === 'admin') && users.length) users[0].role = 'admin';
  return { users };
}

function load() {
  if (store) return store;
  try {
    store = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (!Array.isArray(store.users)) store = { users: [] };
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn('[users] could not read store, re-seeding:', e.message);
    store = seedFromEnv();
    save();
    console.log(`[users] seeded ${store.users.length} account(s) from AUTH_USERS into data/users.json`);
  }
  return store;
}

function save() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(store, null, 2), 'utf8');
}

function find(username) {
  return load().users.find(u => u.username === username) || null;
}

// Returns the user record on success, null otherwise.
function authenticate(username, password) {
  const u = find(username);
  if (!u) return null;
  return passwordMatches(password, u.salt, u.hash) ? u : null;
}

// Never expose salt/hash to the client.
function publicView(u) {
  return { username: u.username, role: u.role, createdAt: u.createdAt || null };
}

function list() {
  return load().users.map(publicView);
}

function isAdmin(username) {
  const u = find(username);
  return !!u && u.role === 'admin';
}

function create({ username, password, role }) {
  const name = String(username || '').trim();
  if (!name) throw new Error('Username is required.');
  if (!/^[a-zA-Z0-9._-]{2,32}$/.test(name)) throw new Error('Username must be 2-32 characters: letters, numbers, dot, dash or underscore.');
  if (String(password || '').length < 6) throw new Error('Password must be at least 6 characters.');
  if (find(name)) throw new Error('That username already exists.');
  const r = ROLES.includes(role) ? role : 'user';
  const { salt, hash } = hashPassword(password);
  load().users.push({ username: name, salt, hash, role: r, createdAt: new Date().toISOString() });
  save();
  return publicView(find(name));
}

function remove(username) {
  const s = load();
  const u = find(username);
  if (!u) throw new Error('No such user.');
  // Never allow the last admin to be deleted — that would lock everyone out
  // of user management with no way back in short of editing files on the server.
  if (u.role === 'admin' && s.users.filter(x => x.role === 'admin').length === 1) {
    throw new Error('Cannot remove the only admin.');
  }
  s.users = s.users.filter(x => x.username !== username);
  store = s;
  save();
}

function setPassword(username, password) {
  const u = find(username);
  if (!u) throw new Error('No such user.');
  if (String(password || '').length < 6) throw new Error('Password must be at least 6 characters.');
  const { salt, hash } = hashPassword(password);
  u.salt = salt; u.hash = hash;
  save();
}

function setRole(username, role) {
  const s = load();
  const u = find(username);
  if (!u) throw new Error('No such user.');
  if (!ROLES.includes(role)) throw new Error('Role must be "admin" or "user".');
  if (u.role === 'admin' && role !== 'admin' && s.users.filter(x => x.role === 'admin').length === 1) {
    throw new Error('Cannot demote the only admin.');
  }
  u.role = role;
  save();
  return publicView(u);
}

module.exports = { authenticate, list, isAdmin, create, remove, setPassword, setRole, find, publicView, ROLES };
