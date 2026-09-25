// ─────────────────────────────────────────────────────────────
// User store (SQL Server)
//
// Accounts live in dbo.visualoom_users on AIDB. Login is by EMAIL; the
// password is never stored — only a random salt and a scrypt hash of it.
//
// The table is read into memory once at startup and refreshed after every
// change, so per-request role checks cost nothing. The database stays the
// source of truth; memory is only a read cache. (A second app server
// writing to the table wouldn't be seen until this one restarts — fine for
// a single instance, worth revisiting if the app is ever scaled out.)
//
// On first run the table is seeded from AUTH_SEED in .env so the existing
// team isn't locked out by the move off the JSON file.
// ─────────────────────────────────────────────────────────────
const crypto = require('crypto');
const db = require('./db');

const ROLES = ['admin', 'user'];
let cache = [];   // [{ email, salt, hash, role, createdAt }]
let ready = false;   // false until the table has been read at least once

// The app serves even when the database is down (see server.js), so callers
// need a way to tell "no accounts exist" from "we haven't loaded them yet".
function isReady() { return ready; }

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

function normaliseEmail(v) { return String(v || '').trim().toLowerCase(); }
function looksLikeEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }

async function refresh() {
  const r = await db.request().query(
    `SELECT email, salt, hash, role, created_at FROM dbo.${db.USERS_TABLE} ORDER BY created_at`
  );
  cache = r.recordset.map(row => ({
    email: row.email,
    salt: row.salt,
    hash: row.hash,
    role: row.role,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null
  }));
  return cache;
}

// AUTH_SEED="email:password:role,email:password:role" — used once, only when
// the table is empty, so existing logins survive the move to the database.
function parseSeed() {
  return (process.env.AUTH_SEED || '').split(',')
    .map(s => s.trim()).filter(Boolean)
    .map(entry => {
      const parts = entry.split(':');
      if (parts.length < 2) return null;
      const email = normaliseEmail(parts[0]);
      const password = parts[1];
      const role = ROLES.includes(parts[2]) ? parts[2] : 'user';
      return (email && password) ? { email, password, role } : null;
    })
    .filter(Boolean);
}

async function init() {
  await db.connect();
  await db.ensureSchema();
  await refresh();

  if (cache.length === 0) {
    const seed = parseSeed();
    if (!seed.length) {
      console.warn('[users] table is empty and AUTH_SEED is not set — nobody can sign in. Add AUTH_SEED to .env and restart.');
    }
    for (const s of seed) {
      const { salt, hash } = hashPassword(s.password);
      await db.request()
        .input('email', db.sql.NVarChar(255), s.email)
        .input('salt', db.sql.NVarChar(64), salt)
        .input('hash', db.sql.NVarChar(256), hash)
        .input('role', db.sql.NVarChar(20), s.role)
        .query(`INSERT INTO dbo.${db.USERS_TABLE} (email, salt, hash, role) VALUES (@email, @salt, @hash, @role)`);
    }
    if (seed.length) {
      await refresh();
      console.log(`[users] seeded ${seed.length} account(s) from AUTH_SEED into dbo.${db.USERS_TABLE}`);
    }
  }
  ready = true;
  console.log(`[users] ${cache.length} account(s) loaded from dbo.${db.USERS_TABLE}`);
}

function find(email) {
  const e = normaliseEmail(email);
  return cache.find(u => u.email === e) || null;
}

// Returns the account on success, null otherwise.
function authenticate(email, password) {
  const u = find(email);
  if (!u) return null;
  return passwordMatches(password, u.salt, u.hash) ? u : null;
}

// Salt and hash never leave the server.
function publicView(u) { return { email: u.email, role: u.role, createdAt: u.createdAt }; }
function list() { return cache.map(publicView); }
function isAdmin(email) { const u = find(email); return !!u && u.role === 'admin'; }
function adminCount() { return cache.filter(u => u.role === 'admin').length; }

async function create({ email, password, role }) {
  const e = normaliseEmail(email);
  if (!e) throw new Error('Email is required.');
  if (!looksLikeEmail(e)) throw new Error('That does not look like a valid email address.');
  if (String(password || '').length < 6) throw new Error('Password must be at least 6 characters.');
  if (find(e)) throw new Error('That email already exists.');
  const r = ROLES.includes(role) ? role : 'user';
  const { salt, hash } = hashPassword(password);
  await db.request()
    .input('email', db.sql.NVarChar(255), e)
    .input('salt', db.sql.NVarChar(64), salt)
    .input('hash', db.sql.NVarChar(256), hash)
    .input('role', db.sql.NVarChar(20), r)
    .query(`INSERT INTO dbo.${db.USERS_TABLE} (email, salt, hash, role) VALUES (@email, @salt, @hash, @role)`);
  await refresh();
  return publicView(find(e));
}

async function remove(email) {
  const u = find(email);
  if (!u) throw new Error('No such user.');
  // Losing the last admin would lock everyone out of user management with no
  // way back short of editing the database by hand.
  if (u.role === 'admin' && adminCount() === 1) throw new Error('Cannot remove the only admin.');
  await db.request()
    .input('email', db.sql.NVarChar(255), u.email)
    .query(`DELETE FROM dbo.${db.USERS_TABLE} WHERE email = @email`);
  await refresh();
}

async function setPassword(email, password) {
  const u = find(email);
  if (!u) throw new Error('No such user.');
  if (String(password || '').length < 6) throw new Error('Password must be at least 6 characters.');
  const { salt, hash } = hashPassword(password);
  await db.request()
    .input('email', db.sql.NVarChar(255), u.email)
    .input('salt', db.sql.NVarChar(64), salt)
    .input('hash', db.sql.NVarChar(256), hash)
    .query(`UPDATE dbo.${db.USERS_TABLE} SET salt = @salt, hash = @hash WHERE email = @email`);
  await refresh();
}

async function setRole(email, role) {
  const u = find(email);
  if (!u) throw new Error('No such user.');
  if (!ROLES.includes(role)) throw new Error('Role must be "admin" or "user".');
  if (u.role === 'admin' && role !== 'admin' && adminCount() === 1) throw new Error('Cannot demote the only admin.');
  await db.request()
    .input('email', db.sql.NVarChar(255), u.email)
    .input('role', db.sql.NVarChar(20), role)
    .query(`UPDATE dbo.${db.USERS_TABLE} SET role = @role WHERE email = @email`);
  await refresh();
  return publicView(find(u.email));
}

module.exports = { init, isReady, authenticate, list, isAdmin, create, remove, setPassword, setRole, find, publicView, ROLES };
