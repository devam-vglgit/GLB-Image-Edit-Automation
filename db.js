// ─────────────────────────────────────────────────────────────
// SQL Server connection
//
// Credentials come from .env (git-ignored) — never hard-coded, never
// committed. AIDB is a SHARED database with hundreds of tables belonging to
// other systems, so everything this app creates is namespaced `visualoom_*`
// to avoid colliding with them (there is already an unrelated `dbo.users`).
// ─────────────────────────────────────────────────────────────
const sql = require('mssql');

const config = {
  server: process.env.DB_HOST || '',
  database: process.env.DB_NAME || '',
  user: process.env.DB_USER || '',
  password: process.env.DB_PASSWORD || '',
  port: Number(process.env.DB_PORT) || 1433,
  options: {
    // The server presents a self-signed cert on the internal network, so the
    // chain can't be validated. Set DB_ENCRYPT=true once a trusted cert is in
    // place to encrypt the connection properly.
    encrypt: String(process.env.DB_ENCRYPT || 'false') === 'true',
    trustServerCertificate: true
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  connectionTimeout: 15000,
  requestTimeout: 20000
};

const USERS_TABLE = 'visualoom_users';

let pool = null;

function isConfigured() {
  return !!(config.server && config.database && config.user);
}

async function connect() {
  if (pool) return pool;
  if (!isConfigured()) throw new Error('Database is not configured — set DB_HOST, DB_NAME, DB_USER and DB_PASSWORD in .env');
  pool = await new sql.ConnectionPool(config).connect();
  pool.on('error', e => console.error('[db] pool error:', e.message));
  return pool;
}

// Creates the app's own table if it isn't there yet. Deliberately touches
// nothing else in the database.
async function ensureSchema() {
  const p = await connect();
  await p.request().query(`
    IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES
                   WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = '${USERS_TABLE}')
    BEGIN
      CREATE TABLE dbo.${USERS_TABLE} (
        id          INT IDENTITY(1,1) PRIMARY KEY,
        email       NVARCHAR(255) NOT NULL,
        salt        NVARCHAR(64)  NOT NULL,
        hash        NVARCHAR(256) NOT NULL,
        role        NVARCHAR(20)  NOT NULL CONSTRAINT DF_${USERS_TABLE}_role DEFAULT 'user',
        created_at  DATETIME2     NOT NULL CONSTRAINT DF_${USERS_TABLE}_created DEFAULT SYSUTCDATETIME()
      );
      CREATE UNIQUE INDEX UX_${USERS_TABLE}_email ON dbo.${USERS_TABLE}(email);
    END
  `);
}

function request() {
  if (!pool) throw new Error('Database not connected yet.');
  return pool.request();
}

async function close() {
  if (pool) { await pool.close(); pool = null; }
}

module.exports = { sql, connect, ensureSchema, request, close, isConfigured, USERS_TABLE };
