// Rug Room accounts API — Cloudflare Pages Functions + D1.
// Needs one D1 database bound to this Pages project with the variable name DB.
// Tables are created automatically on first use.

const SESSION_DAYS = 60;
const PBKDF2_ITERATIONS = 100000; // Workers' maximum

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      pass_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS saves (
      user_id INTEGER PRIMARY KEY,
      state TEXT NOT NULL,
      updated_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS scores (
      user_id INTEGER PRIMARY KEY,
      alias TEXT, avatar TEXT,
      peak REAL DEFAULT 0, cash REAL DEFAULT 0, extracted REAL DEFAULT 0,
      rugs INTEGER DEFAULT 0, peakMc REAL DEFAULT 0, tiers INTEGER DEFAULT 0,
      updated_at INTEGER NOT NULL)`),
  ]);
  schemaReady = true;
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
const fail = (error, status = 400) => json({ error }, status);

const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS }, key, 256);
  return toHex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const cleanEmail = (e) => String(e || '').trim().toLowerCase();

async function readBody(request) {
  try { return await request.json(); } catch { return {}; }
}

async function newSession(db, userId) {
  const token = randomHex(32);
  await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, Date.now() + SESSION_DAYS * 864e5).run();
  return token;
}

async function currentUser(db, request) {
  const m = (request.headers.get('authorization') || '').match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!m) return null;
  const row = await db.prepare(
    `SELECT u.id, u.email, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`)
    .bind(m[1]).first();
  if (!row || row.expires_at < Date.now()) return null;
  return { id: row.id, username: row.email, email: row.email, token: m[1] };
}

const num = (v) => (Number.isFinite(+v) ? +v : 0);

export async function onRequest({ request, env, params }) {
  const db = env.DB;
  const path = '/' + [].concat(params.path || []).join('/');
  const method = request.method;

  if (!db) return fail('Accounts are not set up yet (no database bound).', 503);
  try {
    await ensureSchema(db);

    if (path === '/health') return json({ ok: true });

    if ((path === '/register' || path === '/login') && method === 'POST') {
      const body = await readBody(request);
      const email = cleanEmail(body.email || body.username);
      const password = String(body.password || '');
      if (!EMAIL_RE.test(email) || email.length > 120) return fail('Enter a valid email address.');
      if (password.length < 6 || password.length > 128) return fail('Password needs at least 6 characters.');

      if (path === '/register') {
        const exists = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (exists) return fail('That email already has an account. Try signing in.', 409);
        const salt = randomHex(16);
        const hash = await hashPassword(password, salt);
        const res = await db.prepare('INSERT INTO users (email, pass_hash, salt, created_at) VALUES (?, ?, ?, ?)')
          .bind(email, hash, salt, Date.now()).run();
        const id = res.meta.last_row_id;
        const token = await newSession(db, id);
        return json({ token, user: { id, username: email, email } });
      }

      const user = await db.prepare('SELECT id, email, pass_hash, salt FROM users WHERE email = ?').bind(email).first();
      const hash = user ? await hashPassword(password, user.salt) : await hashPassword(password, randomHex(16));
      if (!user || !safeEqual(hash, user.pass_hash)) return fail('Wrong email or password.', 401);
      // tidy old sessions for this user
      await db.prepare('DELETE FROM sessions WHERE user_id = ? AND expires_at < ?').bind(user.id, Date.now()).run();
      const token = await newSession(db, user.id);
      return json({ token, user: { id: user.id, username: user.email, email: user.email } });
    }

    if (path === '/leaderboard' && method === 'GET') {
      const { results } = await db.prepare(
        `SELECT user_id AS id, alias, avatar, peak, cash, extracted, rugs, peakMc, tiers, updated_at AS updatedAt
         FROM scores ORDER BY peak DESC LIMIT 500`).all();
      return json({ rows: results || [] });
    }

    const me = await currentUser(db, request);
    if (!me) return fail('Please sign in again.', 401);

    if (path === '/me' && method === 'GET') return json({ user: { id: me.id, username: me.email, email: me.email } });

    if (path === '/logout' && method === 'POST') {
      await db.prepare('DELETE FROM sessions WHERE token = ?').bind(me.token).run();
      return json({ ok: true });
    }

    if (path === '/save' && method === 'GET') {
      const row = await db.prepare('SELECT state, updated_at FROM saves WHERE user_id = ?').bind(me.id).first();
      return json({ save: row ? { state: row.state, updatedAt: row.updated_at } : null });
    }

    if (path === '/save' && method === 'PUT') {
      const body = await readBody(request);
      const state = typeof body.state === 'string' ? body.state : JSON.stringify(body.state || {});
      if (state.length > 500000) return fail('Save is too large.', 413);
      await db.prepare(
        `INSERT INTO saves (user_id, state, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`)
        .bind(me.id, state, Date.now()).run();
      return json({ ok: true });
    }

    if (path === '/score' && method === 'PUT') {
      const s = await readBody(request);
      await db.prepare(
        `INSERT INTO scores (user_id, alias, avatar, peak, cash, extracted, rugs, peakMc, tiers, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET alias=excluded.alias, avatar=excluded.avatar, peak=excluded.peak,
           cash=excluded.cash, extracted=excluded.extracted, rugs=excluded.rugs, peakMc=excluded.peakMc,
           tiers=excluded.tiers, updated_at=excluded.updated_at`)
        .bind(me.id, String(s.alias || 'anon').slice(0, 18), String(s.avatar || '🦊').slice(0, 8),
          num(s.peak), num(s.cash), num(s.extracted), Math.round(num(s.rugs)), num(s.peakMc),
          Math.round(num(s.tiers)), Date.now()).run();
      return json({ ok: true });
    }

    return fail('Not found', 404);
  } catch (e) {
    return fail('Server error. Try again in a moment.', 500);
  }
}
