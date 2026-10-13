// Rug Room accounts API — runs inside the Cloudflare Worker, stores data in D1.
// Needs one D1 database bound with the variable name DB (see wrangler.jsonc).
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
    db.prepare(`CREATE TABLE IF NOT EXISTS resets (
      hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL)`),
  ]);
  schemaReady = true;
}

// One-time wipe of every account (second reset, 13 Oct 2026), then the owner account is created
// with $5B on Chill. Only a salted PBKDF2 hash of the owner's password is stored here.
const WIPE_ID = 'wipe-2026-10-13-b';
const OWNER = {
  email: 'jamesmsmith555@gmail.com',
  salt: '7685f921600862656271f6d419b3d015',
  hash: '821c22492d5eb0c36148d25aa701988596b382f2e27d2d91ed8411830b8a4fb8',
};
let seeded = false;
async function ensureSeed(db) {
  if (seeded) return;
  await db.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)').run();
  const wiped = await db.prepare('SELECT v FROM meta WHERE k = ?').bind(WIPE_ID).first();
  if (!wiped) {
    await db.batch([
      db.prepare('DELETE FROM sessions'),
      db.prepare('DELETE FROM saves'),
      db.prepare('DELETE FROM scores'),
      db.prepare('DELETE FROM resets'),
      db.prepare('DELETE FROM users'),
      db.prepare('INSERT OR IGNORE INTO meta (k, v) VALUES (?, ?)').bind(WIPE_ID, String(Date.now())),
    ]);
  }
  const exists = await db.prepare('SELECT id FROM users WHERE email = ?').bind(OWNER.email).first();
  if (!exists) {
    const now = Date.now();
    await db.prepare('INSERT OR IGNORE INTO users (email, pass_hash, salt, created_at) VALUES (?, ?, ?, ?)')
      .bind(OWNER.email, OWNER.hash, OWNER.salt, now).run();
    const { id } = await db.prepare('SELECT id FROM users WHERE email = ?').bind(OWNER.email).first();
    const state = {
      cash: 5000000000, peakCash: 5000000000, heat: 0, trust: 60, alias: 'james', aliasN: 1,
      lifetime: { launched: 0, rugs: 0, extracted: 0, victims: 0, lost: 0 }, shame: [],
      profile: { name: 'james', avatar: '👑', wallet: '0x7A3E5000000000000000000000000000000BEEF', created: now },
      blacklisted: false, diff: 'easy', owned: {}, done: {}, stats: {}, savedAt: now,
    };
    await db.prepare('INSERT OR IGNORE INTO saves (user_id, state, updated_at) VALUES (?, ?, ?)').bind(id, JSON.stringify(state), now).run();
  }
  seeded = true;
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

async function sha256(text) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}
const escHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

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

export async function handleApi(request, env) {
  const db = env.DB;
  const path = new URL(request.url).pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
  const method = request.method;

  if (!db) return fail('Accounts are not set up yet (no database bound).', 503);
  try {
    await ensureSchema(db);
    await ensureSeed(db);

    if (path === '/health') return json({ ok: true });

    if ((path === '/register' || path === '/login') && method === 'POST') {
      const body = await readBody(request);
      const email = cleanEmail(body.email || body.username);
      const password = String(body.password || '');
      if (!EMAIL_RE.test(email) || email.length > 120) return fail('Enter a valid email address.');
      if (!password || password.length > 128) return fail('Enter your password.');

      if (path === '/register') {
        if (password.length < 6) return fail('Password needs at least 6 characters.');
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

    // Password reset, same approach as Torque Index: Resend sends a one-hour link to /#reset-<token>.
    // Needs a RESEND_KEY secret on the Worker; MAIL_FROM is optional.
    if (path === '/forgot' && method === 'POST') {
      const key = env.RESEND_KEY;
      if (!key) return fail("Password reset isn't switched on yet.", 503);
      const email = cleanEmail((await readBody(request)).email);
      if (!EMAIL_RE.test(email)) return fail('Enter a valid email address.');
      const user = await db.prepare('SELECT id, email FROM users WHERE email = ?').bind(email).first();
      if (user) {
        const recent = await db.prepare('SELECT COUNT(*) AS n FROM resets WHERE user_id = ? AND expires_at > ?')
          .bind(user.id, Date.now() + 3600e3 - 15 * 60e3).first();
        if (!recent || recent.n < 3) {
          await db.prepare('DELETE FROM resets WHERE expires_at < ?').bind(Date.now()).run();
          const token = randomHex(24);
          await db.prepare('INSERT INTO resets (hash, user_id, expires_at) VALUES (?, ?, ?)')
            .bind(await sha256(token), user.id, Date.now() + 3600e3).run();
          const link = new URL(request.url).origin + '/#reset-' + token;
          const from = env.MAIL_FROM || 'Rug Room <onboarding@resend.dev>';
          try {
            await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
              body: JSON.stringify({
                from, to: [user.email], subject: 'Reset your Rug Room password',
                html: `<p>Hi,</p><p>Someone asked to reset your Rug Room password. If it was you, open this link within an hour:</p><p><a href="${escHtml(link)}">${escHtml(link)}</a></p><p>If it wasn't you, ignore this email. Your password won't change.</p>`,
              }),
            });
          } catch {}
        }
      }
      // same answer either way, so nobody can test which emails have accounts
      return json({ ok: true });
    }

    if (path === '/reset' && method === 'POST') {
      const body = await readBody(request);
      const password = String(body.password || '');
      if (password.length < 6 || password.length > 128) return fail('Password needs at least 6 characters.');
      const row = await db.prepare('SELECT user_id, expires_at FROM resets WHERE hash = ?')
        .bind(await sha256(String(body.token || ''))).first();
      if (!row || row.expires_at < Date.now()) return fail('That reset link has expired. Ask for a new one.');
      const user = await db.prepare('SELECT id, email FROM users WHERE id = ?').bind(row.user_id).first();
      if (!user) return fail('That reset link has expired. Ask for a new one.');
      const salt = randomHex(16);
      await db.batch([
        db.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').bind(await hashPassword(password, salt), salt, user.id),
        db.prepare('DELETE FROM resets WHERE user_id = ?').bind(user.id),
        db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
      ]);
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
      if (state.length > 900000) return fail('Save is too large.', 413);
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
