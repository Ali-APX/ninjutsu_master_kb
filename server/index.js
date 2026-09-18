import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const port = Number(process.env.PORT || 8787);
const appId = '6a4673f3e858d791810c2e7d';
const databasePath = process.env.DATABASE_PATH || './data/ninjutsu.sqlite';
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new DatabaseSync(databasePath);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    full_name TEXT NOT NULL DEFAULT '',
    phone TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    phone_verified INTEGER NOT NULL DEFAULT 0,
    national_id TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );
  CREATE TABLE IF NOT EXISTS email_verifications (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    user_id TEXT,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS entities_type_index ON entities(type);
  CREATE INDEX IF NOT EXISTS entities_user_index ON entities(user_id);
`);
try {
  db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0');
} catch (error) {
  if (!String(error.message).includes('duplicate column name')) throw error;
}
for (const statement of [
  'ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN national_id TEXT',
]) {
  try {
    db.exec(statement);
  } catch (error) {
    if (!String(error.message).includes('duplicate column name')) throw error;
  }
}

const app = express();
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:8787';
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: allowedOrigin, credentials: true }));
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-8' }));
app.use((req, res, next) => {
  if (req.path === '/data' || req.path.startsWith('/data/')) return res.status(404).end();
  next();
});
app.use(express.static(process.cwd(), { extensions: ['html'] }));

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const publicUser = ({ password_hash, ...user }) => user;
const sessionCookie = { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 };
const publicReadableEntities = new Set(['Course', 'Discipline', 'Instructor', 'Branch', 'CalendarEvent', 'News', 'FAQ', 'GalleryItem', 'Competition', 'Product', 'Rank', 'HomeStat']);
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', message: { message: 'Too many authentication attempts' } });
const verificationSecret = process.env.VERIFICATION_SECRET || crypto.randomBytes(32).toString('hex');
app.use('/api/auth', authLimiter);
app.use(`/api/apps/${appId}/auth`, authLimiter);

function tokenFor(userId) {
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now());
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash IN (SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET 5)').run(userId, userId);
  const rawToken = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)').run(
    crypto.createHash('sha256').update(rawToken).digest('hex'),
    userId,
    new Date(Date.now() + sessionCookie.maxAge).toISOString(),
    now(),
  );
  return rawToken;
}

function verificationHash(code) {
  return crypto.createHmac('sha256', verificationSecret).update(code).digest('hex');
}

async function deliverEmail(to, subject, code) {
  const webhook = process.env.EMAIL_WEBHOOK_URL;
  if (!webhook) return false;
  const headers = { 'content-type': 'application/json' };
  if (process.env.EMAIL_WEBHOOK_TOKEN) headers.authorization = `Bearer ${process.env.EMAIL_WEBHOOK_TOKEN}`;
  const response = await fetch(webhook, {
    method: 'POST',
    headers,
    body: JSON.stringify({ to, subject, code }),
    signal: AbortSignal.timeout(5000),
  });
  return response.ok;
}

async function issueVerification(user) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare('INSERT OR REPLACE INTO email_verifications (user_id,email,code_hash,expires_at,attempts) VALUES (?,?,?,?,0)').run(
    user.id,
    user.email,
    verificationHash(code),
    new Date(Date.now() + 15 * 60 * 1000).toISOString(),
  );
  try {
    await deliverEmail(user.email, 'Ninjutsu Master email verification', code);
  } catch (error) {
    console.error('Email verification delivery failed:', error.message);
  }
}

function authenticate(req, res, next) {
  const raw = req.cookies.ninjutsu_session || req.get('authorization')?.replace(/^Bearer\s+/i, '');
  if (!raw) return res.status(401).json({ message: 'Authentication required' });
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  const session = db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash, now());
  if (!session) return res.status(401).json({ message: 'Invalid session' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ message: 'Invalid session' });
  req.user = publicUser(user);
  next();
}

function optionalAuthenticate(req, _res, next) {
  const raw = req.cookies.ninjutsu_session || req.get('authorization')?.replace(/^Bearer\s+/i, '');
  if (raw) {
    const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
    const session = db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash, now());
    if (session) req.user = publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id));
  }
  next();
}

function requireStaff(req, res, next) {
  if (!['admin', 'developer'].includes(req.user.role)) return res.status(403).json({ message: 'Insufficient permissions' });
  next();
}

const credentials = z.object({ email: z.string().email().transform((value) => value.toLowerCase()), password: z.string().min(8).max(128) });
const entityName = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/);
const memberWritableEntities = new Set(['Registration', 'TrialRegistration', 'WaitlistEntry', 'SupportTicket', 'AgreementAcceptance', 'Notification']);

async function registerUser(req, res) {
  const parsed = credentials.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Email and password are invalid' });
  const { email, password } = parsed.data;
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return res.status(409).json({ message: 'Email is already registered' });
  const user = { id: id(), email, password_hash: await bcrypt.hash(password, 12), role: 'user', full_name: '', phone: null, created_at: now() };
  db.prepare('INSERT INTO users (id,email,password_hash,role,full_name,phone,created_at) VALUES (@id,@email,@password_hash,@role,@full_name,@phone,@created_at)').run(user);
  await issueVerification(user);
  res.status(202).json({ verification_required: true, message: 'Verification code sent' });
}

async function loginUser(req, res) {
  const parsed = credentials.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Email and password are invalid' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(parsed.data.email);
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) return res.status(401).json({ message: 'Invalid email or password' });
  if (!user.email_verified) return res.status(403).json({ message: 'Email verification required' });
  const accessToken = tokenFor(user.id);
  res.cookie('ninjutsu_session', accessToken, sessionCookie).json({ access_token: accessToken, user: publicUser(user) });
}

function findUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
}

function createResetToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO password_resets (token_hash,user_id,expires_at) VALUES (?,?,?)').run(
    crypto.createHash('sha256').update(token).digest('hex'),
    userId,
    new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  );
  return token;
}

function allowMemberWrite(req, type) {
  if (['admin', 'developer'].includes(req.user.role)) return true;
  if (!memberWritableEntities.has(type)) return false;
  if (!req.body) return false;
  if (req.body.user_id) return req.body.user_id === req.user.id;
  if (req.body.student_id) {
    const student = db.prepare('SELECT data FROM entities WHERE id = ? AND type = ?').get(req.body.student_id, 'Student');
    return Boolean(student && JSON.parse(student.data).user_id === req.user.id);
  }
  return false;
}

function allowMemberEntityUpdate(req, type, entityId, body) {
  if (['admin', 'developer'].includes(req.user.role)) return true;
  if (!memberWritableEntities.has(type) || body?.user_id || body?.student_id) return false;
  if (type === 'Notification' && Object.keys(body || {}).some((key) => key !== 'is_read')) return false;
  const row = db.prepare('SELECT id, data, created_at, updated_at FROM entities WHERE id = ? AND type = ?').get(entityId, type);
  return Boolean(row && canReadEntity(req, type, entityResponse(row)));
}

function canReadEntity(req, type, entity) {
  if (publicReadableEntities.has(type)) return true;
  if (!req.user) return false;
  if (['admin', 'developer'].includes(req.user.role)) return true;
  if (type === 'User') return entity.id === req.user.id;
  if (entity.user_id === req.user.id) return true;
  if (entity.student_id) {
    const student = db.prepare('SELECT data FROM entities WHERE id = ? AND type = ?').get(entity.student_id, 'Student');
    return Boolean(student && JSON.parse(student.data).user_id === req.user.id);
  }
  return false;
}

function parseEntityQuery(query) {
  if (!query.q) return {};
  try {
    const parsed = JSON.parse(query.q);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return null;
  }
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'ninjutsu-master-api' }));
app.post('/api/auth/register', registerUser);

app.post('/api/auth/login', loginUser);
app.post('/api/auth/verify-otp', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.otp_code || '');
  const user = findUserByEmail(email);
  const verification = user && db.prepare('SELECT * FROM email_verifications WHERE user_id = ? AND expires_at > ?').get(user.id, now());
  if (!verification || verification.attempts >= 5 || !/^\d{6}$/.test(code)) return res.status(400).json({ message: 'Invalid or expired verification code' });
  db.prepare('UPDATE email_verifications SET attempts = attempts + 1 WHERE user_id = ?').run(user.id);
  if (verificationHash(code) !== verification.code_hash) return res.status(400).json({ message: 'Invalid or expired verification code' });
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  db.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(user.id);
  const accessToken = tokenFor(user.id);
  res.cookie('ninjutsu_session', accessToken, sessionCookie).json({ access_token: accessToken, user: publicUser({ ...user, email_verified: 1 }) });
});
app.post('/api/auth/resend-otp', async (req, res) => {
  const user = findUserByEmail(req.body?.email);
  if (user && !user.email_verified) await issueVerification(user);
  res.json({ message: 'If the account requires verification, a new code has been sent' });
});
app.post('/api/auth/logout', (req, res) => {
  const raw = req.cookies.ninjutsu_session;
  if (raw) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(crypto.createHash('sha256').update(raw).digest('hex'));
  res.clearCookie('ninjutsu_session', sessionCookie).status(204).end();
});
app.get('/api/auth/me', authenticate, (req, res) => res.json(publicUser(req.user)));
app.post('/api/auth/reset-password-request', async (req, res) => {
  const user = findUserByEmail(req.body?.email);
  if (user) {
    const token = createResetToken(user.id);
    try {
      await deliverEmail(user.email, 'Ninjutsu Master password reset', token);
    } catch (error) {
      console.error('Password reset delivery failed:', error.message);
    }
  }
  res.json({ message: 'If the account exists, password reset instructions have been sent' });
});
app.post('/api/auth/reset-password', async (req, res) => {
  const token = String(req.body?.reset_token || '');
  const password = String(req.body?.new_password || '');
  if (token.length !== 64 || password.length < 8 || password.length > 128) return res.status(400).json({ message: 'Invalid reset request' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const reset = db.prepare('SELECT user_id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?').get(tokenHash, now());
  if (!reset) return res.status(400).json({ message: 'Invalid or expired reset request' });
  db.prepare('UPDATE users SET password_hash = @password_hash WHERE id = @id').run({ password_hash: await bcrypt.hash(password, 12), id: reset.user_id });
  db.prepare('UPDATE password_resets SET used_at = ? WHERE token_hash = ?').run(now(), tokenHash);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(reset.user_id);
  res.json({ message: 'Password updated' });
});
app.post('/api/auth/change-password', authenticate, async (req, res) => {
  const currentPassword = String(req.body?.current_password || '');
  const newPassword = String(req.body?.new_password || '');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) return res.status(401).json({ message: 'Current password is incorrect' });
  if (newPassword.length < 8 || newPassword.length > 128) return res.status(400).json({ message: 'New password is invalid' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await bcrypt.hash(newPassword, 12), req.user.id);
  res.json({ message: 'Password updated' });
});

app.get('/api/entities/:type', authenticate, (req, res) => {
  const type = entityName.safeParse(req.params.type);
  if (!type.success) return res.status(400).json({ message: 'Invalid entity name' });
  const rows = db.prepare('SELECT id, data, created_at, updated_at FROM entities WHERE type = ? ORDER BY created_at DESC LIMIT 1000').all(type.data);
  res.json(rows.map(entityResponse).filter((entity) => canReadEntity(req, type.data, entity)));
});
app.post('/api/entities/:type', authenticate, requireStaff, (req, res) => {
  const type = entityName.safeParse(req.params.type);
  if (!type.success || !req.body || Array.isArray(req.body)) return res.status(400).json({ message: 'Invalid entity payload' });
  const created = now();
  const entity = { id: id(), ...req.body };
  db.prepare('INSERT INTO entities (id,type,user_id,data,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(entity.id, type.data, req.user.id, JSON.stringify(entity), created, created);
  res.status(201).json({ ...entity, created_date: created, updated_date: created });
});
app.patch('/api/entities/:type/:id', authenticate, requireStaff, (req, res) => {
  const type = entityName.safeParse(req.params.type);
  if (!type.success || !req.body || Array.isArray(req.body)) return res.status(400).json({ message: 'Invalid entity payload' });
  const row = db.prepare('SELECT data FROM entities WHERE id = ? AND type = ?').get(req.params.id, type.data);
  if (!row) return res.status(404).json({ message: 'Entity not found' });
  const updated = { ...JSON.parse(row.data), ...req.body, id: req.params.id };
  const updatedAt = now();
  db.prepare('UPDATE entities SET data = ?, updated_at = ? WHERE id = ? AND type = ?').run(JSON.stringify(updated), updatedAt, req.params.id, type.data);
  res.json({ ...updated, updated_date: updatedAt });
});
app.delete('/api/entities/:type/:id', authenticate, requireStaff, (req, res) => {
  const result = db.prepare('DELETE FROM entities WHERE id = ? AND type = ?').run(req.params.id, req.params.type);
  if (!result.changes) return res.status(404).json({ message: 'Entity not found' });
  res.status(204).end();
});

function entityResponse(row) {
  return { id: row.id, ...JSON.parse(row.data), created_date: row.created_at, updated_date: row.updated_at };
}

function entityRows(type, query, req) {
  const filters = parseEntityQuery(query);
  if (filters === null) return null;
  const rows = db.prepare('SELECT id, data, created_at, updated_at FROM entities WHERE type = ? ORDER BY created_at DESC LIMIT 1000').all(type);
  return rows.map(entityResponse)
    .filter((entity) => canReadEntity(req, type, entity))
    .filter((entity) => Object.entries(filters).every(([key, value]) => entity[key] === value));
}

function compatibilityEntity(req, res, next) {
  if (req.params.app !== appId) return res.status(404).json({ message: 'Application not found' });
  next();
}

app.post('/api/apps/:app/auth/register', compatibilityEntity, (req, res) => {
  return registerUser(req, res);
});
app.post('/api/apps/:app/auth/login', compatibilityEntity, (req, res) => {
  return loginUser(req, res);
});
app.post('/api/apps/:app/auth/verify-otp', compatibilityEntity, (req, res) => {
  req.url = '/api/auth/verify-otp';
  return app.handle(req, res);
});
app.post('/api/apps/:app/auth/resend-otp', compatibilityEntity, (req, res) => {
  req.url = '/api/auth/resend-otp';
  return app.handle(req, res);
});
app.get('/api/apps/:app/entities/User/me', compatibilityEntity, authenticate, (req, res) => res.json(req.user));
app.put('/api/apps/:app/entities/User/me', compatibilityEntity, authenticate, (req, res) => {
  const allowed = ['full_name', 'phone', 'national_id', 'phone_verified'];
  const updates = Object.fromEntries(Object.entries(req.body || {}).filter(([key]) => allowed.includes(key)));
  if (Object.keys(updates).length) {
    const fields = Object.keys(updates).map((key) => `${key} = @${key}`).join(', ');
    db.prepare(`UPDATE users SET ${fields} WHERE id = @id`).run({ ...updates, id: req.user.id });
  }
  res.json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
});
app.get('/api/apps/:app/entities/:type', compatibilityEntity, optionalAuthenticate, (req, res) => {
  if (!publicReadableEntities.has(req.params.type) && !req.user) return res.status(401).json({ message: 'Authentication required' });
  const rows = entityRows(req.params.type, req.query, req);
  if (rows === null) return res.status(400).json({ message: 'Invalid entity query' });
  if (req.query.limit) res.json(rows.slice(Number(req.query.skip || 0), Number(req.query.skip || 0) + Number(req.query.limit)));
  else res.json(rows);
});
app.get('/api/apps/:app/entities/:type/:id', compatibilityEntity, optionalAuthenticate, (req, res) => {
  if (!publicReadableEntities.has(req.params.type) && !req.user) return res.status(401).json({ message: 'Authentication required' });
  const row = db.prepare('SELECT id, data, created_at, updated_at FROM entities WHERE id = ? AND type = ?').get(req.params.id, req.params.type);
  if (!row) return res.status(404).json({ message: 'Entity not found' });
  const entity = entityResponse(row);
  if (!canReadEntity(req, req.params.type, entity)) return res.status(403).json({ message: 'Insufficient permissions' });
  res.json(entity);
});
app.post('/api/apps/:app/entities/:type', compatibilityEntity, authenticate, (req, res) => {
  if (!allowMemberWrite(req, req.params.type)) return res.status(403).json({ message: 'Insufficient permissions' });
  const created = now();
  const entity = { id: id(), ...(req.body || {}) };
  db.prepare('INSERT INTO entities (id,type,user_id,data,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(entity.id, req.params.type, req.user.id, JSON.stringify(entity), created, created);
  res.status(201).json({ ...entity, created_date: created, updated_date: created });
});
app.post('/api/apps/:app/entities/:type/bulk', compatibilityEntity, authenticate, (req, res) => {
  if (!allowMemberWrite(req, req.params.type) || !Array.isArray(req.body)) return res.status(403).json({ message: 'Insufficient permissions' });
  const created = now();
  const insert = db.prepare('INSERT INTO entities (id,type,user_id,data,created_at,updated_at) VALUES (?,?,?,?,?,?)');
  const entities = req.body.map((item) => {
    const entity = { id: id(), ...item };
    insert.run(entity.id, req.params.type, req.user.id, JSON.stringify(entity), created, created);
    return { ...entity, created_date: created, updated_date: created };
  });
  res.status(201).json(entities);
});
app.put('/api/apps/:app/entities/:type/bulk', compatibilityEntity, authenticate, requireStaff, (req, res) => {
  if (!Array.isArray(req.body)) return res.status(400).json({ message: 'Invalid bulk payload' });
  const updatedAt = now();
  const update = db.prepare('UPDATE entities SET data = ?, updated_at = ? WHERE id = ? AND type = ?');
  const entities = req.body.map((item) => {
    const row = db.prepare('SELECT data FROM entities WHERE id = ? AND type = ?').get(item.id, req.params.type);
    if (!row) return null;
    const updated = { ...JSON.parse(row.data), ...item, id: item.id };
    update.run(JSON.stringify(updated), updatedAt, item.id, req.params.type);
    return { ...updated, updated_date: updatedAt };
  }).filter(Boolean);
  res.json(entities);
});
app.put('/api/apps/:app/entities/:type/:id', compatibilityEntity, authenticate, (req, res) => {
  if (!allowMemberEntityUpdate(req, req.params.type, req.params.id, req.body)) return res.status(403).json({ message: 'Insufficient permissions' });
  const row = db.prepare('SELECT data FROM entities WHERE id = ? AND type = ?').get(req.params.id, req.params.type);
  if (!row) return res.status(404).json({ message: 'Entity not found' });
  const updated = { ...JSON.parse(row.data), ...(req.body || {}), id: req.params.id };
  const updatedAt = now();
  db.prepare('UPDATE entities SET data = ?, updated_at = ? WHERE id = ? AND type = ?').run(JSON.stringify(updated), updatedAt, req.params.id, req.params.type);
  res.json({ ...updated, updated_date: updatedAt });
});
app.patch('/api/apps/:app/entities/:type/update-many', compatibilityEntity, authenticate, requireStaff, (req, res) => {
  const filters = req.body?.query || {};
  const rows = entityRows(req.params.type, { q: JSON.stringify(filters) }, req);
  const updatedAt = now();
  const update = db.prepare('UPDATE entities SET data = ?, updated_at = ? WHERE id = ? AND type = ?');
  const entities = rows.map((row) => {
    const updated = { ...row, ...(req.body?.data || {}), id: row.id };
    update.run(JSON.stringify(updated), updatedAt, row.id, req.params.type);
    return { ...updated, updated_date: updatedAt };
  });
  res.json(entities);
});
app.delete('/api/apps/:app/entities/:type/:id', compatibilityEntity, authenticate, (req, res) => {
  if (!allowMemberEntityUpdate(req, req.params.type, req.params.id, {})) return res.status(403).json({ message: 'Insufficient permissions' });
  const result = db.prepare('DELETE FROM entities WHERE id = ? AND type = ?').run(req.params.id, req.params.type);
  if (!result.changes) return res.status(404).json({ message: 'Entity not found' });
  res.status(204).end();
});
app.delete('/api/apps/:app/entities/:type', compatibilityEntity, authenticate, requireStaff, (req, res) => {
  const ids = Array.isArray(req.body) ? req.body.map((item) => item.id).filter(Boolean) : [];
  const remove = db.prepare('DELETE FROM entities WHERE id = ? AND type = ?');
  ids.forEach((entityId) => remove.run(entityId, req.params.type));
  res.status(204).end();
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  res.status(500).json({ message: 'Internal server error' });
});

app.listen(port, () => console.log(`Ninjutsu Master API listening on http://localhost:${port}`));