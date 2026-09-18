import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const port = Number(process.env.PORT || 8787);
const databasePath = process.env.DATABASE_PATH || './data/ninjutsu.sqlite';
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new Database(databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    full_name TEXT NOT NULL DEFAULT '',
    phone TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
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

const app = express();
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:8787';
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: allowedOrigin, credentials: true }));
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-8' }));
app.use(express.static(process.cwd(), { extensions: ['html'] }));

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const publicUser = ({ password_hash, ...user }) => user;
const sessionCookie = { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 7 * 24 * 60 * 60 * 1000 };

function tokenFor(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const rawToken = `${userId}.${token}`;
  db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)').run(
    crypto.createHash('sha256').update(rawToken).digest('hex'),
    userId,
    new Date(Date.now() + sessionCookie.maxAge).toISOString(),
    now(),
  );
  return rawToken;
}

function authenticate(req, res, next) {
  const raw = req.cookies.ninjutsu_session;
  if (!raw) return res.status(401).json({ message: 'Authentication required' });
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  const session = db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash, now());
  if (!session) return res.status(401).json({ message: 'Invalid session' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ message: 'Invalid session' });
  req.user = publicUser(user);
  next();
}

function requireStaff(req, res, next) {
  if (!['admin', 'developer'].includes(req.user.role)) return res.status(403).json({ message: 'Insufficient permissions' });
  next();
}

const credentials = z.object({ email: z.string().email().transform((value) => value.toLowerCase()), password: z.string().min(8).max(128) });
const entityName = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/);

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'ninjutsu-master-api' }));
app.post('/api/auth/register', async (req, res) => {
  const parsed = credentials.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Email and password are invalid' });
  const { email, password } = parsed.data;
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return res.status(409).json({ message: 'Email is already registered' });
  const user = { id: id(), email, password_hash: await bcrypt.hash(password, 12), role: 'user', full_name: '', phone: null, created_at: now() };
  db.prepare('INSERT INTO users (id,email,password_hash,role,full_name,phone,created_at) VALUES (@id,@email,@password_hash,@role,@full_name,@phone,@created_at)').run(user);
  res.cookie('ninjutsu_session', tokenFor(user.id), sessionCookie).status(201).json({ user: publicUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const parsed = credentials.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Email and password are invalid' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(parsed.data.email);
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) return res.status(401).json({ message: 'Invalid email or password' });
  res.cookie('ninjutsu_session', tokenFor(user.id), sessionCookie).json({ user: publicUser(user) });
});
app.post('/api/auth/logout', (req, res) => {
  const raw = req.cookies.ninjutsu_session;
  if (raw) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(crypto.createHash('sha256').update(raw).digest('hex'));
  res.clearCookie('ninjutsu_session', sessionCookie).status(204).end();
});
app.get('/api/auth/me', authenticate, (req, res) => res.json(publicUser(req.user)));

app.get('/api/entities/:type', authenticate, (req, res) => {
  const type = entityName.safeParse(req.params.type);
  if (!type.success) return res.status(400).json({ message: 'Invalid entity name' });
  const rows = db.prepare('SELECT id, data, created_at, updated_at FROM entities WHERE type = ? ORDER BY created_at DESC LIMIT 1000').all(type.data);
  res.json(rows.map((row) => ({ id: row.id, ...JSON.parse(row.data), created_date: row.created_at, updated_date: row.updated_at })));
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

app.listen(port, () => console.log(`Ninjutsu Master API listening on http://localhost:${port}`));