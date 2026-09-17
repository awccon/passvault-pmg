// PassVault server
// -----------------
// This server NEVER sees your master password and NEVER sees your
// decrypted vault. It only stores:
//   - a one-way-derived "auth proof" (hashed again with bcrypt), used
//     purely to check you know the master password at login
//   - an opaque encrypted blob (your vault, encrypted in the browser)
//
// If someone steals data/users.json and data/vaults.json, they get
// nothing usable without your master password.
//
// The one exception is the shared chat below: unlike the vault, chat
// messages are stored in plain text (same trust model as any ordinary
// self-hosted chat tool) since they need to be readable by every user,
// not just the one who wrote them.

// Load a .env file if one exists (an alternative to setting environment
// variables on the command line — edit the file, no terminal needed).
// A real environment variable (e.g. one set by pm2) always wins over
// whatever's in the file, so this is safe to leave in place everywhere.
try {
  process.loadEnvFile();
} catch (e) {
  // No .env file present — fine, fall back to real environment variables.
}

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(VAULTS_FILE)) fs.writeFileSync(VAULTS_FILE, '[]');
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '[]');

const MAX_MESSAGES = 500;
const MAX_MESSAGE_LENGTH = 2000;

function readJSON(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function writeJSON(file, data) {
  // write to temp file then rename, to avoid corruption on crash
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set in environment. Using a random secret ' +
    'that will change on every restart (all sessions will be invalidated). ' +
    'Set SESSION_SECRET in your environment for production use.');
}

// New accounts require this code (set by you, the operator) so only
// people you've shared it with can register. Unset = registration
// disabled entirely (fail closed, not fail open).
const REGISTRATION_CODE = process.env.REGISTRATION_CODE || null;
if (!REGISTRATION_CODE) {
  console.warn('WARNING: REGISTRATION_CODE not set in environment. New account ' +
    'registration is DISABLED until you set it. Existing accounts can still log in.');
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // Set secure:true automatically when running behind HTTPS.
    // If you put this behind a reverse proxy with TLS, also set
    // app.set('trust proxy', 1) and cookie.secure = true.
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 1000 * 60 * 60 * 12 // 12 hours
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  next();
}

// Limit brute-forcing of master passwords / usernames.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' }
});

// Keep a buggy client (or a spammy user) from flooding the shared chat.
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Sending too many messages. Slow down a bit.' }
});

// --- Registration ---
// Client sends: username, salt (base64, generated client-side),
// authProof (base64) = a value derived from the master password via
// PBKDF2 in the browser. We never see the master password itself.
app.post('/api/register', loginLimiter, async (req, res) => {
  try {
    const { username, salt, authProof, inviteCode } = req.body || {};
    if (!username || !salt || !authProof) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (!REGISTRATION_CODE) {
      return res.status(503).json({ error: 'Registration is currently disabled on this server.' });
    }
    if (!inviteCode || !timingSafeEqualStr(inviteCode, REGISTRATION_CODE)) {
      return res.status(403).json({ error: 'Invalid invite code' });
    }
    if (typeof username !== 'string' || username.length < 3 || username.length > 64) {
      return res.status(400).json({ error: 'Username must be 3-64 characters' });
    }
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    const authHash = await bcrypt.hash(authProof, 12);
    const user = {
      id: crypto.randomUUID(),
      username,
      salt,       // safe to store: useless without the master password
      authHash,   // bcrypt hash of the derived auth proof
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeJSON(USERS_FILE, users);

    const vaults = readJSON(VAULTS_FILE);
    vaults.push({ userId: user.id, iv: null, blob: null, updatedAt: null });
    writeJSON(VAULTS_FILE, vaults);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Client needs the salt before it can compute its authProof at login.
app.get('/api/salt/:username', (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username.toLowerCase() === req.params.username.toLowerCase());
  if (!user) {
    // Return a fake-but-stable salt so we don't trivially reveal
    // which usernames exist via timing/shape differences.
    const fakeSalt = crypto.createHash('sha256').update('nosalt:' + req.params.username).digest('base64').slice(0, 24);
    return res.json({ salt: fakeSalt });
  }
  res.json({ salt: user.salt });
});

// A precomputed dummy hash, compared against when the username doesn't
// exist, so login always takes ~the same time either way and can't be
// used to enumerate valid usernames via timing.
const DUMMY_HASH = bcrypt.hashSync('no-such-user-dummy-password', 12);

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, authProof } = req.body || {};
    if (!username || !authProof) return res.status(400).json({ error: 'Missing fields' });
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    const ok = await bcrypt.compare(authProof, user ? user.authHash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: 'Invalid username or master password' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ loggedIn: true, username: req.session.username });
  }
  res.json({ loggedIn: false });
});

// --- Vault (always opaque encrypted blob to the server) ---
app.get('/api/vault', requireAuth, (req, res) => {
  const vaults = readJSON(VAULTS_FILE);
  const v = vaults.find(v => v.userId === req.session.userId);
  if (!v || !v.blob) return res.json({ iv: null, blob: null });
  res.json({ iv: v.iv, blob: v.blob });
});

app.put('/api/vault', requireAuth, (req, res) => {
  const { iv, blob } = req.body || {};
  if (!iv || !blob) return res.status(400).json({ error: 'Missing iv/blob' });
  const vaults = readJSON(VAULTS_FILE);
  const idx = vaults.findIndex(v => v.userId === req.session.userId);
  const entry = { userId: req.session.userId, iv, blob, updatedAt: new Date().toISOString() };
  if (idx === -1) vaults.push(entry); else vaults[idx] = entry;
  writeJSON(VAULTS_FILE, vaults);
  res.json({ ok: true });
});

// --- Chat (shared, plain text — see note at the top of this file) ---
app.get('/api/messages', requireAuth, (req, res) => {
  const messages = readJSON(MESSAGES_FILE);
  const since = req.query.since;
  const result = since ? messages.filter(m => m.createdAt > since) : messages;
  res.json({ messages: result });
});

app.post('/api/messages', requireAuth, chatLimiter, (req, res) => {
  const { text } = req.body || {};
  if (typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({ error: 'Message cannot be empty' });
  }
  if (text.length > MAX_MESSAGE_LENGTH) {
    return res.status(400).json({ error: `Message too long (max ${MAX_MESSAGE_LENGTH} characters)` });
  }
  const messages = readJSON(MESSAGES_FILE);
  const message = {
    id: crypto.randomUUID(),
    userId: req.session.userId,
    username: req.session.username,
    text: text.trim(),
    createdAt: new Date().toISOString()
  };
  messages.push(message);
  if (messages.length > MAX_MESSAGES) messages.splice(0, messages.length - MAX_MESSAGES);
  writeJSON(MESSAGES_FILE, messages);
  res.json({ ok: true, message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PassVault running on http://localhost:${PORT}`);
});
