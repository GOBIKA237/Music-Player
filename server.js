const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const fs = require('fs');


const dataDir = '/opt/render/project/data';
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'music.db');
const db = new Database(dbPath);



/* 🔐 API KEY ONLY ON SERVER */
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || 'AIzaSyBwzATzzlT0yrBMLoqYEWGmUqrORVO-gXQ';

/* ================= DATABASE ================= */
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
`);

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'music-player-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

/* 🛡️ SECURITY HEADERS */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

app.use(express.static(__dirname, { index: false }));

function requireAuth(req, res, next) {
  if (req.session.userId) next();
  else res.status(401).json({ error: 'Not authenticated' });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, req.session.userId ? 'index.html' : 'login.html'));
});

/* 🔐 SECURE YOUTUBE SEARCH */
app.get('/api/search', requireAuth, async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ items: [] });

  try {
    const ytRes = await fetch(
      `https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&videoCategoryId=10&maxResults=10&q=${encodeURIComponent(q)}&key=${YOUTUBE_API_KEY}`
    );
    const data = await ytRes.json();
    res.json({ items: data.items || [] });
  } catch {
    res.json({ items: [] });
  }
});

/* ================= AUTH ================= */
app.post('/api/register', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, password) VALUES (?, ?)'
  ).run(req.body.username, hash);

  req.session.userId = result.lastInsertRowid;
  req.session.username = req.body.username;
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const user = db.prepare(
    'SELECT * FROM users WHERE username = ?'
  ).get(req.body.username);

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/user', requireAuth, (req, res) => {
  res.json({ username: req.session.username });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Secure Music Player running on port ${PORT}`);
});
