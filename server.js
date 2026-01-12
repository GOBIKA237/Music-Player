const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('music.db');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS playlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    videos TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'music-player-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: false // set to true if using HTTPS
  }
}));

// Serve static files AFTER session middleware
app.use(express.static(__dirname, {
  index: false // Don't serve index.html automatically
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.sendFile(path.join(__dirname, 'index.html'));
  } else {
    res.sendFile(path.join(__dirname, 'login.html'));
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const result = stmt.run(username, hashedPassword);
    
    req.session.userId = result.lastInsertRowid;
    req.session.username = username;
    
    res.json({ success: true, username });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Get current user
app.get('/api/user', requireAuth, (req, res) => {
  res.json({ username: req.session.username });
});

// Get playlists
app.get('/api/playlists', requireAuth, (req, res) => {
  const playlists = db.prepare('SELECT * FROM playlists WHERE user_id = ?').all(req.session.userId);
  res.json(playlists.map(p => ({
    ...p,
    videos: p.videos ? JSON.parse(p.videos) : []
  })));
});

// Save playlist
app.post('/api/playlists', requireAuth, (req, res) => {
  const { name, videos } = req.body;
  const stmt = db.prepare('INSERT INTO playlists (user_id, name, videos) VALUES (?, ?, ?)');
  const result = stmt.run(req.session.userId, name, JSON.stringify(videos));
  
  res.json({ success: true, id: result.lastInsertRowid });
});

// Delete playlist
app.delete('/api/playlists/:id', requireAuth, (req, res) => {
  const stmt = db.prepare('DELETE FROM playlists WHERE id = ? AND user_id = ?');
  stmt.run(req.params.id, req.session.userId);
  
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Music Player Server running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop the server');
});