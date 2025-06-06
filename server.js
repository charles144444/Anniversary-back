const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Debug: Log all route registrations
['get', 'post', 'put', 'delete', 'use'].forEach(method => {
  const orig = app[method];
  app[method] = function(path, ...args) {
    if (typeof path === 'string') {
      console.log(`Registering ${method.toUpperCase()} route:`, path);
    }
    return orig.call(this, path, ...args);
  };
});

// Middleware
app.use(cors());
app.use(bodyParser.json());

// SQLite DB setup
const dbPath = path.resolve(__dirname, 'anniversary.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create tables if not exist
const createTables = () => {
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS gallery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src TEXT NOT NULL,
    caption TEXT,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    text TEXT NOT NULL,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  // Add is_admin column if it doesn't exist
  db.get("PRAGMA table_info(users)", (err, info) => {
    db.all("PRAGMA table_info(users)", (err, columns) => {
      if (!columns.some(col => col.name === 'is_admin')) {
        db.run('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0');
      }
    });
  });
};
createTables();

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Auth: Signup
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hashedPassword = bcrypt.hashSync(password, 10);
  const isAdmin = username === 'pietro' ? 1 : 0;
  db.run('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', [username, hashedPassword, isAdmin], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }
    const user = { id: this.lastID, username, is_admin: isAdmin };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  });
});

// Auth: Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, is_admin: user.is_admin } });
  });
});

// Gallery Endpoints (SHARED)
app.get('/api/gallery', authenticateToken, (req, res) => {
  db.all('SELECT * FROM gallery ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/gallery', authenticateToken, (req, res) => {
  const { src, caption } = req.body;
  if (!src) return res.status(400).json({ error: 'Image src required' });
  db.run('INSERT INTO gallery (src, caption, user_id) VALUES (?, ?, ?)', [src, caption || '', req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ id: this.lastID, src, caption, user_id: req.user.id });
  });
});

app.delete('/api/gallery/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM gallery WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Image not found' });
    res.json({ success: true });
  });
});

// Messages Endpoints (SHARED)
app.get('/api/messages', authenticateToken, (req, res) => {
  db.all('SELECT * FROM messages ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/messages', authenticateToken, (req, res) => {
  const { sender, text } = req.body;
  if (!sender || !text) return res.status(400).json({ error: 'Sender and text required' });
  db.run('INSERT INTO messages (sender, text, user_id) VALUES (?, ?, ?)', [sender, text, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ id: this.lastID, sender, text, user_id: req.user.id });
  });
});

app.delete('/api/messages/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM messages WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Message not found' });
    res.json({ success: true });
  });
});

// ADMIN ENDPOINT: List all users (now includes is_admin)
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Forbidden' });
  db.all('SELECT id, username, is_admin FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Delete a user (admin only, cannot delete self)
app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Forbidden' });
  if (req.user.id == req.params.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

// Toggle admin status (admin only, cannot demote self)
app.post('/api/admin/users/:id/toggle-admin', authenticateToken, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Forbidden' });
  if (req.user.id == req.params.id) return res.status(400).json({ error: 'Cannot change your own admin status' });
  db.get('SELECT is_admin FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'Database error' });
    const newStatus = user.is_admin ? 0 : 1;
    db.run('UPDATE users SET is_admin = ? WHERE id = ?', [newStatus, req.params.id], function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, is_admin: newStatus });
    });
  });
});

// Serve static files from the React app (for deployment)
// const clientBuildPath = path.join(__dirname, 'client', 'build');
// app.use(express.static(clientBuildPath));
// app.get('*', (req, res) => {
//   // Only serve index.html for non-API routes
//   if (!req.path.startsWith('/api/')) {
//     res.sendFile(path.join(clientBuildPath, 'index.html'));
//   } else {
//     res.status(404).json({ error: 'Not found' });
//   }
// });

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app, db };