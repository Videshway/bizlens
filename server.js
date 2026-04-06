const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const initSqlJs = require('sql.js');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'bizlens.db');

let db;

// ── Middleware ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'bizlens-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth Middleware ──
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// ── Database Init ──
async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ideas (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    industry TEXT,
    target_audience TEXT,
    status TEXT DEFAULT 'draft',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,
    idea_id TEXT NOT NULL,
    market_size INTEGER DEFAULT 0,
    growth_potential INTEGER DEFAULT 0,
    competition INTEGER DEFAULT 0,
    barrier_to_entry INTEGER DEFAULT 0,
    revenue_model INTEGER DEFAULT 0,
    scalability INTEGER DEFAULT 0,
    team_fit INTEGER DEFAULT 0,
    timing INTEGER DEFAULT 0,
    customer_pain INTEGER DEFAULT 0,
    innovation INTEGER DEFAULT 0,
    funding_needs INTEGER DEFAULT 0,
    total_score REAL DEFAULT 0,
    grade TEXT DEFAULT 'F',
    scored_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (idea_id) REFERENCES ideas(id)
  )`);

  saveDB();
  console.log('Database initialized');
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// ── Scoring Algorithm ──
const WEIGHTS = {
  market_size: 0.12,
  growth_potential: 0.10,
  competition: 0.08,
  barrier_to_entry: 0.07,
  revenue_model: 0.12,
  scalability: 0.11,
  team_fit: 0.09,
  timing: 0.08,
  customer_pain: 0.13,
  innovation: 0.05,
  funding_needs: 0.05
};

function calculateScore(metrics) {
  let weighted = 0;
  let totalWeight = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const val = metrics[key] || 0;
    weighted += val * weight;
    totalWeight += weight;
  }
  const score = (weighted / totalWeight) * 10; // Scale to 100
  return Math.round(score * 10) / 10;
}

function getGrade(score) {
  if (score >= 90) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 80) return 'A-';
  if (score >= 75) return 'B+';
  if (score >= 70) return 'B';
  if (score >= 65) return 'B-';
  if (score >= 60) return 'C+';
  if (score >= 55) return 'C';
  if (score >= 50) return 'C-';
  if (score >= 45) return 'D+';
  if (score >= 40) return 'D';
  return 'F';
}

// AUTH ROUTES

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = db.exec("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const id = uuidv4();

    db.run("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)",
      [id, name, email, hashedPassword]);
    saveDB();

    req.session.userId = id;
    req.session.userName = name;
    req.session.userEmail = email;

    res.json({ success: true, user: { id, name, email } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = db.exec("SELECT id, name, email, password FROM users WHERE email = ?", [email]);
    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result[0].values[0];
    const [id, name, userEmail, hashedPassword] = user;

    const valid = await bcrypt.compare(password, hashedPassword);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.session.userId = id;
    req.session.userName = name;
    req.session.userEmail = userEmail;

    res.json({ success: true, user: { id, name, email: userEmail } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({
    user: {
      id: req.session.userId,
      name: req.session.userName,
      email: req.session.userEmail
    }
  });
});

// IDEAS ROUTES

app.get('/api/ideas', requireAuth, (req, res) => {
  try {
    const result = db.exec(`
      SELECT i.*, s.total_score, s.grade
      FROM ideas i
      LEFT JOIN scores s ON i.id = s.idea_id
      WHERE i.user_id = ?
      ORDER BY i.created_at DESC
    `, [req.session.userId]);

    if (result.length === 0) return res.json({ ideas: [] });

    const columns = result[0].columns;
    const ideas = result[0].values.map(row => {
      const obj = {};
      columns.forEach((col, i) => obj[col] = row[i]);
      return obj;
    });

    res.json({ ideas });
  } catch (err) {
    console.error('List ideas error:', err);
    res.status(500).json({ error: 'Failed to fetch ideas' });
  }
});

app.post('/api/ideas', requireAuth, (req, res) => {
  try {
    const { name, description, industry, target_audience } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Idea name is required' });
    }

    const id = uuidv4();
    db.run(`INSERT INTO ideas (id, user_id, name, description, industry, target_audience)
            VALUES (?, ?, ?, ?, ?, ?)`,
      [id, req.session.userId, name, description || '', industry || '', target_audience || '']);
    saveDB();

    res.json({ success: true, idea: { id, name, description, industry, target_audience, status: 'draft' } });
  } catch (err) {
    console.error('Create idea error:', err);
    res.status(500).json({ error: 'Failed to create idea' });
  }
});

app.get('/api/ideas/:id', requireAuth, (req, res) => {
  try {
    const result = db.exec(`
      SELECT i.*, s.market_size, s.growth_potential, s.competition, s.barrier_to_entry,
             s.revenue_model, s.scalability, s.team_fit, s.timing, s.customer_pain,
             s.innovation, s.funding_needs, s.total_score, s.grade, s.scored_at
      FROM ideas i
      LEFT JOIN scores s ON i.id = s.idea_id
      WHERE i.id = ? AND i.user_id = ?
    `, [req.params.id, req.session.userId]);

    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ error: 'Idea not found' });
    }

    const columns = result[0].columns;
    const idea = {};
    columns.forEach((col, i) => idea[col] = result[0].values[0][i]);

    res.json({ idea });
  } catch (err) {
    console.error('Get idea error:', err);
    res.status(500).json({ error: 'Failed to fetch idea' });
  }
});

app.put('/api/ideas/:id', requireAuth, (req, res) => {
  try {
    const { name, description, industry, target_audience } = req.body;

    db.run(`UPDATE ideas SET name = ?, description = ?, industry = ?, target_audience = ?,
            updated_at = datetime('now') WHERE id = ? AND user_id = ?`,
      [name, description, industry, target_audience, req.params.id, req.session.userId]);
    saveDB();

    res.json({ success: true });
  } catch (err) {
    console.error('Update idea error:', err);
    res.status(500).json({ error: 'Failed to update idea' });
  }
});

app.delete('/api/ideas/:id', requireAuth, (req, res) => {
  try {
    db.run("DELETE FROM scores WHERE idea_id = ?", [req.params.id]);
    db.run("DELETE FROM ideas WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId]);
    saveDB();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete idea error:', err);
    res.status(500).json({ error: 'Failed to delete idea' });
  }
});

// SCORING ROUTES

app.post('/api/ideas/:id/score', requireAuth, (req, res) => {
  try {
    const ideaId = req.params.id;
    const metrics = req.body;

    // Verify ownership
    const check = db.exec("SELECT id FROM ideas WHERE id = ? AND user_id = ?", [ideaId, req.session.userId]);
    if (check.length === 0 || check[0].values.length === 0) {
      return res.status(404).json({ error: 'Idea not found' });
    }

    const totalScore = calculateScore(metrics);
    const grade = getGrade(totalScore);

    // Upsert score
    db.run("DELETE FROM scores WHERE idea_id = ?", [ideaId]);
    const scoreId = uuidv4();
    db.run(`INSERT INTO scores (id, idea_id, market_size, growth_potential, competition,
            barrier_to_entry, revenue_model, scalability, team_fit, timing,
            customer_pain, innovation, funding_needs, total_score, grade)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [scoreId, ideaId, metrics.market_size || 0, metrics.growth_potential || 0,
       metrics.competition || 0, metrics.barrier_to_entry || 0, metrics.revenue_model || 0,
       metrics.scalability || 0, metrics.team_fit || 0, metrics.timing || 0,
       metrics.customer_pain || 0, metrics.innovation || 0, metrics.funding_needs || 0,
       totalScore, grade]);

    db.run("UPDATE ideas SET status = 'scored', updated_at = datetime('now') WHERE id = ?", [ideaId]);
    saveDB();

    res.json({
      success: true,
      score: { total_score: totalScore, grade, metrics }
    });
  } catch (err) {
    console.error('Score idea error:', err);
    res.status(500).json({ error: 'Failed to score idea' });
  }
});

// ── Dashboard Stats ──
app.get('/api/dashboard', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;

    const totalResult = db.exec("SELECT COUNT(*) FROM ideas WHERE user_id = ?", [userId]);
    const totalIdeas = totalResult[0]?.values[0]?.[0] || 0;

    const scoredResult = db.exec("SELECT COUNT(*) FROM ideas WHERE user_id = ? AND status = 'scored'", [userId]);
    const scoredIdeas = scoredResult[0]?.values[0]?.[0] || 0;

    const avgResult = db.exec(`
      SELECT AVG(s.total_score) FROM scores s
      JOIN ideas i ON s.idea_id = i.id
      WHERE i.user_id = ?
    `, [userId]);
    const avgScore = avgResult[0]?.values[0]?.[0] || 0;

    const topResult = db.exec(`
      SELECT i.name, s.total_score, s.grade FROM scores s
      JOIN ideas i ON s.idea_id = i.id
      WHERE i.user_id = ?
      ORDER BY s.total_score DESC LIMIT 5
    `, [userId]);

    let topIdeas = [];
    if (topResult.length > 0) {
      topIdeas = topResult[0].values.map(row => ({
        name: row[0], score: row[1], grade: row[2]
      }));
    }

    res.json({
      totalIdeas,
      scoredIdeas,
      avgScore: Math.round(avgScore * 10) / 10,
      topIdeas
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// ── SPA fallback ──
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`BizLens running at http://localhost:${PORT}`);
  });
});
