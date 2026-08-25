const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const PDFDocument = require('pdfkit');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'PORTFOLIO_SECRET';

// ─── DATABASE ───
const db = new sqlite3.Database('./portfolio.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    name TEXT,
    username TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    tagline TEXT,
    bio TEXT,
    avatar_url TEXT,
    skills TEXT,
    stats TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    tags TEXT,
    image_url TEXT,
    links TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS experiences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    company TEXT,
    date TEXT,
    description TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Seed default accounts
  const hash = (p) => bcrypt.hashSync(p, 8);
  const users = [
    ['admin@portfolio.com', hash('admin123'), 'admin', 'Admin User', 'admin'],
    ['kekanaletago58@gmail.com', hash('Password@123'), 'mentor', 'Letago', 'letago'],
    ['zinhle@portfolio.com', hash('user123'), 'user', 'Zinhle Ntuli', 'zinhle']
  ];
  users.forEach(u => {
    db.get("SELECT id FROM users WHERE email = ?", [u[0]], (err, row) => {
      if (err) return console.error('Seed error:', err.message);
      if (!row) {
        db.run("INSERT INTO users (email, password, role, name, username) VALUES (?,?,?,?,?)", u, (err) => {
          if (err) console.error('Insert seed error:', err.message);
        });
      }
    });
  });
});

// ─── MIDDLEWARE ───
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// ─── AUTH ───
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, name: user.name, username: user.username } });
  });
});

// ─── PUBLIC PROFILE (for shared links) ───
app.get('/api/profile/:username', (req, res) => {
  const { username } = req.params;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'Not found' });

    db.get("SELECT * FROM profiles WHERE user_id = ?", [user.id], (err, profile) => {
      if (err) return res.status(500).json({ error: err.message });

      db.all("SELECT * FROM projects WHERE user_id = ?", [user.id], (err, projects) => {
        if (err) return res.status(500).json({ error: err.message });

        db.all("SELECT * FROM experiences WHERE user_id = ?", [user.id], (err, experiences) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ user, profile: profile || {}, projects: projects || [], experiences: experiences || [] });
        });
      });
    });
  });
});

// ─── PROTECTED: MANAGE OWN DATA ───
app.get('/api/me', authenticate, (req, res) => {
  db.get("SELECT id, email, role, name, username FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});

app.put('/api/me/profile', authenticate, (req, res) => {
  const { tagline, bio, skills, stats, avatar_url } = req.body;
  db.get("SELECT * FROM profiles WHERE user_id = ?", [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });

    if (row) {
      db.run("UPDATE profiles SET tagline=?, bio=?, skills=?, stats=?, avatar_url=? WHERE user_id=?",
        [tagline, bio, skills, stats, avatar_url, req.user.id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Profile saved' });
        });
    } else {
      db.run("INSERT INTO profiles (user_id, tagline, bio, skills, stats, avatar_url) VALUES (?,?,?,?,?,?)",
        [req.user.id, tagline, bio, skills, stats, avatar_url], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Profile saved' });
        });
    }
  });
});

// Projects CRUD
app.get('/api/me/projects', authenticate, (req, res) => {
  db.all("SELECT * FROM projects WHERE user_id = ?", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/me/projects', authenticate, (req, res) => {
  const { title, description, tags, image_url, links } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });

  db.run("INSERT INTO projects (user_id, title, description, tags, image_url, links) VALUES (?,?,?,?,?,?)",
    [req.user.id, title, description, tags, image_url, links], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put('/api/me/projects/:id', authenticate, (req, res) => {
  const { title, description, tags, image_url, links } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });

  db.run("UPDATE projects SET title=?, description=?, tags=?, image_url=?, links=? WHERE id=? AND user_id=?",
    [title, description, tags, image_url, links, req.params.id, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Project not found or not owned by you' });
      res.json({ message: 'Updated' });
    });
});

app.delete('/api/me/projects/:id', authenticate, (req, res) => {
  db.run("DELETE FROM projects WHERE id=? AND user_id=?", [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Project not found or not owned by you' });
    res.json({ message: 'Deleted' });
  });
});

// Experience CRUD
app.get('/api/me/experiences', authenticate, (req, res) => {
  db.all("SELECT * FROM experiences WHERE user_id = ?", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/me/experiences', authenticate, (req, res) => {
  const { title, company, date, description } = req.body;
  if (!title || !company) return res.status(400).json({ error: 'Title and company are required' });

  db.run("INSERT INTO experiences (user_id, title, company, date, description) VALUES (?,?,?,?,?)",
    [req.user.id, title, company, date, description], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put('/api/me/experiences/:id', authenticate, (req, res) => {
  const { title, company, date, description } = req.body;
  if (!title || !company) return res.status(400).json({ error: 'Title and company are required' });

  db.run("UPDATE experiences SET title=?, company=?, date=?, description=? WHERE id=? AND user_id=?",
    [title, company, date, description, req.params.id, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Experience not found or not owned by you' });
      res.json({ message: 'Updated' });
    });
});

app.delete('/api/me/experiences/:id', authenticate, (req, res) => {
  db.run("DELETE FROM experiences WHERE id=? AND user_id=?", [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Experience not found or not owned by you' });
    res.json({ message: 'Deleted' });
  });
});

// ─── ADMIN / MENTOR ROUTES ───
app.get('/api/admin/users', authenticate, authorize('admin', 'mentor'), (req, res) => {
  db.all("SELECT id, email, role, name, username FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.put('/api/admin/users/:id/role', authenticate, authorize('admin'), (req, res) => {
  const { role } = req.body;
  if (!role) return res.status(400).json({ error: 'Role is required' });

  db.run("UPDATE users SET role=? WHERE id=?", [role, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Role updated' });
  });
});

// ─── CV DOWNLOAD (PDF Generation) ───
app.get('/api/cv/:username/download', (req, res) => {
  const { username } = req.params;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.status(500).send('Database error');
    if (!user) return res.status(404).send('User not found');

    db.get("SELECT * FROM profiles WHERE user_id = ?", [user.id], (err, profile) => {
      if (err) return res.status(500).send('Database error');

      db.all("SELECT * FROM experiences WHERE user_id = ?", [user.id], (err, experiences) => {
        if (err) return res.status(500).send('Database error');

        db.all("SELECT * FROM projects WHERE user_id = ?", [user.id], (err, projects) => {
          if (err) return res.status(500).send('Database error');

          try {
            const doc = new PDFDocument();
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${username}-cv.pdf"`);
            doc.pipe(res);

            doc.fontSize(24).text(user.name, 50, 50);
            doc.fontSize(12).fillColor('#666').text(profile?.tagline || '', 50, 80);
            doc.moveDown();
            doc.fillColor('#000').fontSize(12).text(profile?.bio || 'No bio provided.');
            doc.moveDown();

            doc.fontSize(16).text('Experience', { underline: true });
            doc.moveDown(0.5);
            if (experiences.length === 0) {
              doc.fontSize(10).text('No experience listed.');
              doc.moveDown();
            } else {
              experiences.forEach(exp => {
                doc.fontSize(12).text(`${exp.title} — ${exp.company} (${exp.date})`);
                doc.fontSize(10).text(exp.description || '');
                doc.moveDown();
              });
            }

            doc.fontSize(16).text('Projects', { underline: true });
            doc.moveDown(0.5);
            if (projects.length === 0) {
              doc.fontSize(10).text('No projects listed.');
              doc.moveDown();
            } else {
              projects.forEach(proj => {
                doc.fontSize(12).text(proj.title);
                doc.fontSize(10).text(proj.description || '');
                doc.moveDown();
              });
            }

            doc.end();
          } catch (pdfErr) {
            console.error('PDF generation error:', pdfErr);
            if (!res.headersSent) return res.status(500).send('PDF generation failed');
          }
        });
      });
    });
  });
});

// ─── 404 & ERROR HANDLERS ───
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── START SERVER ───
const server = app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ─── GRACEFUL SHUTDOWN ───
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  server.close(() => {
    db.close((err) => {
      if (err) console.error('DB close error:', err);
      console.log('Database connection closed.');
      process.exit(0);
    });
  });
});