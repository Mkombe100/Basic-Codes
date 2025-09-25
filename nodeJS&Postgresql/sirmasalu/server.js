const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'views')));

// Serve index.html for registration and login
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { firstname, lastname, email, phonenumber, address, age, gender, password } = req.body;
  const role = gender.toLowerCase() === 'instructor' ? 'instructor' : 'student';

  try {
    // Check if email exists in either table
    const instructorCheck = await pool.query('SELECT * FROM instructors WHERE email = $1', [email]);
    const studentCheck = await pool.query('SELECT * FROM students WHERE email = $1', [email]);
    if (instructorCheck.rows.length > 0 || studentCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `
      INSERT INTO ${role}s (firstname, lastname, email, phonenumber, address, age, password)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, firstname, lastname, email
    `;
    const values = [firstname, lastname, email, phonenumber, address, age, hashedPassword];
    const { rows } = await pool.query(query, values);

    res.status(201).json({ message: 'Registration successful', user: { ...rows[0], role } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check both tables for the user
    let user, role;
    const instructorResult = await pool.query('SELECT * FROM instructors WHERE email = $1', [email]);
    if (instructorResult.rows.length > 0) {
      user = instructorResult.rows[0];
      role = 'instructor';
    } else {
      const studentResult = await pool.query('SELECT * FROM students WHERE email = $1', [email]);
      if (studentResult.rows.length > 0) {
        user = studentResult.rows[0];
        role = 'student';
      }
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Dashboard routes
app.get('/dash', authenticateToken, (req, res) => {
  if (req.user.role === 'instructor') {
    res.sendFile(path.join(__dirname, 'views', 'dash.html'));
  } else {
    res.status(403).json({ message: 'Access denied' });
  }
});

app.get('/stud_dash', authenticateToken, (req, res) => {
  if (req.user.role === 'student') {
    res.sendFile(path.join(__dirname, 'views', 'stud_dash.html'));
  } else {
    res.status(403).json({ message: 'Access denied' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});