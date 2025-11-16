import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});

// Ensure users table exists
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
    console.log('✅ Users table ensured');
  } catch (err) {
    console.error('❌ Error ensuring users table:', err.message);
  }
})();

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  console.log('📥 Incoming registration:', username);
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    console.log(`✅ Registered user: ${username}`);
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
  } catch (err) {
    console.error('❌ Registration error:', err.message);
    res.status(500).send('Error registering user');
  }
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('🔐 Login attempt:', username);
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        console.log(`✅ Login success: ${username}`);
        res.sendFile(path.join(__dirname, 'public', 'main.html'));
      } else {
        console.log(`❌ Wrong password for: ${username}`);
        res.status(401).send('Invalid username or password');
      }
    } else {
      console.log(`❌ Username not found: ${username}`);
      res.status(401).send('Invalid username or password');
    }
  } catch (err) {
    console.error('❌ Login error:', err.message);
    res.status(500).send('Error logging in');
  }
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  pool.query('SELECT NOW()', (err, res) => {
    if (err) {
      console.error('❌ DB connection failed:', err.message);
      console.log('🔍 DATABASE_URL:', process.env.DATABASE_URL);
    } else {
      console.log('🔗 Connected to Supabase at:', res.rows[0].now);
    }
  });
});

process.on('SIGINT', async () => {
  console.log('🛑 Shutting down...');
  await pool.end();
  process.exit(0);
});