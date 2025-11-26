// server.js (CommonJS) — PATCHED for safe file writes & serialized file access
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'keys.json');
const BACKUP_FILE = path.join(__dirname, 'keys.json.bak');
const TMP_FILE = path.join(__dirname, 'keys.json.tmp');
const CONFIG_FILE = path.join(__dirname, 'config.json');

// JWT / HMAC secrets
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-me-jwt';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-me-hmac';

// Initialize files if missing (only create empty file on first-run)
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = 'superhentai';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = { admin: { username: 'zxsadmin', passwordHash: hash } };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

// ----------------- File operation queue (serialize all file I/O) -----------------
// Use a Promise chain to queue operations so read-modify-write cannot interleave.
let fileOpQueue = Promise.resolve();

function enqueueFileOp(fn) {
  // fn is async function that does the file operation and returns value
  fileOpQueue = fileOpQueue
    .then(() => fn())
    .catch(err => {
      console.error('fileOpQueue inner error:', err);
      // swallow error to not break queue chain, but rethrow so callers can handle
      throw err;
    });
  return fileOpQueue;
}

// ----------------- Safe read/write helpers -----------------
async function safeReadFile() {
  // Read file contents synchronously (within the queue) and parse JSON.
  return enqueueFileOp(() => {
    try {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
          console.warn('keys.json content is not an array, treating as empty array');
          return [];
        }
        return parsed;
      } catch (parseErr) {
        console.error('Failed to parse keys.json, attempting backup:', parseErr);
        // try backup
        if (fs.existsSync(BACKUP_FILE)) {
          try {
            const bak = fs.readFileSync(BACKUP_FILE, 'utf8');
            const parsedBak = JSON.parse(bak);
            console.warn('Recovered keys from backup');
            return parsedBak;
          } catch (e) {
            console.error('Backup read/parse failed', e);
          }
        }
        // as last resort return empty array (but DO NOT overwrite original file here)
        return [];
      }
    } catch (err) {
      console.error('safeReadFile error', err);
      // if file missing (shouldn't be), return empty
      return [];
    }
  });
}

async function safeWriteFile(keys) {
  // Write atomically: write to tmp file then rename. Also keep a backup copy.
  return enqueueFileOp(() => {
    try {
      // make backup first (best-effort)
      try {
        if (fs.existsSync(DATA_FILE)) {
          fs.copyFileSync(DATA_FILE, BACKUP_FILE);
        }
      } catch (bakErr) {
        console.warn('Backup failed (continuing):', bakErr);
      }

      // write tmp then rename
      fs.writeFileSync(TMP_FILE, JSON.stringify(keys, null, 2), 'utf8');
      // atomic rename on most platforms
      fs.renameSync(TMP_FILE, DATA_FILE);
      return true;
    } catch (err) {
      console.error('safeWriteFile error', err);
      // cleanup tmp if exists
      try { if (fs.existsSync(TMP_FILE)) fs.unlinkSync(TMP_FILE); } catch(e){}
      throw err;
    }
  });
}

// ----------------- config helpers -----------------
function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch (e) {
    console.error('Failed to read config.json', e);
    throw e;
  }
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

// ----------------- HMAC / JWT helpers -----------------
function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && payload.username === loadConfig().admin.username) {
      req.admin = payload;
      return next();
    } else {
      return res.status(403).json({ error: 'Not admin' });
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

// ----------------- Endpoints -----------------

// Admin login
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body || {};
  const cfg = loadConfig();
  if (!username || !password) return res.status(400).json({ success: false, message: 'Missing' });
  if (username !== cfg.admin.username) return res.status(401).json({ success: false, message: 'Invalid' });
  const ok = await bcrypt.compare(password, cfg.admin.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid' });
  const token = jwt.sign({ username: cfg.admin.username, iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: '6h' });
  return res.json({ success: true, token });
});

// Create key (async, uses safe read/write)
app.post('/api/create-key', requireAdmin, async (req, res) => {
  const { days, devices } = req.body || {};
  // validate inputs
  const daysNum = Number(days);
  const devicesNum = Number(devices);
  if (!Number.isFinite(daysNum) || daysNum <= 0) return res.status(400).json({ success: false, message: 'Invalid days' });
  if (!Number.isFinite(devicesNum) || devicesNum <= 0 || devicesNum > 1000) return res.status(400).json({ success: false, message: 'Invalid devices' });

  try {
    const keys = await safeReadFile();

    // generate unique key_code (guard against collisions)
    let keyCode;
    for (let attempts = 0; attempts < 8; attempts++) {
      const candidate = `ZXS-${Math.random().toString(36).substring(2,8).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
      if (!keys.find(k => k.key_code === candidate)) { keyCode = candidate; break; }
    }
    if (!keyCode) keyCode = `ZXS-${uuidv4().slice(0,8).toUpperCase()}`;

    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + (daysNum * 24 * 60 * 60 * 1000)).toISOString();
    const signature = signValue(keyCode);

    const record = {
      id: uuidv4(),
      key_code: keyCode,
      signature,
      created_at: createdAt,
      expires_at: expiresAt,
      allowed_devices: Number(devicesNum),
      devices: []
    };

    keys.push(record);
    await safeWriteFile(keys);
    return res.json({ success: true, key: record });
  } catch (e) {
    console.error('create-key error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// List keys
app.get('/api/list-keys', requireAdmin, async (req, res) => {
  try {
    const keys = await safeReadFile();
    return res.json(keys);
  } catch (e) {
    console.error('list-keys error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Extend key
app.post('/api/extend-key', requireAdmin, async (req, res) => {
  const { key, days } = req.body || {};
  const daysNum = Number(days);
  if (!key || !Number.isFinite(daysNum) || daysNum <= 0) return res.status(400).json({ success: false, message: 'Invalid' });
  try {
    const keys = await safeReadFile();
    const found = keys.find(k => k.key_code === key);
    if (!found) return res.status(404).json({ success: false, message: 'Not found' });
    found.expires_at = new Date(new Date(found.expires_at).getTime() + daysNum * 86400000).toISOString();
    await safeWriteFile(keys);
    return res.json({ success: true });
  } catch (e) {
    console.error('extend-key error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Reset key devices
app.post('/api/reset-key', requireAdmin, async (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
  try {
    const keys = await safeReadFile();
    const found = keys.find(k => k.key_code === key);
    if (!found) return res.status(404).json({ success: false, message: 'Not found' });
    found.devices = [];
    await safeWriteFile(keys);
    return res.json({ success: true });
  } catch (e) {
    console.error('reset-key error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete key
app.post('/api/delete-key', requireAdmin, async (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ success: false, message: 'Missing key' });
  try {
    let keys = await safeReadFile();
    keys = keys.filter(k => k.key_code !== key);
    await safeWriteFile(keys);
    return res.json({ success: true });
  } catch (e) {
    console.error('delete-key error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Verify key (public)
app.post('/api/verify-key', async (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key || !device_id) return res.status(400).json({ success: false, message: 'Missing' });

  try {
    const keys = await safeReadFile();
    const found = keys.find(k => k.key_code === key);
    if (!found) return res.status(404).json({ success: false, message: 'Key not found' });

    const expectedSig = signValue(found.key_code);
    if (expectedSig !== found.signature) {
      return res.status(500).json({ success: false, message: 'Key signature mismatch' });
    }

    if (new Date(found.expires_at) < new Date()) {
      return res.json({ success: false, message: 'Expired' });
    }

    if (!Array.isArray(found.devices)) found.devices = [];
    if (!found.devices.includes(device_id)) {
      if (found.devices.length >= found.allowed_devices) {
        return res.json({ success: false, message: 'Device limit reached' });
      }
      found.devices.push(device_id);
      await safeWriteFile(keys);
    }

    return res.json({ success: true, message: 'OK' });
  } catch (e) {
    console.error('verify-key error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Serve UI if present
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  return res.send('License server running');
});

app.listen(PORT, () => console.log('Server listening on', PORT));
