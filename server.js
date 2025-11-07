const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// SQLite database
const db = new sqlite3.Database('./licenses.db');
db.run(`
CREATE TABLE IF NOT EXISTS license_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_code TEXT,
  created_at TEXT,
  expires_at TEXT,
  is_active INTEGER,
  allowed_devices INTEGER DEFAULT 1,
  used_devices TEXT DEFAULT '[]'
)
`);

// Helper: Tạo key ngẫu nhiên
function generateKey() {
  const prefix = "ZXS";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const parts = Array.from({ length: 3 }, () =>
    Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join("")
  );
  return `${prefix}-${parts.join('-')}`;
}

// ✅ Check key (dành cho Windows Form)
app.post('/api/check-key', (req, res) => {
  const { key, machineId } = req.body;
  db.get(`SELECT * FROM license_keys WHERE key_code = ?`, [key], (err, row) => {
    if (err) return res.status(500).send(err.message);
    if (!row) return res.json({ valid: false, reason: 'Key không tồn tại' });

    const now = new Date();
    if (!row.is_active) return res.json({ valid: false, reason: 'Key bị vô hiệu hóa' });
    if (new Date(row.expires_at) < now) return res.json({ valid: false, reason: 'Key hết hạn' });

    let used = JSON.parse(row.used_devices || "[]");
    if (!used.includes(machineId)) {
      if (used.length >= row.allowed_devices)
        return res.json({ valid: false, reason: 'Vượt giới hạn số máy đăng nhập' });
      used.push(machineId);
      db.run(`UPDATE license_keys SET used_devices=? WHERE key_code=?`, [JSON.stringify(used), key]);
    }

    res.json({ valid: true, expires_at: row.expires_at });
  });
});

// 🆕 Tạo key mới
app.post('/api/create-key', (req, res) => {
  const { days, devices } = req.body;
  const key = generateKey();
  const now = new Date();
  const expires = new Date(now.getTime() + days * 86400000);
  db.run(`INSERT INTO license_keys (key_code, created_at, expires_at, is_active, allowed_devices)
          VALUES (?, ?, ?, 1, ?)`,
    [key, now.toISOString(), expires.toISOString(), devices || 1],
    err => {
      if (err) return res.status(500).send(err.message);
      res.json({ key, expires: expires.toISOString() });
    });
});

// 📋 Danh sách key
app.get('/api/list-keys', (req, res) => {
  db.all(`SELECT * FROM license_keys`, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// 🔁 Reset key (xoá danh sách thiết bị)
app.post('/api/reset-key', (req, res) => {
  const { key } = req.body;
  db.run(`UPDATE license_keys SET used_devices='[]' WHERE key_code=?`, [key], err => {
    if (err) return res.status(500).send(err.message);
    res.json({ message: "Đã reset key" });
  });
});

// ⏫ Gia hạn key
app.post('/api/extend-key', (req, res) => {
  const { key, days } = req.body;
  db.get(`SELECT * FROM license_keys WHERE key_code = ?`, [key], (err, row) => {
    if (!row) return res.status(404).send("Key không tồn tại");
    const newDate = new Date(row.expires_at);
    newDate.setDate(newDate.getDate() + days);
    db.run(`UPDATE license_keys SET expires_at = ? WHERE key_code = ?`, [newDate.toISOString(), key]);
    res.json({ message: "Gia hạn thành công", new_expires: newDate.toISOString() });
  });
});

// ❌ Xoá key
app.post('/api/delete-key', (req, res) => {
  const { key } = req.body;
  db.run(`DELETE FROM license_keys WHERE key_code = ?`, [key]);
  res.json({ message: "Đã xoá key" });
});

// 🚪 Admin login
app.post('/api/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "123456")
    return res.json({ success: true });
  res.status(401).json({ success: false });
});

// Server khởi chạy
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Server chạy tại http://localhost:${PORT}`)
);
