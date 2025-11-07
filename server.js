// server.js
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());

const KEY_FILE = './keys.json';

// Load keys từ file JSON
function loadKeys() {
  if (!fs.existsSync(KEY_FILE)) fs.writeFileSync(KEY_FILE, JSON.stringify([]));
  return JSON.parse(fs.readFileSync(KEY_FILE));
}

// Lưu keys
function saveKeys(keys) {
  fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
}

// Tạo key ngẫu nhiên
function generateKey() {
  return 'ZXS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// Tính thời hạn
function getExpiry(duration) {
  const now = new Date();
  switch(duration) {
    case 'day': now.setDate(now.getDate()+1); break;
    case 'week': now.setDate(now.getDate()+7); break;
    case 'month': now.setMonth(now.getMonth()+1); break;
    case 'year': now.setFullYear(now.getFullYear()+1); break;
    default: now.setDate(now.getDate()+1);
  }
  return Math.floor(now.getTime()/1000);
}

// --- API --- //
// Lấy danh sách key
app.get('/api/keys', (req, res) => {
  const keys = loadKeys();
  res.json({ ok: true, keys });
});

// Tạo key mới
app.post('/api/create-key', (req, res) => {
  const { duration, device_limit } = req.body;
  if (!duration || !device_limit) return res.json({ ok:false, message:"Thiếu dữ liệu" });

  const keys = loadKeys();
  const key = {
    key_text: generateKey(),
    created_at: Math.floor(Date.now()/1000),
    expires_at: getExpiry(duration),
    device_limit: parseInt(device_limit),
    devices_used: 0
  };
  keys.push(key);
  saveKeys(keys);
  res.json({ ok:true, key: key.key_text });
});

// Reset/Gia hạn key (+1 ngày)
app.put('/api/reset-key/:key', (req, res) => {
  const { key } = req.params;
  const keys = loadKeys();
  const k = keys.find(x => x.key_text === key);
  if (!k) return res.json({ ok:false, message:"Không tìm thấy key" });
  k.expires_at += 86400; // +1 ngày
  saveKeys(keys);
  res.json({ ok:true, message:"Đã thêm 1 ngày cho key "+key });
});

// Xoá key
app.delete('/api/delete-key/:key', (req, res) => {
  const { key } = req.params;
  let keys = loadKeys();
  keys = keys.filter(x => x.key_text !== key);
  saveKeys(keys);
  res.json({ ok:true, message:"Đã xoá key "+key });
});

// Check key login
app.get('/api/check-key/:key', (req, res) => {
  const { key } = req.params;
  const keys = loadKeys();
  const k = keys.find(x => x.key_text === key);
  if (!k) return res.json({ ok: false, message: "Key không tồn tại" });

  const now = Math.floor(Date.now()/1000);
  if (k.expires_at < now)
    return res.json({ ok: false, message: "Key đã hết hạn" });

  if (k.devices_used >= k.device_limit)
    return res.json({ ok: false, message: "Đã đạt giới hạn thiết bị" });

  res.json({ ok: true, message: "Key hợp lệ" });
});

app.listen(PORT, () => console.log(`Server chạy trên http://localhost:${PORT}`));