const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// ======= Load / Lưu file key.json =======
let keys = [];
const DATA_FILE = './keys.json';

function loadKeys() {
  if (fs.existsSync(DATA_FILE)) {
    keys = JSON.parse(fs.readFileSync(DATA_FILE));
  }
}
function saveKeys() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2));
}
loadKeys();

// ======= Random key generator =======
function generateKey() {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const part = () => Array.from({ length: 4 }, () => letters[Math.floor(Math.random() * letters.length)]).join('');
  return `ZXS-${part()}-${part()}-${part()}`;
}

// ======= API: Danh sách key =======
app.get('/api/list-keys', (req, res) => {
  res.json(keys);
});

// ======= API: Tạo key mới =======
app.post('/api/create-key', (req, res) => {
  const { days } = req.body;
  const newKey = generateKey();
  const created_at = new Date();
  const expires_at = new Date(created_at.getTime() + days * 24 * 60 * 60 * 1000);
  const keyObj = {
    key_code: newKey,
    created_at,
    expires_at,
    allowed_devices: 1,
    devices: []
  };
  keys.push(keyObj);
  saveKeys();
  res.json({ success: true, key: keyObj });
});

// ======= API: Xóa key =======
app.post('/api/delete-key', (req, res) => {
  const { key } = req.body;
  keys = keys.filter(k => k.key_code !== key);
  saveKeys();
  res.json({ success: true });
});

// ======= API: Reset key =======
app.post('/api/reset-key', (req, res) => {
  const { key } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false, message: "Không tìm thấy key" });
  found.devices = [];
  saveKeys();
  res.json({ success: true });
});

// ======= API: Gia hạn thêm key =======
app.post('/api/extend-key', (req, res) => {
  const { key, days } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false, message: "Không tìm thấy key" });
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days * 24 * 60 * 60 * 1000);
  saveKeys();
  res.json({ success: true });
});

// ======= API: Kiểm tra key cho WinForm =======
app.post('/api/verify-key', (req, res) => {
  const { key, device_id } = req.body;
  const found = keys.find(k => k.key_code === key);

  if (!found) return res.json({ success: false, message: "Key không tồn tại" });
  if (new Date(found.expires_at) < new Date())
    return res.json({ success: false, message: "Key đã hết hạn" });

  if (!found.devices) found.devices = [];

  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) {
      return res.json({ success: false, message: "Key đã vượt số thiết bị cho phép" });
    }
    found.devices.push(device_id);
  }

  saveKeys();
  return res.json({ success: true });
});

// ======= Khởi động server =======
app.listen(PORT, () => console.log(`✅ Server đang chạy tại cổng ${PORT}`));
