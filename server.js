const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = 'ZXS_LICENSE_SECRET'; // đổi lại nếu muốn bảo mật hơn

app.use(cors());
app.use(bodyParser.json());

// ====== Tệp dữ liệu lưu key ======
const KEY_FILE = './keys.json';
if (!fs.existsSync(KEY_FILE)) fs.writeFileSync(KEY_FILE, '[]');

// ====== Tài khoản admin mặc định ======
const ADMIN_USER = {
  username: 'ZxsVN-ad',
  passwordHash: bcrypt.hashSync('123321', 10) // mật khẩu: 123321
};

// ====== Middleware kiểm tra JWT ======
function requireAdmin(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Thiếu token' });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: 'Token không hợp lệ' });
    req.admin = decoded;
    next();
  });
}

// ====== Đăng nhập admin ======
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body;

  if (username !== ADMIN_USER.username)
    return res.status(401).json({ success: false, message: 'Sai tài khoản' });

  const match = await bcrypt.compare(password, ADMIN_USER.passwordHash);
  if (!match)
    return res.status(401).json({ success: false, message: 'Sai mật khẩu' });

  const token = jwt.sign({ username }, SECRET, { expiresIn: '2h' });
  res.json({ success: true, token });
});

// ====== Load danh sách key ======
app.get('/api/list-keys', requireAdmin, (req, res) => {
  const keys = JSON.parse(fs.readFileSync(KEY_FILE));
  res.json({ success: true, keys });
});

// ====== Tạo key ======
app.post('/api/create-key', requireAdmin, (req, res) => {
  const { days, devices } = req.body;
  if (!days || !devices)
    return res.status(400).json({ success: false, message: 'Thiếu dữ liệu' });

  const key = generateKey();
  const now = Date.now();
  const newKey = {
    key,
    devices,
    created: now,
    expires: now + days * 24 * 60 * 60 * 1000,
    activeDevices: []
  };

  const keys = JSON.parse(fs.readFileSync(KEY_FILE));
  keys.push(newKey);
  fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));

  res.json({ success: true, key });
});

// ====== Gia hạn key ======
app.post('/api/extend-key', requireAdmin, (req, res) => {
  const { key, days } = req.body;
  let keys = JSON.parse(fs.readFileSync(KEY_FILE));

  const index = keys.findIndex(k => k.key === key);
  if (index === -1)
    return res.json({ success: false, message: 'Không tìm thấy key' });

  keys[index].expires += days * 24 * 60 * 60 * 1000;
  fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));

  res.json({ success: true });
});

// ====== Reset key (xoá danh sách thiết bị) ======
app.post('/api/reset-key', requireAdmin, (req, res) => {
  const { key } = req.body;
  let keys = JSON.parse(fs.readFileSync(KEY_FILE));

  const index = keys.findIndex(k => k.key === key);
  if (index === -1)
    return res.json({ success: false, message: 'Không tìm thấy key' });

  keys[index].activeDevices = [];
  fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));

  res.json({ success: true });
});

// ====== Xoá key ======
app.post('/api/delete-key', requireAdmin, (req, res) => {
  const { key } = req.body;
  let keys = JSON.parse(fs.readFileSync(KEY_FILE));
  keys = keys.filter(k => k.key !== key);
  fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));

  res.json({ success: true });
});

// ====== Verify key cho client ======
app.post('/api/verify-key', (req, res) => {
  const { key, device_id } = req.body;
  if (!key || !device_id)
    return res.json({ success: false, message: 'Thiếu dữ liệu' });

  const keys = JSON.parse(fs.readFileSync(KEY_FILE));
  const found = keys.find(k => k.key === key);

  if (!found) return res.json({ success: false, message: 'Key không tồn tại' });
  if (Date.now() > found.expires)
    return res.json({ success: false, message: 'Key hết hạn' });

  if (!found.activeDevices.includes(device_id)) {
    if (found.activeDevices.length >= found.devices)
      return res.json({ success: false, message: 'Vượt quá số thiết bị' });
    found.activeDevices.push(device_id);
    fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
  }

  res.json({ success: true, message: 'Key hợp lệ' });
});

// ====== Tạo key ngẫu nhiên ======
function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = 'KEY-';
  for (let i = 0; i < 8; i++) key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

app.listen(PORT, () => console.log(`✅ Server đang chạy tại cổng ${PORT}`));
