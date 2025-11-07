const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const session = require("express-session");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ===== Cấu hình session (đăng nhập admin) =====
app.use(session({
  secret: "super_secret_key_license_manager",
  resave: false,
  saveUninitialized: true
}));

// ===== Bộ nhớ lưu key tạm (hoặc thay bằng database sau) =====
let keys = [];

// ===== Hàm tạo key ngẫu nhiên =====
function generateKey() {
  const prefix = "ZXS";
  const rand1 = Math.random().toString(36).substring(2, 6).toUpperCase();
  const rand2 = Math.random().toString(36).substring(2, 6).toUpperCase();
  const rand3 = Math.random().toString(36).substring(2, 4).toUpperCase();
  return `${prefix}-${rand1}-${rand2}-${rand3}`;
}

// ===== Đăng nhập admin =====
app.post("/api/admin-login", (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "123456") {
    req.session.loggedIn = true;
    return res.json({ success: true });
  }
  res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu" });
});

// ===== Kiểm tra đã login chưa =====
function requireLogin(req, res, next) {
  if (req.session.loggedIn) return next();
  res.status(403).json({ error: "Chưa đăng nhập" });
}

// ===== API: Tạo key =====
app.post("/api/create-key", requireLogin, (req, res) => {
  const { days, devices } = req.body;
  const newKey = generateKey();
  const now = new Date();
  const expires = new Date(now);
  expires.setDate(expires.getDate() + (days || 30));

  const keyData = {
    key_code: newKey,
    created_at: now,
    expires_at: expires,
    allowed_devices: devices || 3,
    used_devices: [],
    is_active: true
  };

  keys.push(keyData);
  console.log("✅ Key created:", newKey);
  res.json({ success: true, key: newKey });
});

// ===== API: Danh sách key =====
app.get("/api/list-keys", requireLogin, (req, res) => {
  res.json(keys);
});

// ===== API: Xóa key =====
app.post("/api/delete-key", requireLogin, (req, res) => {
  const { key } = req.body;
  keys = keys.filter(k => k.key_code !== key);
  res.json({ success: true });
});

// ===== API: Reset key =====
app.post("/api/reset-key", requireLogin, (req, res) => {
  const { key } = req.body;
  const k = keys.find(x => x.key_code === key);
  if (k) k.used_devices = [];
  res.json({ success: true });
});

// ===== API: Gia hạn =====
app.post("/api/extend-key", requireLogin, (req, res) => {
  const { key, days } = req.body;
  const k = keys.find(x => x.key_code === key);
  if (k) {
    k.expires_at.setDate(k.expires_at.getDate() + (days || 7));
  }
  res.json({ success: true });
});

// ===== API: Verify key (WinForm gọi) =====
app.post("/api/verify-key", (req, res) => {
  const { key, hwid } = req.body;
  const k = keys.find(x => x.key_code === key);
  if (!k) return res.status(404).json({ valid: false, message: "Key không tồn tại" });

  const now = new Date();
  if (now > k.expires_at) return res.status(403).json({ valid: false, message: "Key đã hết hạn" });

  if (!k.used_devices.includes(hwid)) {
    if (k.used_devices.length >= k.allowed_devices)
      return res.status(403).json({ valid: false, message: "Key đã đạt giới hạn thiết bị" });
    k.used_devices.push(hwid);
  }

  res.json({ valid: true, message: "Key hợp lệ" });
});

// ===== Khởi động server =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server đang chạy trên cổng ${PORT}`));
