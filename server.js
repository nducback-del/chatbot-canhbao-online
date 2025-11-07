const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ==== Cấu hình session cho login admin ====
app.use(session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 ngày
}));

// ==== Đường dẫn file key.json ====
const DATA_FILE = path.join(__dirname, "keys.json");
let keys = [];

function loadKeys() {
  if (fs.existsSync(DATA_FILE)) {
    keys = JSON.parse(fs.readFileSync(DATA_FILE));
  }
}
function saveKeys() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2));
}
loadKeys();

// ==== Tài khoản admin ====
const ADMIN_USER = "zxs";
const ADMIN_PASS = "1";

// ==== Middleware bảo vệ trang admin ====
function checkAuth(req, res, next) {
  if (req.session.loggedIn) next();
  else res.redirect("/login.html");
}

// ==== Phục vụ file HTML (trang admin + login) ====
app.use(express.static(path.join(__dirname, "public")));

// ==== Trang chính quản lý key ====
app.get("/", checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ==== Đăng nhập admin ====
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.loggedIn = true;
    res.json({ success: true });
  } else {
    res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu!" });
  }
});

// ==== Đăng xuất ====
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ==== API: Danh sách key ====
app.get("/api/list-keys", (req, res) => {
  if (!req.session.loggedIn) return res.status(403).json({ error: "Chưa đăng nhập" });
  res.json(keys);
});

// ==== API: Tạo key ====
app.post("/api/create-key", (req, res) => {
  if (!req.session.loggedIn) return res.status(403).json({ error: "Chưa đăng nhập" });
  const { days } = req.body;
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const part = () => Array.from({ length: 4 }, () => letters[Math.floor(Math.random() * letters.length)]).join("");
  const newKey = `ZXS-${part()}-${part()}-${part()}`;
  const created_at = new Date();
  const expires_at = new Date(created_at.getTime() + days * 24 * 60 * 60 * 1000);
  const keyObj = { key_code: newKey, created_at, expires_at, allowed_devices: 1, devices: [] };
  keys.push(keyObj);
  saveKeys();
  res.json({ success: true, key: keyObj });
});

// ==== API: Xóa key ====
app.post("/api/delete-key", (req, res) => {
  if (!req.session.loggedIn) return res.status(403).json({ error: "Chưa đăng nhập" });
  const { key } = req.body;
  keys = keys.filter(k => k.key_code !== key);
  saveKeys();
  res.json({ success: true });
});

// ==== API: Reset key ====
app.post("/api/reset-key", (req, res) => {
  if (!req.session.loggedIn) return res.status(403).json({ error: "Chưa đăng nhập" });
  const { key } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false, message: "Không tìm thấy key" });
  found.devices = [];
  saveKeys();
  res.json({ success: true });
});

// ==== API: Gia hạn key ====
app.post("/api/extend-key", (req, res) => {
  if (!req.session.loggedIn) return res.status(403).json({ error: "Chưa đăng nhập" });
  const { key, days } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false, message: "Không tìm thấy key" });
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days * 24 * 60 * 60 * 1000);
  saveKeys();
  res.json({ success: true });
});

// ==== API: Dành cho WinForm login ====
app.post("/api/verify-key", (req, res) => {
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

// ==== Khởi động server ====
app.listen(PORT, () => console.log(`✅ Server đang chạy tại cổng ${PORT}`));
