// 🚀 License Manager Server (Render version)
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import path from "path";

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(bodyParser.json());

const __dirname = path.resolve();
const DATA_FILE = path.join(__dirname, "keys.json");

// 🔐 Admin account
const ADMIN = { username: "zxs", password: "12" };

// 🗝 Load keys
function loadKeys() {
  if (!fs.existsSync(DATA_FILE)) return [];
  return JSON.parse(fs.readFileSync(DATA_FILE));
}
function saveKeys(keys) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2));
}

// ✅ Login admin
app.post("/api/admin-login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN.username && password === ADMIN.password)
    return res.json({ success: true, message: "Đăng nhập thành công" });
  return res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
});

// ✅ Tạo key
app.post("/api/create-key", (req, res) => {
  const { days, devices } = req.body;
  const keys = loadKeys();
  const key_code = Math.random().toString(36).substring(2, 10).toUpperCase();
  const created_at = new Date();
  const expires_at = new Date(Date.now() + days * 86400000);
  const newKey = { key_code, created_at, expires_at, allowed_devices: devices, is_active: true, devices_list: [] };
  keys.push(newKey);
  saveKeys(keys);
  res.json({ success: true, key: newKey });
});

// ✅ Lấy danh sách key
app.get("/api/list-keys", (req, res) => {
  const keys = loadKeys();
  res.json(keys);
});

// ✅ Gia hạn key
app.post("/api/extend-key", (req, res) => {
  const { key, days } = req.body;
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days * 86400000);
  saveKeys(keys);
  res.json({ success: true });
});

// ✅ Reset key (xoá danh sách thiết bị)
app.post("/api/reset-key", (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.devices_list = [];
  saveKeys(keys);
  res.json({ success: true });
});

// ✅ Xoá key
app.post("/api/delete-key", (req, res) => {
  const { key } = req.body;
  let keys = loadKeys();
  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);
  res.json({ success: true });
});

// ✅ Trang chủ
app.get("/", (req, res) => {
  res.send("✅ License Server đang chạy...");
});

app.listen(PORT, () => console.log(`✅ Server đang chạy tại cổng ${PORT}`));
