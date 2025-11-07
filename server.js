import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname)); // để serve index.html

const ADMIN = { username: "admin", password: "123456" };
const DATA_FILE = path.join(__dirname, "keys.json");
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");

const loadKeys = () => JSON.parse(fs.readFileSync(DATA_FILE));
const saveKeys = (k) => fs.writeFileSync(DATA_FILE, JSON.stringify(k, null, 2));

// Đăng nhập admin
app.post("/api/admin-login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN.username && password === ADMIN.password)
    return res.json({ success: true });
  res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
});

// Tạo key
app.post("/api/create-key", (req, res) => {
  const { days, devices } = req.body;
  const keys = loadKeys();
  const key_code = "ZXS-" + Math.random().toString(36).substring(2, 8).toUpperCase();
  const created_at = new Date();
  const expires_at = new Date(Date.now() + days * 86400000);
  const newKey = {
    key_code,
    created_at,
    expires_at,
    allowed_devices: devices,
    is_active: true,
    devices_list: []
  };
  keys.push(newKey);
  saveKeys(keys);
  res.json({ success: true, key: newKey });
});

// Lấy danh sách key
app.get("/api/list-keys", (req, res) => {
  res.json(loadKeys());
});

// Gia hạn key
app.post("/api/extend-key", (req, res) => {
  const { key, days } = req.body;
  const keys = loadKeys();
  const k = keys.find((x) => x.key_code === key);
  if (!k) return res.status(404).json({ success: false });
  k.expires_at = new Date(new Date(k.expires_at).getTime() + days * 86400000);
  saveKeys(keys);
  res.json({ success: true });
});

// Reset key
app.post("/api/reset-key", (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  const k = keys.find((x) => x.key_code === key);
  if (!k) return res.status(404).json({ success: false });
  k.devices_list = [];
  saveKeys(keys);
  res.json({ success: true });
});

// Xoá key
app.post("/api/delete-key", (req, res) => {
  const { key } = req.body;
  let keys = loadKeys();
  keys = keys.filter((x) => x.key_code !== key);
  saveKeys(keys);
  res.json({ success: true });
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
