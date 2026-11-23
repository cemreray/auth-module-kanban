
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

// ==========================================
// 1. SUNUCU AYARLARI
// ==========================================

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json({ limit: "10kb" }));

// ==========================================
// 2. VERITABANI BAGLANTISI
// ==========================================

const db = new Database(path.join(__dirname, "users.db"));

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// ==========================================
// 3. API SAGLIK KONTROLU
// ==========================================

app.get("/api/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "AuthSpace API çalışıyor."
  });
});

// ==========================================
// 4. KAN-6: KULLANICI KAYIT API
// POST /api/auth/register
// ==========================================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};

    // Zorunlu alan kontrolü
    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        success: false,
        message: "Tüm alanları doğru biçimde doldurun."
      });
    }

    const name = fullName.trim();
    const normalizedEmail = email.trim().toLowerCase();

    // Ad soyad kontrolü
    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Ad soyad 2-100 karakter olmalıdır."
      });
    }

    // E-posta kontrolü
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (
      normalizedEmail.length > 254 ||
      !emailRegex.test(normalizedEmail)
    ) {
      return res.status(400).json({
        success: false,
        message: "Geçerli bir e-posta adresi girin."
      });
    }

    // Şifre güvenliği kontrolü
    const validPassword =
      password.length >= 8 &&
      password.length <= 72 &&
      /[a-z]/.test(password) &&
      /[A-Z]/.test(password) &&
      /[0-9]/.test(password) &&
      /[^a-zA-Z0-9]/.test(password);

    if (!validPassword) {
      return res.status(400).json({
        success: false,
        message:
          "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, sayı ve sembol içermelidir."
      });
    }

    // Aynı e-posta ile kayıt var mı?
    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(normalizedEmail);

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Bu e-posta adresi zaten kayıtlı."
      });
    }

    // Şifreyi hashle
    const passwordHash = await bcrypt.hash(password, 12);

    // Kullanıcıyı veritabanına kaydet
    const result = db.prepare(`
      INSERT INTO users (full_name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name, normalizedEmail, passwordHash);

    return res.status(201).json({
      success: true,
      message: "Kullanıcı başarıyla kaydedildi.",
      user: {
        id: String(result.lastInsertRowid),
        fullName: name,
        email: normalizedEmail
      }
    });

  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        success: false,
        message: "Bu e-posta adresi zaten kayıtlı."
      });
    }

    console.error("Register API hatası:", error.message);

    return res.status(500).json({
      success: false,
      message: "Kayıt işlemi gerçekleştirilemedi."
    });
  }
});

// ==========================================
// 5. KAN-7: KULLANICI GIRIS (LOGIN) API
// POST /api/auth/login
// ==========================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // E-posta ve şifre kontrolü
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "E-posta ve şifre alanları zorunludur."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Kullanıcıyı veritabanında ara
    const user = db.prepare(`
      SELECT id, full_name, email, password_hash
      FROM users
      WHERE email = ?
    `).get(normalizedEmail);

    // Kullanıcı bulunamadıysa
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "E-posta veya şifre hatalı."
      });
    }

    // Şifreyi bcrypt ile karşılaştır
    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "E-posta veya şifre hatalı."
      });
    }

    // Başarılı giriş
    return res.status(200).json({
      success: true,
      message: "Giriş başarılı.",
      user: {
        id: String(user.id),
        fullName: user.full_name,
        email: user.email
      }
    });

  } catch (error) {
    console.error("Login API hatası:", error.message);

    return res.status(500).json({
      success: false,
      message: "Giriş işlemi gerçekleştirilemedi."
    });
  }
});

// ==========================================
// 6. SUNUCUYU BASLAT
// ==========================================

app.listen(PORT, () => {
  console.log(`AuthSpace API: http://localhost:${PORT}`);
});
