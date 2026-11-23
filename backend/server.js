
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3000;

// Geliştirme ortamı için
app.use(cors());
app.use(express.json({ limit: "10kb" }));

// Veritabanını oluştur
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

// API sağlık kontrolü
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "AuthSpace API çalışıyor."
  });
});

// KAN-6: Kullanıcı kayıt API
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};

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

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Ad soyad 2-100 karakter olmalıdır."
      });
    }

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
        message: "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, sayı ve sembol içermelidir."
      });
    }

    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(normalizedEmail);

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Bu e-posta adresi zaten kayıtlı."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (full_name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name, normalizedEmail, passwordHash);

    return res.status(201).json({
      success: true,
      message: "Kullanıcı başarıyla kaydedildi.",
      user: {
        id: result.lastInsertRowid.toString(),
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

    console.error("Kayıt sırasında sunucu hatası:", error.message);

    return res.status(500).json({
      success: false,
      message: "Kayıt işlemi gerçekleştirilemedi."
    });
  }
});

app.listen(PORT, () => {
  console.log(`AuthSpace API: http://localhost:${PORT}`);
});
