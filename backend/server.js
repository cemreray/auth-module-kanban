
const crypto = require("crypto");
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

// ==========================================
// 1. SUNUCU AYARLARI
// ==========================================

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Yalnizca yerel gelistirme icin
app.use(cors());
app.use(express.json({ limit: "10kb" }));

// ==========================================
// 2. VERITABANI
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
  );

  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ==========================================
// 3. YARDIMCI FONKSIYONLAR
// ==========================================

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function isStrongPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    Buffer.byteLength(password, "utf8") <= 72 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^a-zA-Z0-9]/.test(password)
  );
}

const devResetMode =
  process.env.RESET_DEV_MODE === "1" &&
  process.env.NODE_ENV !== "production";

// ==========================================
// 4. API SAGLIK KONTROLU
// ==========================================

app.get("/api/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "AuthSpace API çalışıyor."
  });
});

// ==========================================
// 5. KAN-6: KULLANICI KAYIT API
// ==========================================

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
    const normalizedEmail = normalizeEmail(email);

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Ad soyad 2-100 karakter olmalıdır."
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Geçerli bir e-posta adresi girin."
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message: "Şifre en az 8 karakter olmalı; büyük harf, küçük harf, sayı ve sembol içermelidir. UTF-8 uzunluğu en fazla 72 bayt olabilir."
      });
    }

    const existingUser = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(normalizedEmail);

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
// 6. KAN-7: KULLANICI GIRIS API
// ==========================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

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

    const normalizedEmail = normalizeEmail(email);

    const user = db.prepare(`
      SELECT id, full_name, email, password_hash
      FROM users
      WHERE email = ?
    `).get(normalizedEmail);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "E-posta veya şifre hatalı."
      });
    }

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
// 7. KAN-8: SIFRE SIFIRLAMA ISTEGI
// POST /api/auth/forgot-password
// ==========================================

app.post("/api/auth/forgot-password", (req, res) => {
  try {
    const { email } = req.body || {};

    if (typeof email !== "string") {
      return res.status(400).json({
        success: false,
        message: "Geçerli bir e-posta adresi girin."
      });
    }

    const normalizedEmail = normalizeEmail(email);

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Geçerli bir e-posta adresi girin."
      });
    }

    const user = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(normalizedEmail);

    const response = {
      success: true,
      message: "Şifre sıfırlama talebi alındı."
    };

    // Kayitli olmayan e-postalar icin de ayni mesaj
    if (!user) {
      return res.status(200).json(response);
    }

    // Guvenli ve rastgele token olustur
    const token = crypto.randomBytes(32).toString("hex");

    // Tokenin kendisi yerine hash degerini sakla
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Token 15 dakika gecerlidir
    const expiresAt = Date.now() + 15 * 60 * 1000;

    const saveToken = db.transaction(() => {
      // Eski sifirlama tokenlarini sil
      db.prepare(`
        DELETE FROM password_reset_tokens
        WHERE user_id = ?
      `).run(user.id);

      db.prepare(`
        INSERT INTO password_reset_tokens
          (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `).run(user.id, tokenHash, expiresAt);
    });

    saveToken();

    // E-posta servisi henuz yok.
    // Token sadece yerel test modunda doner.
    if (devResetMode) {
      response.devResetToken = token;
      response.expiresInMinutes = 15;
    }

    return res.status(200).json(response);

  } catch (error) {
    console.error("Forgot password hatası:", error.message);

    return res.status(500).json({
      success: false,
      message: "Şifre sıfırlama talebi işlenemedi."
    });
  }
});

// ==========================================
// 8. KAN-8: YENI SIFRE BELIRLEME
// POST /api/auth/reset-password
// ==========================================

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};

    if (
      typeof token !== "string" ||
      !/^[a-f0-9]{64}$/.test(token) ||
      typeof newPassword !== "string"
    ) {
      return res.status(400).json({
        success: false,
        message: "Geçersiz sıfırlama isteği."
      });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Yeni şifre en az 8 karakter olmalı; büyük harf, küçük harf, sayı ve sembol içermelidir. UTF-8 uzunluğu en fazla 72 bayt olabilir."
      });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const record = db.prepare(`
      SELECT user_id, expires_at
      FROM password_reset_tokens
      WHERE token_hash = ?
    `).get(tokenHash);

    if (!record || record.expires_at <= Date.now()) {
      return res.status(400).json({
        success: false,
        message: "Token geçersiz veya süresi dolmuş."
      });
    }

    const newHash = await bcrypt.hash(newPassword, 12);

    // Token kullanimi ve sifre guncellemesini
    // tek veritabani islemi olarak gerceklestir.
    const applyReset = db.transaction(() => {
      const deleted = db.prepare(`
        DELETE FROM password_reset_tokens
        WHERE token_hash = ? AND expires_at > ?
      `).run(tokenHash, Date.now());

      if (deleted.changes !== 1) {
        return false;
      }

      const updated = db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(newHash, record.user_id);

      if (updated.changes !== 1) {
        throw new Error("Kullanıcı güncellenemedi.");
      }

      // Kullaniciya ait diger tokenlari da sil
      db.prepare(`
        DELETE FROM password_reset_tokens
        WHERE user_id = ?
      `).run(record.user_id);

      return true;
    });

    if (!applyReset()) {
      return res.status(400).json({
        success: false,
        message: "Token geçersiz veya süresi dolmuş."
      });
    }

    return res.status(200).json({
      success: true,
      message: "Şifre başarıyla güncellendi."
    });

  } catch (error) {
    console.error("Reset password hatası:", error.message);

    return res.status(500).json({
      success: false,
      message: "Şifre güncellenemedi."
    });
  }
});

// ==========================================
// 9. SUNUCUYU BASLAT
// ==========================================

app.listen(PORT, () => {
  console.log(`AuthSpace API: http://localhost:${PORT}`);
  console.log(
    `Sifre sifirlama test modu: ${devResetMode ? "ACIK" : "KAPALI"}`
  );
});
