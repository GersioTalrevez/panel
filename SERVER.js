require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_TTL = 60 * 60 * 1000; // 1 hora
const sessionStore = new Map();

// ==========================================
// Funciones de utilidad de sesión
// ==========================================

function safeEqual(a, b) {
  try {
    const aBuf = Buffer.from(a, 'hex');
    const bBuf = Buffer.from(b, 'hex');

    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  } catch (_) {
    return false;
  }
}

function readCookie(rawCookie, name) {
  if (!rawCookie) return null;
  const match = rawCookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function signSessionToken(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) return null;
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const signature = signSessionToken(token);

  if (!signature) return null;

  sessionStore.set(token, {
    email: String(email).trim().toLowerCase(),
    expiresAt: Date.now() + SESSION_TTL
  });

  return `${token}.${signature}`;
}

function verifySessionCookie(rawValue) {
  if (!rawValue || typeof rawValue !== 'string') return null;

  const [token, signature] = rawValue.split('.');
  if (!token || !signature) return null;

  const expectedSignature = signSessionToken(token);
  if (!expectedSignature) return null;

  if (!safeEqual(expectedSignature, signature)) {
    return null;
  }

  const session = sessionStore.get(token);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    sessionStore.delete(token);
    return null;
  }

  return session;
}

function requireAuth(req, res, next) {
  const rawCookie = req.headers.cookie || '';
  const cookieValue = readCookie(rawCookie, 'panel_session');

  const session = verifySessionCookie(cookieValue);

  if (!session) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  req.session = session;
  next();
}

// ==========================================
// Configuración de seguridad
// ==========================================

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdn.tailwindcss.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:', 'https:', 'blob:'],
      connectSrc: ["'self'", 'https://*.supabase.co'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : undefined
    }
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname)));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ==========================================
// Rate Limiter
// ==========================================

const loginRateLimiter = (() => {
  const attempts = new Map();

  return (req, res, next) => {
    const key = req.ip || 'global';
    const now = Date.now();
    const windowMs = 60 * 1000;
    const maxAttempts = 8;

    const entries = attempts.get(key) || [];
    const recent = entries.filter(ts => now - ts < windowMs);

    if (recent.length >= maxAttempts) {
      return res.status(429).json({ success: false, message: 'Demasiados intentos. Intenta más tarde.' });
    }

    recent.push(now);
    attempts.set(key, recent);

    next();
  };
})();

// ==========================================
// Rutas de autenticación
// ==========================================

app.post('/api/verify-key', loginRateLimiter, (req, res) => {
  const { key, email } = req.body || {};

  const backupKey = process.env.BACKUP_KEY;
  const allowedEmail = (process.env.ALLOWED_EMAIL || '').trim().toLowerCase();
  const sessionSecret = process.env.SESSION_SECRET;

  if (!backupKey || !allowedEmail || !sessionSecret) {
    return res.status(500).json({
      success: false,
      message: 'Configuración del servidor incompleta'
    });
  }

  if (typeof key !== 'string' || !key.trim()) {
    return res.status(400).json({
      success: false,
      message: 'Falta la clave'
    });
  }

  if (key !== backupKey) {
    return res.status(401).json({
      success: false,
      message: 'Clave incorrecta'
    });
  }

  const normalizedEmail = ((email || allowedEmail) + '').trim().toLowerCase();
  const sessionValue = createSession(normalizedEmail);

  if (!sessionValue) {
    return res.status(500).json({
      success: false,
      message: 'No se pudo crear la sesión'
    });
  }

  const isProd = process.env.NODE_ENV === 'production';

  res.setHeader('Set-Cookie', [
    `panel_session=${sessionValue}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`,
    `panel_email=${encodeURIComponent(normalizedEmail)}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`
  ]);

  return res.status(200).json({
    success: true,
    message: 'Autenticación exitosa',
    email: normalizedEmail
  });
});

app.get('/api/session', (req, res) => {
  const rawCookie = req.headers.cookie || '';
  const cookieValue = readCookie(rawCookie, 'panel_session');
  const session = verifySessionCookie(cookieValue);

  if (!session) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  return res.status(200).json({
    authorized: true,
    email: session.email
  });
});

app.post('/api/logout', (req, res) => {
  const rawCookie = req.headers.cookie || '';
  const cookieValue = readCookie(rawCookie, 'panel_session');
  const token = cookieValue ? cookieValue.split('.')[0] : null;

  if (token) {
    sessionStore.delete(token);
  }

  const isProd = process.env.NODE_ENV === 'production';

  res.setHeader('Set-Cookie', [
    `panel_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`,
    `panel_email=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`
  ]);

  return res.status(200).json({ ok: true, message: 'Sesión cerrada correctamente' });
});

// ==========================================
// Manejo de errores
// ==========================================

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==========================================
// Iniciar servidor
// ==========================================

const server = app.listen(PORT, () => {
  console.log(`Servidor de panel administrativo corriendo en puerto ${PORT}`);
  console.log(`Origen CORS: ${FRONTEND_ORIGIN}`);
  console.log(`Modo: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
