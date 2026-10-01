// server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

const app = express();

// Configuraciones de seguridad básicas
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Configuración de CORS si el frontend se aloja en otro dominio
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || null;
if (FRONTEND_ORIGIN) {
  app.use(cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  }));
}

// Credenciales y parámetros (usando variables de entorno por seguridad)
const ALLOWED_EMAIL = (process.env.ALLOWED_EMAIL || 'molinaoksergio@gmail.com').toLowerCase();
const BACKUP_KEY = process.env.BACKUP_KEY || 'admin2026';
const COOKIE_MAX_AGE = 60 * 60 * 1000; // 1 hora de sesión

// Función auxiliar para configurar cookies de sesión seguras
function setAdminCookie(res, email) {
  const secureFlag = (process.env.NODE_ENV === 'production');
  
  // Cookie de sesión (HttpOnly evita que JavaScript en el navegador pueda robarla)
  res.cookie('admin_session', 'true', {
    httpOnly: true,
    sameSite: 'Lax',
    secure: secureFlag,
    maxAge: COOKIE_MAX_AGE,
    path: '/',
  });

  // Cookie auxiliar para el email
  res.cookie('admin_email', String(email || '').toLowerCase(), {
    httpOnly: false,
    secure: secureFlag,
    sameSite: 'Lax',
    maxAge: COOKIE_MAX_AGE,
    path: '/',
  });
}

// -----------------------------------------
// RUTAS DE AUTENTICACIÓN Y API
// -----------------------------------------

// Endpoint de Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Faltan credenciales' });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  
  // Verificación de credenciales
  if (cleanEmail === ALLOWED_EMAIL && password === BACKUP_KEY) {
    setAdminCookie(res, cleanEmail);
    return res.json({ success: true, message: 'Autenticación exitosa' });
  }

  return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
});

// Endpoint para verificar si la sesión sigue activa
app.get('/api/check-session', (req, res) => {
  const isAuthed = req.cookies && req.cookies.admin_session === 'true';
  if (isAuthed) {
    return res.json({ authenticated: true, email: req.cookies.admin_email || '' });
  }
  return res.status(401).json({ authenticated: false });
});

// Endpoint de Logout (limpia las cookies)
app.post('/api/logout', (req, res) => {
  res.clearCookie('admin_session', { path: '/' });
  res.clearCookie('admin_email', { path: '/' });
  return res.json({ success: true, message: 'Sesión cerrada' });
});

// -----------------------------------------
// ARCHIVOS ESTÁTICOS Y PUERTO
// -----------------------------------------

// Servir archivos estáticos del frontend (HTML, CSS, JS públicos)
app.use(express.static(path.join(__dirname)));

// Ruta comodín para manejar el frontend o index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor seguro corriendo en el puerto ${PORT}`);
});
