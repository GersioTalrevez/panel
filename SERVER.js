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

