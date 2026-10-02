// server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Si necesitas llamadas cross-origin (frontend en distinto dominio), ajusta ORIGIN:
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || null;
if (FRONTEND_ORIGIN) {
  app.use(cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  }));
}

// Configuración (preferible desde variables de entorno)
const ALLOWED_EMAIL = (process.env.ALLOWED_EMAIL || 'molinaoksergio@gmail.com').toLowerCase();
const BACKUP_KEY = process.env.BACKUP_KEY || 'admin2026';
const COOKIE_MAX_AGE = 60 * 60 * 1000; // 1 hora

function setAdminCookie(res, email) {
  const secureFlag = (process.env.NODE_ENV === 'production');
  res.cookie('admin_session', 'true', {
    httpOnly: true,
    sameSite: 'Lax',
    secure: secureFlag,
    maxAge: COOKIE_MAX_AGE,
    path: '/',
  });
  // email cookie NO es HttpOnly para que el frontend (si lo necesita) lo lea; si no quieres exponerlo, pon httpOnly: true
  res.cookie('admin_email', String(email || '').toLowerCase(), {
    httpOnly: false,
