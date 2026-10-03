import crypto from 'crypto';

const SESSION_TTL = 60 * 60 * 1000; // 1 hora
globalThis.__panelSessions = globalThis.__panelSessions || new Map();

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Método no permitido' });
  }

  const body = req.body || {};
  const { key, email } = body;

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

  const normalizedEmail = (email || allowedEmail).trim().toLowerCase();

  if (!normalizedEmail) {
    return res.status(400).json({
      success: false,
      message: 'Falta email válido'
    });
  }

  const sessionToken = crypto.randomBytes(32).toString('hex');
  const signature = crypto
    .createHmac('sha256', sessionSecret)
    .update(sessionToken)
    .digest('hex');

  globalThis.__panelSessions.set(sessionToken, {
    email: normalizedEmail,
    expiresAt: Date.now() + SESSION_TTL
  });

  const isProd = process.env.NODE_ENV === 'production';

  res.setHeader('Set-Cookie', [
    `panel_session=${sessionToken}.${signature}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`,
    `panel_email=${encodeURIComponent(normalizedEmail)}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`
  ]);

  return res.status(200).json({
    success: true,
    message: 'Autenticación exitosa',
    email: normalizedEmail
  });
}
