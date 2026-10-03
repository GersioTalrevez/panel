const crypto = require('crypto');

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const { email } = req.body || {};
  const allowedEmail = (process.env.ALLOWED_EMAIL || '').trim().toLowerCase();
  const sessionSecret = process.env.SESSION_SECRET;

  if (!allowedEmail || !sessionSecret) {
    return res.status(500).json({ authorized: false, error: 'Configuración del servidor incompleta' });
  }

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ authorized: false, error: 'Email requerido' });
  }

  const normalized = email.trim().toLowerCase();

  if (normalized !== allowedEmail) {
    return res.status(403).json({ authorized: false, error: 'No autorizado' });
  }

  const sessionToken = crypto.randomBytes(32).toString('hex');
  const signature = crypto
    .createHmac('sha256', sessionSecret)
    .update(sessionToken)
    .digest('hex');

  globalThis.__panelSessions = globalThis.__panelSessions || new Map();
  globalThis.__panelSessions.set(sessionToken, {
    email: normalized,
    expiresAt: Date.now() + 60 * 60 * 1000
  });

  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', [
    `panel_session=${sessionToken}.${signature}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`
  ]);

  return res.status(200).json({ authorized: true, email: normalized });
}
