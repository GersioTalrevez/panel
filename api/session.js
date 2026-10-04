import crypto from 'crypto';

function readCookie(rawCookie, name) {
  if (!rawCookie) return null;
  const match = rawCookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

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

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ authorized: false, message: 'Método no permitido' });
  }

  const cookieHeader = req.headers.cookie || '';
  const raw = readCookie(cookieHeader, 'panel_session');

  if (!raw) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    return res.status(500).json({ authorized: false, message: 'Configuración del servidor incompleta' });
  }

  const [token, signature] = raw.split('.');
  if (!token || !signature) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  const expectedSignature = crypto
    .createHmac('sha256', sessionSecret)
    .update(token)
    .digest('hex');

  if (!safeEqual(expectedSignature, signature)) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  globalThis.__panelSessions = globalThis.__panelSessions || new Map();
  const session = globalThis.__panelSessions.get(token);

  if (!session) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  if (session.expiresAt < Date.now()) {
    globalThis.__panelSessions.delete(token);
    return res.status(401).json({ authorized: false, message: 'Sesión expirada' });
  }

  return res.status(200).json({
    authorized: true,
    email: session.email
  });
}
