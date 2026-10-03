import crypto from 'crypto';

globalThis.__panelSessions = globalThis.__panelSessions || new Map();

function safeEqual(a, b) {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');

  if (aBuf.length !== bBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuf, bBuf);
}

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ authorized: false, message: 'Método no permitido' });
  }

  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)panel_session=([^;]+)/);
  const raw = match ? decodeURIComponent(match[1]) : '';

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
