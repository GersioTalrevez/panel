const crypto = require('crypto');

function verifySession(rawValue) {
  if (!rawValue || typeof rawValue !== 'string') return null;

  const [token, sig] = rawValue.split('.');
  if (!token || !sig) return null;

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) return null;

  const expectedSig = crypto
    .createHmac('sha256', sessionSecret)
    .update(token)
    .digest('hex');

  const safeCompare = (a, b) => {
    const aBuf = Buffer.from(a, 'hex');
    const bBuf = Buffer.from(b, 'hex');
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  };

  if (!safeCompare(expectedSig, sig)) {
    return null;
  }

  globalThis.__panelSessions = globalThis.__panelSessions || new Map();
  const session = globalThis.__panelSessions.get(token);

  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    globalThis.__panelSessions.delete(token);
    return null;
  }

  return session;
}

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ authorized: false, message: 'Método no permitido' });
  }

  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)panel_session=([^;]+)/);

  const cookieValue = match ? decodeURIComponent(match[1]) : '';

  const session = verifySession(cookieValue);

  if (!session) {
    return res.status(401).json({
      authorized: false,
      message: 'No autorizado'
    });
  }

  return res.status(200).json({
    authorized: true,
    email: session.email
  });
}
