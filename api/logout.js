function readCookie(rawCookie, name) {
  if (!rawCookie) return null;
  const match = rawCookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const cookieHeader = req.headers.cookie || '';
  const raw = readCookie(cookieHeader, 'panel_session');

  if (raw) {
    const token = raw.split('.')[0];
    if (token) {
      globalThis.__panelSessions = globalThis.__panelSessions || new Map();
      globalThis.__panelSessions.delete(token);
    }
  }

  const isProd = process.env.NODE_ENV === 'production';

  res.setHeader('Set-Cookie', [
    `panel_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`,
    `panel_email=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${isProd ? '; Secure' : ''}`
  ]);

  return res.status(200).json({
    ok: true,
    message: 'Sesión cerrada correctamente'
  });
}
