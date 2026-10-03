export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const isProd = process.env.NODE_ENV === 'production';

  const cookieHeader = [
    'panel_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax' + (isProd ? '; Secure' : ''),
    'panel_email=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax' + (isProd ? '; Secure' : '')
  ];

  const cookieHeaderRaw = req.headers.cookie || '';
  const match = cookieHeaderRaw.match(/(?:^|;\s*)panel_session=([^;]+)/);
  const token = match ? decodeURIComponent(match[1]).split('.')[0] : null;

  if (token && globalThis.__panelSessions) {
    globalThis.__panelSessions.delete(token);
  }

  res.setHeader('Set-Cookie', cookieHeader);

  return res.status(200).json({
    ok: true,
    message: 'Sesión cerrada correctamente'
  });
}
