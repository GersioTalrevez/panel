// api/verify-key.js
export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { key } = req.body || {};
  if (!key) return res.status(400).json({ authorized: false, error: 'Key required' });

  const BACKUP_KEY = process.env.BACKUP_KEY || '';
  const ALLOWED_EMAIL = (process.env.ALLOWED_EMAIL || '').toLowerCase();

  if (String(key) === BACKUP_KEY) {
    const secureFlag = process.env.NODE_ENV === 'production';
    // admin_session cookie (HttpOnly)
    const cookieOpts = [
      `admin_session=true`,
      `Path=/`,
      `Max-Age=${60 * 60}`, // 1 hora
      `SameSite=Lax`,
      secureFlag ? `Secure` : ''
    ].filter(Boolean).join('; ');

    // admin_email cookie (no HttpOnly, opcional: para mostrar email en frontend)
    const emailCookie = [
      `admin_email=${encodeURIComponent(ALLOWED_EMAIL)}`,
      `Path=/`,
      `Max-Age=${60 * 60}`,
      `SameSite=Lax`,
      secureFlag ? `Secure` : ''
    ].filter(Boolean).join('; ');

    res.setHeader('Set-Cookie', [cookieOpts, emailCookie]);
    return res.status(200).json({ authorized: true, email: ALLOWED_EMAIL });
  }

  return res.status(403).json({ authorized: false });
}
