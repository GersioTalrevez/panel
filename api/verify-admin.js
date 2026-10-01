// api/verify-admin.js
export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email } = req.body || {};
  if (!email) return res.status(400).json({ authorized: false, error: 'Email required' });

  const ALLOWED_EMAIL = (process.env.ALLOWED_EMAIL || '').toLowerCase();
  const normalized = String(email).trim().toLowerCase();

  if (normalized === ALLOWED_EMAIL) {
    const secureFlag = process.env.NODE_ENV === 'production';
    const cookieOpts = [
      `admin_session=true`,
      `Path=/`,
      `Max-Age=${60 * 60}`,
      `SameSite=Lax`,
      secureFlag ? `Secure` : ''
    ].filter(Boolean).join('; ');

    const emailCookie = [
      `admin_email=${encodeURIComponent(normalized)}`,
      `Path=/`,
      `Max-Age=${60 * 60}`,
      `SameSite=Lax`,
      secureFlag ? `Secure` : ''
    ].filter(Boolean).join('; ');

    res.setHeader('Set-Cookie', [cookieOpts, emailCookie]);
    return res.status(200).json({ authorized: true, email: normalized });
  }

  return res.status(403).json({ authorized: false });
}
