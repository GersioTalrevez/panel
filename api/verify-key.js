// api/verify-key.js
export default function handler(req, res) {
  // Solo permitimos método POST por seguridad
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Método no permitido' });
  }

  const { key } = req.body;
  const backupKey = process.env.BACKUP_KEY || 'admin2026';
  const allowedEmail = process.env.ALLOWED_EMAIL || 'molinaoksergio@gmail.com';

  if (!key) {
    return res.status(400).json({ success: false, message: 'Falta la clave' });
  }

  // Verificamos si la clave ingresada coincide con la de respaldo
  if (key === backupKey) {
    const secureFlag = (process.env.NODE_ENV === 'production');

    // Seteamos las cookies de sesión del lado del servidor
    res.setHeader('Set-Cookie', [
      `admin_session=true; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax${secureFlag ? '; Secure' : ''}`,
      `admin_email=${encodeURIComponent(allowedEmail)}; Path=/; Max-Age=3600; SameSite=Lax${secureFlag ? '; Secure' : ''}`
    ]);

    return res.status(200).json({ success: true, message: 'Autenticación exitosa' });
  }

  return res.status(401).json({ success: false, message: 'Clave incorrecta' });
}
