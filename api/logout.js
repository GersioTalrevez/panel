// api/logout.js
export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  // Expirar las cookies para cerrar la sesión de forma segura
  res.setHeader('Set-Cookie', [
    'admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax',
    'admin_email=; Path=/; Max-Age=0; SameSite=Lax'
  ]);

  return res.status(200).json({ ok: true, message: 'Sesión cerrada correctamente' });
}
