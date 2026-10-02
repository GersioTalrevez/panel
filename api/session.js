// api/session.js
export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const cookieHeader = req.headers.cookie || '';
  const sessionOK = cookieHeader.includes('admin_session=true');
  
  // Extraer el email de las cookies si existe
  const match = cookieHeader.match(/admin_email=([^;]+)/);
  const email = match ? decodeURIComponent(match[1]) : '';

  if (!sessionOK) {
    return res.status(401).json({ authorized: false, message: 'No autorizado' });
  }

  return res.status(200).json({ authorized: true, email: email });
}
