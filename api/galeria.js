import crypto from 'crypto';

function readCookie(rawCookie, name) {
  if (!rawCookie) return null;
  const match = rawCookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');

  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifySessionCookie(rawValue) {
  if (!rawValue || typeof rawValue !== 'string') return null;

  const [token, signature] = rawValue.split('.');
  if (!token || !signature) return null;

  const secret = process.env.SESSION_SECRET;
  if (!secret) return null;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');

  if (!safeEqual(expectedSignature, signature)) {
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

function hashPassword(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Método no permitido' });
  }

  const cookieValue = readCookie(req.headers.cookie || '', 'panel_session');
  const session = verifySessionCookie(cookieValue);

  if (!session) {
    return res.status(401).json({ success: false, message: 'No autorizado' });
  }

  const {
    drive_url,
    drive_id,
    titulo,
    portada_url,
    es_privada,
    clave,
    created_at
  } = req.body || {};

  if (!drive_url || typeof drive_url !== 'string' || !drive_url.trim()) {
    return res.status(400).json({ success: false, message: 'Falta la URL de Drive' });
  }

  if (!titulo || typeof titulo !== 'string' || !titulo.trim()) {
    return res.status(400).json({ success: false, message: 'Falta el título' });
  }

  if (es_privada && (!clave || typeof clave !== 'string' || !clave.trim())) {
    return res.status(400).json({ success: false, message: 'Para galería privada, la clave es obligatoria' });
  }

  const safeDriveUrl = String(drive_url).trim();
  const safeTitulo = String(titulo).trim();
  const safePortada = portada_url ? String(portada_url).trim() : '';
  const safeDriveId = drive_id ? String(drive_id).trim() : '';

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceKey) {
    return res.status(500).json({
      success: false,
      message: 'Configuración de Supabase incompleta'
    });
  }

  const payload = {
    titulo: safeTitulo,
    drive_url: safeDriveUrl,
    drive_id: safeDriveId || null,
    portada_url: safePortada || null,
    es_privada: !!es_privada,
    clave_hash: es_privada ? hashPassword(clave) : null,
    created_at: created_at || new Date().toISOString()
  };

  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/galeria`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${supabaseServiceKey}`,
        'apikey': supabaseServiceKey,
        'Prefer': 'return=representation'
      },
      body: JSON.stringify(payload)
    });

    const text = await response.text();

    if (!response.ok) {
      throw new Error(text || 'Error en Supabase');
    }

    return res.status(200).json({
      success: true,
      message: 'Galería guardada correctamente',
      data: JSON.parse(text || '[]')
    });

  } catch (error) {
    console.error('Supabase insert error:', error);
    return res.status(500).json({
      success: false,
      message: 'No se pudo guardar la galería en la base de datos'
    });
  }
}
