import jwt from 'jsonwebtoken';

export function getUser(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

export function requireAuth(req, res) {
  const user = getUser(req);
  if (!user) {
    res.status(401).json({ ok: false, error: 'مش مسجل دخول' });
    return null;
  }
  return user;
}

export function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (!user.isAdmin) {
    res.status(403).json({ ok: false, error: 'غير موجود');
    return null;
  }
  return user;
}

export function requireOwner(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'owner') {
    res.status(403).json({ ok: false, error: 'ممنوع');
    return null;
  }
  return user;
    }
