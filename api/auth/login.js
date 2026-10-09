import { readFileSync } from 'fs';
import { join } from 'path';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'املأ الحقول كلها' });
  }

  let admins = {};
  try {
    const filePath = join(process.cwd(), 'data', 'admins.json');
    admins = JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch {
    return res.status(500).json({ ok: false, error: 'ملف الحسابات مش موجود' });
  }

  const account = admins[username];

  if (!account || account.password !== password) {
    return res.status(401).json({ ok: false, error: 'اسم أو كلمة سر غلط' });
  }

  const role = account.role || 'admin';

  const token = jwt.sign(
    {
      sub: `admin:${username}`,
      username,
      role,
      verified: true,
      isAdmin: true,
      picture: null,
    },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  return res.status(200).json({
    ok: true,
    token,
    user: {
      id: `admin:${username}`,
      username,
      picture: null,
      bio: '',
      role,
      verified: true,
      isAdmin: true,
      banned: false,
    },
  });
}
