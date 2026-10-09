import { readFileSync } from 'fs';
import { join } from 'path';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { db } from '../../lib/db.js';

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function loadAdmins() {
  try {
    const filePath = join(process.cwd(), 'data', 'admins.json');
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch {
    return {};
  }
}

function findAdminByEmail(admins, email) {
  if (!email) return null;
  const lower = email.toLowerCase();
  for (const [username, data] of Object.entries(admins)) {
    if (data.email && data.email.toLowerCase() === lower) {
      return { username, role: data.role || 'admin' };
    }
  }
  return null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const { credential } = req.body || {};
  if (!credential) {
    return res.status(400).json({ ok: false, error: 'Credential مطلوب' });
  }

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch {
    return res.status(401).json({ ok: false, error: 'توكن Google غلط' });
  }

  const { sub, email, name, picture } = payload;

  const admins = loadAdmins();
  const adminMatch = findAdminByEmail(admins, email);

  let user;
  try {
    const existing = await db.execute({
      sql: 'SELECT * FROM users WHERE google_id = ? OR email = ?',
      args: [sub, email],
    });

    if (existing.rows.length) {
      user = existing.rows[0];

      if (user.banned) {
        return res.status(403).json({ ok: false, error: 'حسابك محظور' });
      }

      const newRole = adminMatch ? adminMatch.role : user.role;
      const newVerified = adminMatch ? 1 : user.verified;

      if (newRole !== user.role || newVerified !== user.verified) {
        await db.execute({
          sql: 'UPDATE users SET role = ?, verified = ?, last_seen = ? WHERE id = ?',
          args: [newRole, newVerified, Date.now(), user.id],
        });
        user.role = newRole;
        user.verified = newVerified;
      } else {
        await db.execute({
          sql: 'UPDATE users SET last_seen = ? WHERE id = ?',
          args: [Date.now(), user.id],
        });
      }
    } else {
      const id = crypto.randomUUID();
      const username = adminMatch ? adminMatch.username : (name || email.split('@')[0]);
      const now = Date.now();
      const role = adminMatch ? adminMatch.role : 'user';
      const verified = adminMatch ? 1 : 0;

      await db.execute({
        sql: `INSERT INTO users (id, google_id, email, username, picture, bio, role, verified, banned, created_at, last_seen)
              VALUES (?, ?, ?, ?, ?, '', ?, ?, 0, ?, ?)`,
        args: [id, sub, email, username, picture || '', role, verified, now, now],
      });

      user = {
        id, google_id: sub, email, username,
        picture: picture || '', bio: '',
        role, verified, banned: 0,
        created_at: now, last_seen: now,
      };
    }
  } catch (err) {
    return res.status(500).json({ ok: false, error: 'خطأ في قاعدة البيانات' });
  }

  const token = jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      verified: !!user.verified,
      isAdmin: user.role === 'admin' || user.role === 'owner',
    },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  return res.status(200).json({
    ok: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      picture: user.picture,
      bio: user.bio || '',
      role: user.role,
      verified: !!user.verified,
      isAdmin: user.role === 'admin' || user.role === 'owner',
      banned: !!user.banned,
    },
  });
      }
