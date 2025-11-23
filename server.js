import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const GROUP_ID = process.env.TELEGRAM_GROUP_ID; // e.g. -1001234567890
const BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME; // without @
const BOT_ID = BOT_TOKEN ? BOT_TOKEN.split(':')[0] : null;
const JWT_SECRET = process.env.JWT_SECRET || 'insecure-dev-secret';
const COOKIE_NAME = 'blackrose_session';
const IS_PROD = process.env.NODE_ENV === 'production';
const BITGET_API_KEY = process.env.BITGET_API_KEY;
const BITGET_API_SECRET = process.env.BITGET_API_SECRET;
const BITGET_API_PASSPHRASE = process.env.BITGET_API_PASSPHRASE;
const BITGET_PRODUCT_TYPE = process.env.BITGET_PRODUCT_TYPE || 'umcbl'; // default usdt-m futures

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));

function logMissingEnv() {
  const missing = [];
  if (!BOT_TOKEN) missing.push('TELEGRAM_BOT_TOKEN');
  if (!GROUP_ID) missing.push('TELEGRAM_GROUP_ID');
  if (!BOT_USERNAME) missing.push('TELEGRAM_BOT_USERNAME');
  if (!process.env.JWT_SECRET) {
    missing.push('JWT_SECRET (using insecure default)');
  }
  if (!process.env.BITGET_API_KEY || !process.env.BITGET_API_SECRET || !process.env.BITGET_API_PASSPHRASE) {
    missing.push('BITGET_API_KEY/BITGET_API_SECRET/BITGET_API_PASSPHRASE (for Bitget sync)');
  }
  if (missing.length) {
    // eslint-disable-next-line no-console
    console.warn(`Missing env vars: ${missing.join(', ')}. Set them in .env or your process manager.`);
  }
}

logMissingEnv();

function parseCookies(req) {
  const header = req.headers?.cookie;
  if (!header) return {};
  return header.split(';').reduce((acc, pair) => {
    const [key, ...rest] = pair.trim().split('=');
    if (!key) return acc;
    acc[key] = rest.join('=');
    return acc;
  }, {});
}

function getSessionUser(req) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function setSessionCookie(res, token) {
  const attrs = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=43200',
  ];
  if (IS_PROD) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearSessionCookie(res) {
  const attrs = [
    `${COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (IS_PROD) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function verifySignature(authData) {
  if (!authData || !authData.hash) return false;
  const dataCheckArr = Object.keys(authData)
    .filter((k) => k !== 'hash')
    .sort()
    .map((k) => `${k}=${authData[k]}`)
    .join('\n');
  // Per Telegram docs: secret_key = SHA256(bot_token), then HMAC_SHA256(data_check_string, secret_key)
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN ?? '').digest();
  const hash = crypto.createHmac('sha256', secretKey).update(dataCheckArr).digest('hex');
  return hash === authData.hash;
}

async function isGroupMember(userId) {
  if (!BOT_TOKEN || !GROUP_ID) return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000); // timeout 8s
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${GROUP_ID}&user_id=${userId}`;
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      // eslint-disable-next-line no-console
      console.error('getChatMember failed', await res.text());
      return false;
    }
    const data = await res.json();
    const status = data?.result?.status;
    return ['creator', 'administrator', 'member'].includes(status);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('getChatMember error', err?.message || err);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

app.post('/api/auth/telegram', async (req, res) => {
  const authData = req.body?.authData;
  if (!verifySignature(authData)) {
    return res.status(401).json({ error: 'Invalid Telegram signature' });
  }
  const allowed = await isGroupMember(authData.id);
  if (!allowed) return res.status(403).json({ error: 'Not a member of the required group' });

  const userPayload = {
    id: authData.id,
    username: authData.username,
    first_name: authData.first_name,
    last_name: authData.last_name,
    photo_url: authData.photo_url,
  };
  const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '12h' });
  setSessionCookie(res, token);
  return res.json({ ok: true, redirect: '/dashboard' });
});

app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  return res.json({ user });
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get('/api/config', (req, res) => {
  return res.json({
    botUsername: BOT_USERNAME || '',
    botId: BOT_ID || '',
  });
});

// Bitget helpers
function signBitget({ method, path, body = '' }) {
  const timestamp = Date.now().toString();
  const prehash = timestamp + method.toUpperCase() + path + body;
  const hmac = crypto.createHmac('sha256', BITGET_API_SECRET || '');
  const signature = hmac.update(prehash).digest('base64');
  return { timestamp, signature };
}

async function bitgetRequest(method, path, payload = null) {
  if (!BITGET_API_KEY || !BITGET_API_SECRET || !BITGET_API_PASSPHRASE) {
    throw new Error('Bitget API credentials missing');
  }
  const body = payload ? JSON.stringify(payload) : '';
  const { timestamp, signature } = signBitget({ method, path, body });
  const res = await fetch(`https://api.bitget.com${path}`, {
    method,
    headers: {
      'ACCESS-KEY': BITGET_API_KEY,
      'ACCESS-SIGN': signature,
      'ACCESS-TIMESTAMP': timestamp,
      'ACCESS-PASSPHRASE': BITGET_API_PASSPHRASE,
      'Content-Type': 'application/json',
    },
    body: body || undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text || res.statusText);
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(text || 'Bitget response parse error');
  }
  if (data.code && data.code !== '00000') throw new Error(`${data.code}: ${data.msg || 'Bitget API error'}`);
  return data.data;
}

function mapHistoryToTrades(rows = []) {
  return rows.map((r) => ({
    id: r.orderId || r.tradeId || crypto.randomUUID(),
    time: r.cTime || r.fillTime || r.endTime,
    symbol: r.symbol || r.instId || `${r.baseCoin || ''}/${r.quoteCoin || ''}`.replace('//', '/'),
    side: r.side || r.tradeSide || r.posSide,
    price: r.fillPrice || r.price || r.closePrice,
    qty: r.fillQuantity || r.size || r.quantity,
    status: r.state || r.status,
    pnl: r.pnl || r.closeProfitLoss,
  }));
}

app.get('/api/bitget/history', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const pageSize = req.query.pageSize || 50;
    const path = `/api/mix/v1/order/history?productType=${productType}&pageSize=${pageSize}`;
    const data = await bitgetRequest('GET', path);
    const trades = mapHistoryToTrades(data.orderList || data);
    return res.json({ trades });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Bitget history error:', err.message);
    return res.status(500).json({ error: 'Bitget history fetch failed', detail: err.message });
  }
});

app.get('/dashboard', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect('/');
  return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/trades', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect('/');
  return res.sendFile(path.join(__dirname, 'public', 'trades.html'));
});

app.get('*', (req, res, next) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(indexPath, 'utf8', (err, content) => {
    if (err) return next(err);
    const hydrated = content
      .replace('__BOT_USERNAME__', BOT_USERNAME || 'your_bot_username')
      .replace('__BOT_ID__', BOT_ID || '');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(hydrated);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on http://localhost:${PORT}`);
});
