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
const BITGET_MARGIN_COIN = process.env.BITGET_MARGIN_COIN || 'USDT';
const LIVE_FEED_SOURCE = 'binance'; // simple source for liquidations
const MARKET_MOVERS_SOURCE = 'binance';
const NEWS_API_KEY = process.env.NEWS_API_KEY;
const CRYPTOPANIC_API_KEY = process.env.CRYPTOPANIC_API_KEY;

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
    'Max-Age=2592000', // 30 days
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
  const timer = setTimeout(() => controller.abort(), 15000); // timeout 15s
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${GROUP_ID}&user_id=${userId}`;
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      // eslint-disable-next-line no-console
      console.error('getChatMember failed', await res.text());
      return null;
    }
    const data = await res.json();
    const status = data?.result?.status;
    return ['creator', 'administrator', 'member'].includes(status);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('getChatMember error', err?.message || err);
    return null;
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
  if (allowed === null) {
    return res.status(503).json({ error: 'Không kiểm tra được membership (Telegram API không phản hồi), vui lòng thử lại.' });
  }
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

function mapHistoryToTrades(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((r) => ({
    id: r.orderId || r.tradeId || crypto.randomUUID(),
    time: r.cTime || r.fillTime || r.endTime,
    symbol: r.symbol || r.instId || `${r.baseCoin || ''}/${r.quoteCoin || ''}`.replace('//', '/'),
    side: r.side || r.tradeSide || r.posSide,
    price: r.fillPrice || r.price || r.closePrice,
    qty: r.fillQuantity || r.size || r.quantity,
    status: r.state || r.status,
    pnl: Number(
      r.pnl ??
      r.closeProfitLoss ??
      r.totalProfits ??
      r.profit ??
      r.pnlAmount ??
      r.realizedAmount ??
      0
    ),
  }));
}

app.get('/api/bitget/history', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const pageSize = req.query.pageSize || 50;
    const nowMs = Date.now();
    const end = nowMs;
    const start = nowMs - 30 * 24 * 60 * 60 * 1000; // 30 ngày gần nhất (ms)
    // historyProductType trả toàn bộ lệnh theo productType
    const path = `/api/mix/v1/order/historyProductType?productType=${productType}&pageSize=${pageSize}&startTime=${start}&endTime=${end}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    const trades = mapHistoryToTrades(rows);
    return res.json({ trades });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Bitget history error:', err.message);
    return res.status(500).json({ error: 'Bitget history fetch failed', detail: err.message });
  }
});

// Quét nhiều cửa sổ thời gian để lấy nhiều dữ liệu hơn
async function fetchHistoryWindow(productType, start, end, pageSize = 100, maxPages = 20) {
  const trades = [];
  for (let pageNo = 1; pageNo <= maxPages; pageNo += 1) {
    const path = `/api/mix/v1/order/historyProductType?productType=${productType}&pageSize=${pageSize}&pageNo=${pageNo}&startTime=${start}&endTime=${end}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    if (!rows.length) break;
    trades.push(...mapHistoryToTrades(rows));
    if (rows.length < pageSize) break; // hết trang
  }
  return trades;
}

app.get('/api/bitget/full-history', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const days = Number(req.query.days) || 180; // mặc định 180 ngày
    const windowDays = 30;
    const nowMs = Date.now();
    const startAll = nowMs - days * 24 * 60 * 60 * 1000;

    const tasks = [];
    for (let tEnd = nowMs; tEnd > startAll; tEnd -= windowDays * 24 * 60 * 60 * 1000) {
      const tStart = Math.max(startAll, tEnd - windowDays * 24 * 60 * 60 * 1000);
      tasks.push({ start: tStart, end: tEnd });
    }

    const allTrades = [];
    for (const w of tasks) {
      // eslint-disable-next-line no-console
      console.log(`Fetching Bitget window ${new Date(w.start).toISOString()} -> ${new Date(w.end).toISOString()}`);
      const chunk = await fetchHistoryWindow(productType, w.start, w.end);
      allTrades.push(...chunk);
    }

    // sắp xếp mới nhất trước
    allTrades.sort((a, b) => Number(b.time || 0) - Number(a.time || 0));
    return res.json({ trades: allTrades, count: allTrades.length });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Bitget full history error:', err.message);
    return res.status(500).json({ error: 'Bitget full history fetch failed', detail: err.message });
  }
});

app.get('/api/bitget/open-positions', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const path = `/api/mix/v1/position/allPosition?productType=${productType}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data) ? data : Array.isArray(data?.positions) ? data.positions : [];
    const positions = rows.map((p) => ({
      symbol: p.symbol || p.instId,
      side: p.holdSide || p.posSide || '',
      entryPrice: p.averageOpenPrice || p.avgEntryPrice || p.markAvgPrice || p.price || '-',
      size: p.total || p.totalSize || p.holdVol || p.size || '-',
      margin: p.margin || p.marginMode || '',
      pnl: p.unrealizedPL || p.upl || p.pnl || 0,
      updateTime: p.uTime || p.cTime || Date.now(),
      leverage: p.leverage || '',
    }));
    return res.json({ positions });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Bitget positions error:', err.message);
    return res.status(500).json({ error: 'Bitget positions fetch failed', detail: err.message });
  }
});

app.get('/api/bitget/open-limits', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const pageSize = req.query.pageSize || 50;
    // dùng ordersPending để lấy lệnh limit đang chờ
    const path = `/api/mix/v1/order/orders-pending?productType=${productType}&pageSize=${pageSize}&pageNo=1&marginCoin=${BITGET_MARGIN_COIN}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    const limits = rows
      .filter((o) => String(o.orderType || '').toLowerCase().includes('limit') || String(o.price || '') !== '')
      .map((o) => ({
        symbol: o.symbol || o.instId,
        side: o.side || o.tradeSide || '',
        price: o.price || o.enterPoint || '-',
        size: o.size || o.quantity || o.orderQty || '-',
        state: o.state || o.status || '',
        ctime: o.cTime || o.createdTime || o.createTime || Date.now(),
      }));
    return res.json({ limits });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Bitget limits error:', err.message);
    return res.status(500).json({ error: 'Bitget limits fetch failed', detail: err.message });
  }
});

// Market movers (Binance 24h tickers)
app.get('/api/market-movers', async (req, res) => {
  try {
    const dir = (req.query.dir || 'gainers').toLowerCase(); // gainers|losers
    const limit = Number(req.query.limit) || 5;
    const url = 'https://api.binance.com/api/v3/ticker/24hr';
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    const rows = Array.isArray(data) ? data : [];
    const movers = rows
      .map((r) => ({
        symbol: r.symbol,
        change: Number(r.priceChangePercent || 0),
      }))
      .filter((r) => isFinite(r.change))
      .sort((a, b) => dir === 'losers' ? a.change - b.change : b.change - a.change)
      .slice(0, limit);
    return res.json({ source: MARKET_MOVERS_SOURCE, dir, movers });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('market-movers error:', err.message);
    return res.status(500).json({ error: 'Market movers fetch failed', detail: err.message });
  }
});

// Watchlist (placeholder/static)
app.get('/api/watchlist', (req, res) => {
  const list = [
    { title: 'Spaghetti Chart (Majors + Altcoins)', trader: 'Moritz', date: '2025-10-13' },
    { title: 'BTC Spaghetti', trader: 'Moritz', date: '2025-09-22' },
    { title: 'Hyperliquid Spaghetti', trader: 'Moritz', date: '2025-09-22' },
  ];
  return res.json({ items: list });
});

// News (placeholder)
app.get('/api/news', (req, res) => {
  if (!CRYPTOPANIC_API_KEY) {
    return res.status(500).json({ error: 'CRYPTOPANIC_API_KEY missing' });
  }
  const url = `https://cryptopanic.com/api/v1/posts/?auth_token=${CRYPTOPANIC_API_KEY}&filter=rising`;
  fetch(url)
    .then(async (resp) => {
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    })
    .then((data) => {
      const items = (data.results || []).slice(0, 10).map((n) => ({
        title: n.title,
        time: n.published_at,
        source: n.domain || n.source?.title,
        url: n.url,
      }));
      return res.json({ items, source: 'cryptopanic' });
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error('cryptopanic api error:', err.message);
      return res.status(500).json({ error: 'News fetch failed', detail: err.message });
    });
});

// Live feed: Binance futures liquidations (no API key)
const liveCache = { ts: 0, data: [] };

app.get('/api/live/liquidations', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 20;
    const now = Date.now();
    // cache 10 minutes
    if (liveCache.data.length && now - liveCache.ts < 10 * 60 * 1000) {
      return res.json({ source: LIVE_FEED_SOURCE, items: liveCache.data.slice(0, limit) });
    }
    const url = `https://fapi.binance.com/fapi/v1/allForceOrders?limit=${limit}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || resp.statusText);
    }
    const data = await resp.json();
    const mapped = (Array.isArray(data) ? data : []).map((item) => ({
      symbol: item.symbol,
      side: item.side || (Number(item.price) > 0 ? 'SELL' : 'BUY'),
      price: item.price,
      qty: item.origQty,
      time: item.time,
    })).sort((a, b) => Number(b.time || 0) - Number(a.time || 0));
    liveCache.ts = now;
    liveCache.data = mapped;
    return res.json({ source: LIVE_FEED_SOURCE, items: mapped.slice(0, limit) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('live/liquidations error:', err.message);
    return res.status(500).json({ error: 'Live feed fetch failed', detail: err.message });
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
