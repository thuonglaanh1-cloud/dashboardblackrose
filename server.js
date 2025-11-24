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
const GROUP_ID = process.env.TELEGRAM_GROUP_ID;
const BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME;
const BOT_ID = BOT_TOKEN ? BOT_TOKEN.split(':')[0] : null;
const JWT_SECRET = process.env.JWT_SECRET || 'insecure-dev-secret';
const COOKIE_NAME = 'blackrose_session';
const IS_PROD = process.env.NODE_ENV === 'production';
const BITGET_API_KEY = process.env.BITGET_API_KEY;
const BITGET_API_SECRET = process.env.BITGET_API_SECRET;
const BITGET_API_PASSPHRASE = process.env.BITGET_API_PASSPHRASE;
const BITGET_PRODUCT_TYPE = process.env.BITGET_PRODUCT_TYPE || 'umcbl';
const BITGET_MARGIN_COIN = process.env.BITGET_MARGIN_COIN || 'USDT';
const LIVE_FEED_SOURCE = 'binance';
const MARKET_MOVERS_SOURCE = 'binance';
const CRYPTOPANIC_API_KEY = process.env.CRYPTOPANIC_API_KEY;

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// cookie helpers
function parseCookies(req) {
  const header = req.headers?.cookie;
  if (!header) return {};
  return header.split(';').reduce((acc, pair) => {
    const [k, ...rest] = pair.trim().split('=');
    if (!k) return acc;
    acc[k] = rest.join('=');
    return acc;
  }, {});
}
function getSessionUser(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function setSessionCookie(res, token) {
  const attrs = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=2592000',
  ];
  if (IS_PROD) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}
function clearSessionCookie(res) {
  const attrs = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (IS_PROD) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

// Telegram auth
function verifySignature(authData) {
  if (!authData || !authData.hash) return false;
  const dataCheck = Object.keys(authData).filter(k => k !== 'hash').sort()
    .map(k => `${k}=${authData[k]}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN ?? '').digest();
  const hash = crypto.createHmac('sha256', secretKey).update(dataCheck).digest('hex');
  return hash === authData.hash;
}
async function isGroupMember(userId) {
  if (!BOT_TOKEN || !GROUP_ID) return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${GROUP_ID}&user_id=${userId}`;
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return null;
    const data = await res.json();
    const status = data?.result?.status;
    return ['creator', 'administrator', 'member'].includes(status);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

app.post('/api/auth/telegram', async (req, res) => {
  const authData = req.body?.authData;
  if (!verifySignature(authData)) return res.status(401).json({ error: 'Invalid Telegram signature' });
  const allowed = await isGroupMember(authData.id);
  if (allowed === null) return res.status(503).json({ error: 'Không kiểm tra được membership, thử lại.' });
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
app.post('/api/logout', (req, res) => { clearSessionCookie(res); return res.json({ ok: true }); });
app.get('/api/config', (req, res) => res.json({ botUsername: BOT_USERNAME || '', botId: BOT_ID || '' }));

// Bitget signing
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
  const baseUrl = process.env.BITGET_API_BASE || 'https://api.bitget.com';
  const body = payload ? JSON.stringify(payload) : '';
  const { timestamp, signature } = signBitget({ method, path, body });
  const res = await fetch(`${baseUrl}${path}`, {
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
  const parsed = JSON.parse(text);
  if (parsed.code && parsed.code !== '00000') throw new Error(`${parsed.code}: ${parsed.msg || 'Bitget API error'}`);
  return parsed.data;
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
    pnl: Number(r.pnl ?? r.closeProfitLoss ?? r.totalProfits ?? r.profit ?? r.pnlAmount ?? r.realizedAmount ?? 0),
  }));
}

// Bitget routes
app.get('/api/bitget/history', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const pageSize = req.query.pageSize || 50;
    const nowMs = Date.now();
    const end = nowMs;
    const start = nowMs - 30 * 24 * 60 * 60 * 1000;
    const path = `/api/mix/v1/order/historyProductType?productType=${productType}&pageSize=${pageSize}&startTime=${start}&endTime=${end}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    return res.json({ trades: mapHistoryToTrades(rows) });
  } catch (err) {
    console.error('Bitget history error:', err.message);
    return res.status(500).json({ error: 'Bitget history fetch failed', detail: err.message });
  }
});

async function fetchHistoryWindow(productType, start, end, pageSize = 100, maxPages = 20) {
  const trades = [];
  for (let pageNo = 1; pageNo <= maxPages; pageNo++) {
    const path = `/api/mix/v1/order/historyProductType?productType=${productType}&pageSize=${pageSize}&pageNo=${pageNo}&startTime=${start}&endTime=${end}`;
    const data = await bitgetRequest('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    if (!rows.length) break;
    trades.push(...mapHistoryToTrades(rows));
    if (rows.length < pageSize) break;
  }
  return trades;
}

app.get('/api/bitget/full-history', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const days = Number(req.query.days) || 180;
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
      console.log(`Fetching Bitget window ${new Date(w.start).toISOString()} -> ${new Date(w.end).toISOString()}`);
      allTrades.push(...await fetchHistoryWindow(productType, w.start, w.end));
    }

    allTrades.sort((a, b) => Number(b.time || 0) - Number(a.time || 0));
    return res.json({ trades: allTrades, count: allTrades.length });
  } catch (err) {
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
    console.error('Bitget positions error:', err.message);
    return res.status(500).json({ error: 'Bitget positions fetch failed', detail: err.message });
  }
});

app.get('/api/bitget/open-limits', async (req, res) => {
  try {
    const productType = req.query.productType || BITGET_PRODUCT_TYPE;
    const pageSize = req.query.pageSize || 50;
    const symbol = req.query.symbol;
    const attempts = [];
    const discoveredSymbols = [];
    // lấy symbol từ positions nếu không truyền symbol
    if (!symbol) {
      try {
        const posPath = `/api/mix/v1/position/allPosition?productType=${productType}`;
        const posData = await bitgetRequest('GET', posPath);
        const posRows = Array.isArray(posData) ? posData : Array.isArray(posData?.positions) ? posData.positions : [];
        posRows.forEach((p) => {
          if (p.symbol) discoveredSymbols.push(p.symbol);
        });
      } catch (err) {
        // ignore; không chặn luồng
      }
    }
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
    const baseParams = new URLSearchParams({ productType, pageSize, pageNo: 1 });
    const withMargin = new URLSearchParams(baseParams);
    if (BITGET_MARGIN_COIN) withMargin.append('marginCoin', BITGET_MARGIN_COIN);
    if (symbol) { withMargin.append('symbol', symbol); baseParams.append('symbol', symbol); }
    // v2 không margin, với/không window thời gian
    const v2NoMargin = new URLSearchParams(baseParams);
    v2NoMargin.append('startTime', sevenDaysAgo);
    v2NoMargin.append('endTime', now);
    attempts.push(`/api/mix/v1/order/orders-pending-v2?${v2NoMargin.toString()}`);
    attempts.push(`/api/mix/v1/order/orders-pending-v2?${baseParams.toString()}`);
    // v2 với marginCoin
    const v2WithMargin = new URLSearchParams(withMargin);
    v2WithMargin.append('startTime', sevenDaysAgo);
    v2WithMargin.append('endTime', now);
    attempts.push(`/api/mix/v1/order/orders-pending-v2?${v2WithMargin.toString()}`);
    attempts.push(`/api/mix/v1/order/orders-pending-v2?${withMargin.toString()}`);
    // v1 pending/current
    attempts.push(`/api/mix/v1/order/orders-pending?${withMargin.toString()}`);
    attempts.push(`/api/mix/v1/order/current?${withMargin.toString()}`);
    attempts.push(`/api/mix/v1/order/orders-pending?${baseParams.toString()}`);
    attempts.push(`/api/mix/v1/order/current?${baseParams.toString()}`);

    // lấy thêm symbol từ contracts list và history (top 10) để quét
    const symbolPool = new Set(discoveredSymbols);
    try {
      const contractsPath = `/api/mix/v1/market/contracts?productType=${productType}`;
      const contracts = await bitgetRequest('GET', contractsPath);
      (contracts || []).forEach((c) => c.symbol && symbolPool.add(c.symbol));
    } catch (e) {
      // ignore
    }
    // top symbol từ history 7 ngày
    try {
      const histParams = new URLSearchParams({ productType, pageSize: 100, startTime: sevenDaysAgo, endTime: now });
      const histPath = `/api/mix/v1/order/historyProductType?${histParams.toString()}`;
      const hist = await bitgetRequest('GET', histPath);
      const rows = Array.isArray(hist?.orderList) ? hist.orderList : Array.isArray(hist) ? hist : [];
      rows.forEach((r) => r.symbol && symbolPool.add(r.symbol));
    } catch (e) {
      // ignore
    }

    let rows = [];
    let lastErr = null;
    for (const path of attempts) {
      try {
        const data = await bitgetRequest('GET', path);
        rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
        if (rows.length) break;
      } catch (err) {
        lastErr = err;
        continue;
      }
    }
    // nếu vẫn rỗng, thử theo từng symbol đã phát hiện
    if (!rows.length && symbolPool.size) {
      for (const sym of symbolPool) {
        const paramsSym = new URLSearchParams({ productType, pageSize, pageNo: 1, symbol: sym });
        if (BITGET_MARGIN_COIN) paramsSym.append('marginCoin', BITGET_MARGIN_COIN);
        const path = `/api/mix/v1/order/orders-pending-v2?${paramsSym.toString()}`;
        try {
          const data = await bitgetRequest('GET', path);
          const symRows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
          if (symRows.length) {
            rows.push(...symRows);
          }
        } catch (err) {
          lastErr = err;
          continue;
        }
      }
    }
    if (!rows.length && lastErr) {
      console.error('Bitget limits all attempts failed:', lastErr.message);
      return res.json({ limits: [] });
    }
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
    console.error('Bitget limits error:', err.message);
    return res.status(500).json({ error: 'Bitget limits fetch failed', detail: err.message });
  }
});

// Market movers
app.get('/api/market-movers', async (req, res) => {
  try {
    const dir = (req.query.dir || 'gainers').toLowerCase();
    const limit = Number(req.query.limit) || 5;
    const url = 'https://api.binance.com/api/v3/ticker/24hr';
    const resp = await fetch(url, { headers: {} });
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    const filtered = data.filter((t) => t.symbol && t.symbol.endsWith('USDT'));
    const sorted = filtered.sort((a, b) => Number(b.priceChangePercent) - Number(a.priceChangePercent));
    const movers = (dir === 'losers' ? sorted.slice().reverse() : sorted)
      .slice(0, limit)
      .map((t) => ({ symbol: t.symbol, change: Number(t.priceChangePercent) }));
    return res.json({ movers, source: MARKET_MOVERS_SOURCE });
  } catch (err) {
    console.error('Market movers error:', err.message);
    return res.status(500).json({ error: 'Market movers fetch failed', detail: err.message });
  }
});

// Watchlist placeholder
app.get('/api/watchlist', (req, res) => {
  const list = [
    { title: 'Spaghetti Chart (Majors + Altcoins)', trader: 'Moritz', date: '2025-10-13' },
    { title: 'BTC Spaghetti', trader: 'Moritz', date: '2025-09-22' },
    { title: 'Hyperliquid Spaghetti', trader: 'Moritz', date: '2025-09-22' },
  ];
  return res.json({ items: list });
});

// News via CryptoPanic
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
      console.error('cryptopanic api error:', err.message);
      return res.status(500).json({ error: 'News fetch failed', detail: err.message });
    });
});

// Live feed: Binance force orders (cached 10m)
const liveCache = { ts: 0, data: [] };
app.get('/api/live/liquidations', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 20;
    const now = Date.now();
    if (liveCache.data.length && now - liveCache.ts < 10 * 60 * 1000) {
      return res.json({ source: LIVE_FEED_SOURCE, items: liveCache.data.slice(0, limit) });
    }
    const urls = [
      `https://fapi.binance.com/futures/data/forceOrders?limit=${Math.min(limit, 50)}`,
      `https://fapi.binance.com/fapi/v1/allForceOrders?limit=${Math.min(limit, 50)}`,
    ];
    let data = null;
    for (const url of urls) {
      const resp = await fetch(url);
      if (resp.ok) { data = await resp.json(); break; }
    }
    if (!data) throw new Error('Live feed sources unavailable');
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
    console.error('live/liquidations error:', err.message);
    if (liveCache.data.length) {
      return res.json({ source: LIVE_FEED_SOURCE, cached: true, items: liveCache.data.slice(0, 20) });
    }
    return res.status(500).json({ error: 'Live feed fetch failed', detail: err.message });
  }
});

// Protected pages
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

// Fallback
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
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

