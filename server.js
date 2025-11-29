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
const PRODUCT_TYPE_ALIASES = {
  UMCBL: 'USDT-FUTURES',
};

function normalizeProductType(value, fallback) {
  const raw = String(value ?? '').trim();
  if (!raw || raw.toLowerCase() === 'undefined' || raw.toLowerCase() === 'null') {
    if (!fallback) {
      return '';
    }
    return normalizeProductType(fallback);
  }
  const upper = raw.toUpperCase();
  return PRODUCT_TYPE_ALIASES[upper] || upper;
}

const BITGET_PRODUCT_TYPE = normalizeProductType(process.env.BITGET_PRODUCT_TYPE, 'USDT-FUTURES');
const BITGET_MARGIN_COIN = process.env.BITGET_MARGIN_COIN || 'USDT';
const LIVE_FEED_SOURCE = 'binance';
const MARKET_MOVERS_SOURCE = 'binance';
const CRYPTOPANIC_API_KEY = process.env.CRYPTOPANIC_API_KEY;
const ACCOUNT_EQUITY = Number(process.env.ACCOUNT_EQUITY || 10000);
const RISK_PCT = Number(process.env.RISK_PCT || 0.01);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  if (!user) {
    clearSessionCookie(res);
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.json({ user });
});
app.post('/api/logout', (req, res) => { clearSessionCookie(res); return res.json({ ok: true }); });
app.get('/api/config', (req, res) => res.json({
  botUsername: BOT_USERNAME || '',
  botId: BOT_ID || '',
  riskPct: RISK_PCT,
  accountEquity: ACCOUNT_EQUITY,
  riskPerTrade: ACCOUNT_EQUITY * RISK_PCT,
})); 

async function fetchAccountEquity() {
  const productType = resolveProductType(BITGET_PRODUCT_TYPE);
    const path = `/api/v2/mix/account/accounts?productType=${productType}`;
  const data = await bitgetRequestWithRetry('GET', path);
  const rows = Array.isArray(data) ? data : Array.isArray(data?.accounts) ? data.accounts : [];
  const first = rows.find((r) => (r.marginCoin ? r.marginCoin === BITGET_MARGIN_COIN : true)) || rows[0] || {};
  const eq = Number(
    first.usdtEquity ??
    first.totalEquity ??
    first.equity ??
    first.fixedBalance ??
    first.available ??
    first.crossMarginEquity ??
    0
  );
  return { equity: eq, raw: first };
}

app.get('/api/account-equity', async (req, res) => {
  try {
    const { equity } = await fetchAccountEquity();
    const safeEquity = Number.isFinite(equity) && equity > 0 ? equity : ACCOUNT_EQUITY;
    const riskPerTrade = safeEquity * RISK_PCT;
    return res.json({ equity: safeEquity, riskPct: RISK_PCT, riskPerTrade, source: 'bitget' });
  } catch (err) {
    console.error('account-equity error:', err.message);
    const fallbackRiskPerTrade = ACCOUNT_EQUITY * RISK_PCT;
    return res.json({ equity: ACCOUNT_EQUITY, riskPct: RISK_PCT, riskPerTrade: fallbackRiskPerTrade, source: 'fallback' });
  }
});

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
async function bitgetRequestWithRetry(method, path, payload = null, retries = 2, delayMs = 800) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await bitgetRequest(method, path, payload);
    } catch (err) {
      const msg = err?.message || '';
      const is429 = msg.includes('429') || msg.toLowerCase().includes('too many requests');
      if (is429 && attempt < retries) {
        await sleep(delayMs * (attempt + 1));
        continue;
      }
      throw err;
    }
  }
}

function mapHistoryToTrades(rows) {
  if (!Array.isArray(rows)) return [];
  const pickTime = (r) => r.fillTime || r.endTime || r.finishTime || r.cTime || r.uTime || r.updateTime;
    return rows.map((r) => ({
      id: r.orderId || r.tradeId || crypto.randomUUID(),
      time: pickTime(r),
      symbol: r.symbol || r.instId || `${r.baseCoin || ''}/${r.quoteCoin || ''}`.replace('//', '/'),
      side: r.side || r.tradeSide || r.posSide,
    entry: r.entryPrice || r.price || r.orderPrice || r.fillPrice || r.executePrice || r.dealAvgPrice || r.enterPoint,
    closePrice: r.closePrice || r.exitPrice || r.averageClosePrice || r.avgClosePrice || r.priceAvg || r.dealAvgPrice || r.fillPrice,
    stopLoss: r.stopLoss ?? r.stopLossPrice ?? r.presetStopLossPrice ?? r.sl,
    contractValue: r.contractValue || r.contract_size || r.contractSize,
    price: r.fillPrice || r.price || r.closePrice || r.avgPrice || r.priceAvg || r.executePrice || r.dealAvgPrice || r.enterPoint || r.orderPrice,
    liqPrice: r.liqPrice ?? r.liquidationPrice ?? null,
    qty: r.fillQuantity || r.size || r.quantity || r.baseVolume || r.cumExecQty,
    status: r.state || r.status,
    pnl: Number(r.pnl ?? r.closeProfitLoss ?? r.totalProfits ?? r.profit ?? r.pnlAmount ?? r.realizedAmount ?? 0),
    positionPct: r.position || r.positionPercent || r.positionPct,
  }));
}

// Bitget routes
app.get('/api/bitget/history', async (req, res) => {
  try {
    const productType = resolveProductType(req.query.productType);
    const limit = Number(req.query.pageSize || 50);
    const nowMs = Date.now();
    const end = nowMs;
    const start = nowMs - 30 * 24 * 60 * 60 * 1000;
    const params = new URLSearchParams({
      productType,
      limit: `${limit}`,
      startTime: `${start}`,
      endTime: `${end}`,
    });
    const endpoint = `${ORDER_HISTORY_PATH}?${params.toString()}`;
    console.log('bitget history GET path', endpoint);
    const data = await bitgetRequestWithRetry('GET', endpoint);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    return res.json({ trades: mapHistoryToTrades(rows) });
  } catch (err) {
    console.error('Bitget history error:', err.message);
    return res.status(500).json({ error: 'Bitget history fetch failed', detail: err.message });
  }
});

function resolveProductType(queryType) {
  return normalizeProductType(queryType, BITGET_PRODUCT_TYPE);
}

const ORDER_HISTORY_PATH = '/api/v2/mix/order/orders-history';

async function fetchHistoryWindow(productType, start, end, pageSize = 100, maxPages = 40) {
  const trades = [];
  let idLessThan;
  let page = 0;
  const startTimeLimit = start ? Number(start) : 0;
  const endTimeLimit = end ? Number(end) : 0;
  while (page < maxPages) {
    const params = new URLSearchParams({ productType, limit: `${pageSize}` });
    if (idLessThan) {
      params.set('idLessThan', `${idLessThan}`);
    } else if (endTimeLimit) {
      params.set('endTime', `${endTimeLimit}`);
    }
    const path = `${ORDER_HISTORY_PATH}?${params.toString()}`;
    console.log('fetchHistoryWindow GET path', path);
    const data = await bitgetRequestWithRetry('GET', path);
    const rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
    if (!rows.length) break;
    const mapped = mapHistoryToTrades(rows);
    trades.push(...mapped);
    const ids = rows.map((r) => Number(r.orderId || r.tradeId || 0)).filter((v) => Number.isFinite(v) && v > 0);
    if (!ids.length) break;
    idLessThan = Math.min(...ids);
    const oldestTime = Math.min(...mapped.map((t) => Number(t.time) || 0));
    if (startTimeLimit && oldestTime && oldestTime <= startTimeLimit) break;
    page += 1;
  }
  return trades;
}

const historyCache = { ts: 0, data: [], ttl: 3 * 60 * 1000 };

app.get('/api/bitget/full-history', async (req, res) => {
  try {
    const productType = resolveProductType(req.query.productType);
    console.log('full-history query productType raw ->', req.query.productType, 'resolved ->', productType);
    const days = Number(req.query.days) || 180;
    const windowDays = 30;
    const windowMs = windowDays * 24 * 60 * 60 * 1000;
    const nowMs = Date.now();
    const startAll = nowMs - days * 24 * 60 * 60 * 1000;

    if (historyCache.data.length && nowMs - historyCache.ts < historyCache.ttl && historyCache.productType === productType) {
      const trades = historyCache.data.slice(0);
      return res.json({ trades, count: trades.length, cached: true });
    }

    const allTrades = await fetchHistoryWindow(productType, startAll, nowMs, 100, 60);

    // Dedupe by id (or symbol+time fallback) to avoid duplicates across windows
    const deduped = new Map();
    for (const t of allTrades) {
      const key = t.id || `${t.symbol || 'unk'}-${t.time || crypto.randomUUID()}`;
      if (!deduped.has(key)) deduped.set(key, t);
    }

    const trades = Array.from(deduped.values()).filter((t) => {
      const time = Number(t.time) || 0;
      if (startAll && time < startAll) return false;
      if (nowMs && time > nowMs) return false;
      return true;
    });
    trades.sort((a, b) => Number(b.time || 0) - Number(a.time || 0));
    historyCache.ts = Date.now();
    historyCache.data = trades.slice(0);
    historyCache.productType = productType;
    return res.json({ trades, count: trades.length });
  } catch (err) {
    console.error('Bitget full history error:', err.message);
    return res.status(500).json({ error: 'Bitget full history fetch failed', detail: err.message });
  }
});

app.get('/api/bitget/open-positions', async (req, res) => {
  try {
    const productType = resolveProductType(req.query.productType);
        const path = `/api/v2/mix/position/all-position?productType=${productType}`;
    const data = await bitgetRequestWithRetry('GET', path);
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
      stopLoss: p.stopLossPrice || p.presetStopLossPrice || p.stopLoss || p.sl || '',
      takeProfit: p.takeProfitPrice || p.presetTakeProfitPrice || p.takeProfit || p.tp || '',
    }));
    return res.json({ positions });
  } catch (err) {
    console.error('Bitget positions error:', err.message);
    return res.status(500).json({ error: 'Bitget positions fetch failed', detail: err.message });
  }
});


app.get('/api/bitget/open-limits', async (req, res) => {
  try {
    const productType = resolveProductType(req.query.productType);
    const limit = Number(req.query.pageSize || 50);
    const symbol = req.query.symbol;
    const attempts = [];
    const discoveredSymbols = [];

    // collect symbols from positions if none provided
    if (!symbol) {
      try {
      const posPath = `/api/v2/mix/position/all-position?productType=${productType}`;
        const posData = await bitgetRequestWithRetry('GET', posPath);
        const posRows = Array.isArray(posData) ? posData : Array.isArray(posData?.positions) ? posData.positions : [];
        posRows.forEach((p) => {
          if (p.symbol) discoveredSymbols.push(p.symbol);
        });
      } catch (err) {
        // ignore
      }
    }

    const baseParams = new URLSearchParams({ productType, limit: `${limit > 100 ? 100 : limit}` });
    if (symbol) baseParams.append('symbol', symbol);
    if (BITGET_MARGIN_COIN) baseParams.append('marginCoin', BITGET_MARGIN_COIN);

    // primary endpoints
    attempts.push(`/api/v2/mix/order/orders-pending?${baseParams.toString()}`);
    attempts.push(`/api/v2/mix/order/orders-plan-pending?${baseParams.toString()}`);

    // discover symbols via contracts and recent history
    const symbolPool = new Set(discoveredSymbols);
    try {
      const contractsPath = `/api/v2/mix/market/contracts?productType=${productType}`;
      const contracts = await bitgetRequestWithRetry('GET', contractsPath);
      (contracts || []).forEach((c) => c.symbol && symbolPool.add(c.symbol));
    } catch (e) { /* ignore */ }

    try {
      const now = Date.now();
      const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
      const histParams = new URLSearchParams({ productType, limit: '100', startTime: sevenDaysAgo, endTime: now });
      const histPath = `/api/v2/mix/order/orders-history?${histParams.toString()}`;
      const hist = await bitgetRequestWithRetry('GET', histPath);
      const rows = Array.isArray(hist?.orderList) ? hist.orderList : Array.isArray(hist) ? hist : [];
      rows.forEach((r) => r.symbol && symbolPool.add(r.symbol));
    } catch (e) { /* ignore */ }

    let rows = [];
    let lastErr = null;
    for (const path of attempts) {
      try {
        const data = await bitgetRequestWithRetry('GET', path);
        rows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
        if (rows.length) break;
      } catch (err) {
        const msg = err?.message || '';
        if (msg.includes('40404')) continue; // skip missing endpoints quietly
        lastErr = err;
        continue;
      }
    }

    // if still empty, query per-symbol
    if (!rows.length && symbolPool.size) {
      const symbolLimit = `${limit > 100 ? 100 : limit}`;
      for (const sym of symbolPool) {
        const paramsSym = new URLSearchParams({ productType, limit: symbolLimit, symbol: sym });
        if (BITGET_MARGIN_COIN) paramsSym.append('marginCoin', BITGET_MARGIN_COIN);
        const symbolPaths = [
          `/api/v2/mix/order/orders-pending?${paramsSym.toString()}`,
          `/api/v2/mix/order/orders-plan-pending?${paramsSym.toString()}`,
        ];
        for (const path of symbolPaths) {
          try {
            const data = await bitgetRequestWithRetry('GET', path);
            const symRows = Array.isArray(data?.orderList) ? data.orderList : Array.isArray(data) ? data : [];
            if (symRows.length) {
              rows.push(...symRows);
              break;
            }
          } catch (err) {
            const msg = err?.message || '';
            if (msg.includes('40404')) continue;
            lastErr = err;
            continue;
          }
        }
      }
    }

    if (!rows.length && lastErr) {
      if (String(lastErr?.code || '').includes('404')) {
        console.warn('Bitget limits endpoint not found; returning empty list');
        return res.json({ limits: [] });
      }
      console.error('Bitget limits all attempts failed:', lastErr.message);
      return res.json({ limits: [] });
    }

    const limits = rows
      .filter((o) => String(o.orderType || '').toLowerCase().includes('limit') || String(o.price || o.enterPoint || o.entrustPrice || o.planPrice || '').trim() !== '')
      .map((o) => ({
        symbol: o.symbol || o.instId,
        side: o.side || o.tradeSide || '',
        price: o.price || o.enterPoint || o.entrustPrice || o.planPrice || '-',
        size: o.size || o.quantity || o.orderQty || o.amount || '-',
        state: o.state || o.status || o.planStatus || '',
        ctime: o.cTime || o.createdTime || o.createTime || o.planTime || Date.now(),
        stopLoss: o.presetStopLossPrice || o.stopLossPrice || o.stopLoss || o.sl || '',
        takeProfit: o.presetTakeProfitPrice || o.takeProfitPrice || o.takeProfit || o.tp || '',
        reduceOnly: o.reduceOnly || false,
        orderType: o.orderType || o.planType || '',
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
    const windowSize = (req.query.window || '24h').toLowerCase();
    const win = ['1h', '4h', '12h', '1d', '24h'].includes(windowSize) ? windowSize : '24h';
    const cacheKey = `${dir}-${win}`;
    const now = Date.now();
    const ttl = 5 * 60 * 1000; // 5 minutes cache to avoid Binance ban
    if (marketCache.blockUntil && now < marketCache.blockUntil) {
      if (marketCache.data[cacheKey]) {
        return res.json({ ...marketCache.data[cacheKey].data, cached: true, blocked: true, reason: marketCache.blockReason });
      }
      return res.status(503).json({ error: 'Market movers temporarily blocked due to API weight', retryAfterMs: marketCache.blockUntil - now });
    }
    if (marketCache.data[cacheKey] && now - marketCache.data[cacheKey].ts < ttl) {
      return res.json({ ...marketCache.data[cacheKey].data, cached: true });
    }

    const baseUrl = 'https://api.binance.com/api/v3/ticker/24hr';
    const url = win === '24h' ? baseUrl : `${baseUrl}?windowSize=${win}`;
    let resp = await fetch(url, { headers: {} });
    if (!resp.ok && url.includes('windowSize')) {
      resp = await fetch(baseUrl, { headers: {} });
    }
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    const filtered = data.filter((t) => t.symbol && t.symbol.endsWith('USDT'));
    const sorted = filtered.sort((a, b) => Number(b.priceChangePercent) - Number(a.priceChangePercent));
    const list = dir === 'losers' ? sorted.slice().reverse() : sorted;
    const movers = list
      .slice(0, limit)
      .map((t) => ({ symbol: t.symbol, change: Number(t.priceChangePercent) }));
    const payload = { movers, source: MARKET_MOVERS_SOURCE, window: win, dir };
    marketCache.data[cacheKey] = { ts: now, data: payload };
    marketCache.blockUntil = 0;
    return res.json(payload);
  } catch (err) {
    console.error('Market movers error:', err.message);
    const dir = (req.query.dir || 'gainers').toLowerCase();
    const win = (req.query.window || '24h').toLowerCase();
    const cacheKey = `${dir}-${win}`;
    marketCache.blockUntil = Date.now() + 60 * 1000;
    marketCache.blockReason = err.message;
    if (marketCache.data[cacheKey]) {
      return res.json({ ...marketCache.data[cacheKey].data, cached: true, error: err.message });
    }
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

// Live feed: Binance force orders (cached 10m) via websocket
const LIVE_WS_URL = process.env.LIVE_WS_URL || 'wss://fstream.binance.com/stream?streams=!forceOrder@arr';
const liveCache = { ts: 0, data: [] };
const marketCache = { data: {}, blockUntil: 0, blockReason: '' };
const WebSocketClient = globalThis.WebSocket;
let wsLive;
let wsBackoffMs = 3000;
let wsReconnectTimer = null;

const mapForceOrder = (item) => {
  const price = Number(item.price) || 0;
  const qty = Number(item.origQty) || 0;
  const notional = price && qty ? price * qty : null;
  const side = (item.side || (price > 0 ? 'SELL' : 'BUY')).toUpperCase();
  return {
    symbol: item.symbol,
    side,
    price: price || null,
    qty: qty || null,
    notional,
    time: item.time || Date.now(),
  };
};

const updateLiveCache = (payload) => {
  const entries = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : [];
  if (!entries.length) return;
  const mapped = entries.map(mapForceOrder).sort((a, b) => Number(b.time || 0) - Number(a.time || 0));
  liveCache.ts = Date.now();
  liveCache.data = mapped;
};

const scheduleLiveReconnect = () => {
  if (wsReconnectTimer) return;
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    connectLiveWs();
  }, wsBackoffMs);
  wsBackoffMs = Math.min(wsBackoffMs * 2, 60_000);
};

const connectLiveWs = () => {
  if (!WebSocketClient) {
    console.warn('WebSocket not available in this environment; live feed will rely on REST.');
    return;
  }
  if (wsLive && wsLive.readyState === WebSocket.OPEN) return;
  if (wsLive) {
    wsLive.removeAllListeners?.();
    wsLive.close();
  }
  wsLive = new WebSocketClient(LIVE_WS_URL);
  wsLive.addEventListener('open', () => {
    console.log('Connected to live force order websocket');
    wsBackoffMs = 3000;
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer);
      wsReconnectTimer = null;
    }
  });
  wsLive.addEventListener('message', (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload && payload.data) {
        updateLiveCache(payload.data);
      }
    } catch (err) {
      console.error('live websocket parse error:', err.message);
    }
  });
  wsLive.addEventListener('close', () => {
    console.warn('Live websocket closed; reconnecting');
    scheduleLiveReconnect();
  });
  wsLive.addEventListener('error', (err) => {
    console.error('Live websocket error:', err.message);
    scheduleLiveReconnect();
  });
};
app.get('/api/live/liquidations', (req, res) => {
  const limit = Number(req.query.limit) || 20;
  const now = Date.now();
  if (liveCache.data.length && now - liveCache.ts < 10 * 60 * 1000) {
    return res.json({ source: LIVE_FEED_SOURCE, items: liveCache.data.slice(0, limit) });
  }
  if (liveCache.data.length) {
    return res.json({ source: LIVE_FEED_SOURCE, cached: true, items: liveCache.data.slice(0, limit) });
  }
  return res.status(503).json({ error: 'Live websocket not connected yet', detail: 'Awaiting initial stream data' });
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
connectLiveWs();
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

