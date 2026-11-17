'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const createStore = require('./store');

const PORT = process.env.PORT || 3000;
const store = createStore();
// index.html может лежать в public/ или рядом с server.js (удобно при загрузке файлов через сайт GitHub)
const INDEX = fs.readFileSync(
  [path.join(__dirname, 'public', 'index.html'), path.join(__dirname, 'index.html')].find((f) => fs.existsSync(f))
);

/* ---------------- утилиты ---------------- */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, msg) => { throw new HttpError(status, msg); };

const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
function randomId(len) {
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return s;
}
const token = () => crypto.randomBytes(24).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function hashPin(pin, salt) {
  return crypto.scryptSync(String(pin), salt, 32).toString('hex');
}
function cleanText(v, max) {
  return String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, max);
}
function cleanWish(v) {
  return String(v == null ? '' : v).replace(/\r/g, '').replace(/\n{3,}/g, '\n\n').trim().slice(0, 300);
}
function checkPin(pin) {
  if (!/^\d{4}$/.test(String(pin || ''))) fail(400, 'PIN должен состоять из 4 цифр');
}

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/* ---------------- представления (что кому отдаём) ---------------- */
function publicGame(g) {
  return {
    id: g.id, title: g.title, budget: g.budget, date: g.date, status: g.status,
    players: g.players.map((p) => ({ id: p.id, name: p.name })),
  };
}
function adminGame(g) {
  // Организатор видит участников и прогресс, но НЕ пары.
  return {
    ...publicGame(g),
    players: g.players.map((p) => ({ id: p.id, name: p.name, hasWish: !!p.wish, seen: !!p.seen, pinReset: !!p.mustChangePin })),
  };
}

/* ---------------- авторизация ---------------- */
function requireAdmin(g, req) {
  const key = req.headers['x-admin-key'];
  if (!key || !safeEqual(sha256(key), g.adminHash)) fail(403, 'Нет доступа организатора');
}
function findPlayerByToken(g, req) {
  const t = req.headers['x-player-token'];
  if (!t) fail(401, 'Нужно войти');
  const h = sha256(t);
  const p = g.players.find((x) => x.tokenHashes && x.tokenHashes.some((th) => safeEqual(th, h)));
  if (!p) fail(401, 'Сессия устарела, войдите снова');
  return p;
}
function issueToken(p) {
  const t = token();
  p.tokenHashes = [...(p.tokenHashes || []), sha256(t)].slice(-5); // до 5 устройств
  return t;
}

/* ---------------- маршруты API ---------------- */
async function loadOr404(id) {
  const g = await store.get(id);
  if (!g) fail(404, 'Игра не найдена');
  return g;
}
async function mutate(id, fn) {
  const r = await store.update(id, fn);
  if (r.notFound) fail(404, 'Игра не найдена');
  return r.result;
}

const routes = [
  // создать игру
  ['POST', /^\/api\/games$/, async (req, body) => {
    const title = cleanText(body.title, 60) || 'Тайный Санта';
    const adminKey = token();
    const game = {
      id: randomId(8), title,
      budget: cleanText(body.budget, 30), date: cleanText(body.date, 30),
      status: 'open', adminHash: sha256(adminKey), players: [], pairs: null,
      createdAt: new Date().toISOString(),
    };
    await store.create(game);
    return { id: game.id, adminKey };
  }],

  // публичная информация
  ['GET', /^\/api\/games\/([a-z0-9]+)$/, async (req, body, [id]) => publicGame(await loadOr404(id))],

  // присоединиться
  ['POST', /^\/api\/games\/([a-z0-9]+)\/join$/, async (req, body, [id]) => {
    const name = cleanText(body.name, 40);
    if (!name) fail(400, 'Введите имя');
    checkPin(body.pin);
    if (String(body.pin) === '0000') fail(400, 'PIN 0000 зарезервирован для сброса, придумайте другой');
    return mutate(id, (g) => {
      if (g.status !== 'open') fail(409, 'Жеребьёвка уже прошла, новых участников добавить нельзя');
      if (g.players.length >= 100) fail(409, 'Слишком много участников');
      if (g.players.some((p) => p.name.toLowerCase() === name.toLowerCase()))
        fail(409, 'Такое имя уже есть. Если это вы — нажмите «Я уже участвую». Иначе добавьте фамилию.');
      const salt = crypto.randomBytes(8).toString('hex');
      const p = { id: randomId(6), name, salt, pinHash: hashPin(body.pin, salt), wish: cleanWish(body.wish), seen: false, fails: 0, lockedUntil: 0 };
      const t = issueToken(p);
      g.players.push(p);
      return { playerId: p.id, token: t };
    });
  }],

  // войти с другого устройства
  ['POST', /^\/api\/games\/([a-z0-9]+)\/login$/, async (req, body, [id]) => {
    checkPin(body.pin);
    return mutate(id, (g) => {
      const p = g.players.find((x) => x.id === body.playerId);
      if (!p) fail(404, 'Участник не найден');
      const now = Date.now();
      if (p.lockedUntil > now) fail(429, 'Слишком много попыток. Попробуйте через 10 минут.');
      if (!safeEqual(hashPin(body.pin, p.salt), p.pinHash)) {
        p.fails = (p.fails || 0) + 1;
        if (p.fails >= 5) { p.fails = 0; p.lockedUntil = now + 10 * 60 * 1000; }
        return { error: 'Неверный PIN' };
      }
      p.fails = 0;
      return { playerId: p.id, token: issueToken(p), mustChangePin: !!p.mustChangePin };
    });
  }],

  // моя карточка
  ['GET', /^\/api\/games\/([a-z0-9]+)\/me$/, async (req, body, [id]) => {
    let g = await loadOr404(id);
    let me = findPlayerByToken(g, req);
    if (g.status === 'drawn' && !me.seen) {
      await mutate(id, (gg) => { const p = gg.players.find((x) => x.id === me.id); if (p) p.seen = true; });
    }
    let recipient = null;
    if (g.status === 'drawn' && g.pairs && g.pairs[me.id]) {
      const r = g.players.find((x) => x.id === g.pairs[me.id]);
      if (r) recipient = { name: r.name, wish: r.wish || '' };
    }
    return {
      game: publicGame(g),
      me: { id: me.id, name: me.name, wish: me.wish || '', mustChangePin: !!me.mustChangePin },
      recipient,
    };
  }],

  // изменить своё пожелание
  ['PUT', /^\/api\/games\/([a-z0-9]+)\/me\/wish$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      me.wish = cleanWish(body.wish);
      return { wish: me.wish };
    });
  }],

  // выйти из игры (до жеребьёвки)
  ['DELETE', /^\/api\/games\/([a-z0-9]+)\/me$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      if (g.status !== 'open') fail(409, 'После жеребьёвки выйти нельзя — попросите организатора');
      g.players = g.players.filter((p) => p.id !== me.id);
      return { ok: true };
    });
  }],

  // сменить свой PIN (обязательно после сброса организатором)
  ['PUT', /^\/api\/games\/([a-z0-9]+)\/me\/pin$/, async (req, body, [id]) => {
    checkPin(body.pin);
    if (String(body.pin) === '0000') fail(400, 'Придумайте PIN, отличный от 0000');
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      me.salt = crypto.randomBytes(8).toString('hex');
      me.pinHash = hashPin(body.pin, me.salt);
      me.mustChangePin = false;
      return { ok: true };
    });
  }],

  // ---- организатор ----
  ['GET', /^\/api\/games\/([a-z0-9]+)\/admin$/, async (req, body, [id]) => {
    const g = await loadOr404(id);
    requireAdmin(g, req);
    return adminGame(g);
  }],

  ['PUT', /^\/api\/games\/([a-z0-9]+)\/admin$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (body.title !== undefined) g.title = cleanText(body.title, 60) || 'Тайный Санта';
      if (body.budget !== undefined) g.budget = cleanText(body.budget, 30);
      if (body.date !== undefined) g.date = cleanText(body.date, 30);
      return adminGame(g);
    });
  }],

  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/draw$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (g.players.length < 3) fail(400, 'Нужно минимум 3 участника');
      // одна общая цепочка: никто не дарит сам себе и нет взаимных пар
      const order = shuffle(g.players.map((p) => p.id));
      g.pairs = {};
      order.forEach((pid, i) => { g.pairs[pid] = order[(i + 1) % order.length]; });
      g.players.forEach((p) => { p.seen = false; });
      g.status = 'drawn';
      return adminGame(g);
    });
  }],

  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/reset$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      g.pairs = null; g.status = 'open';
      g.players.forEach((p) => { p.seen = false; });
      return adminGame(g);
    });
  }],

  // сбросить PIN участника на 0000: все его сессии закрываются, при входе он задаст новый PIN
  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/players\/([a-z0-9]+)\/reset-pin$/, async (req, body, [id, pid]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      const p = g.players.find((x) => x.id === pid);
      if (!p) fail(404, 'Участник не найден');
      p.salt = crypto.randomBytes(8).toString('hex');
      p.pinHash = hashPin('0000', p.salt);
      p.mustChangePin = true;
      p.fails = 0; p.lockedUntil = 0;
      p.tokenHashes = [];
      return adminGame(g);
    });
  }],

  ['DELETE', /^\/api\/games\/([a-z0-9]+)\/admin\/players\/([a-z0-9]+)$/, async (req, body, [id, pid]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (g.status !== 'open') fail(409, 'Сначала отмените жеребьёвку');
      g.players = g.players.filter((p) => p.id !== pid);
      return adminGame(g);
    });
  }],
];

/* ---------------- HTTP ---------------- */
function send(res, status, data, headers = {}) {
  const isBuf = Buffer.isBuffer(data);
  const payload = isBuf ? data : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': isBuf ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    ...headers,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 10 * 1024) { reject(new HttpError(413, 'Слишком большой запрос')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) || {}); }
      catch { reject(new HttpError(400, 'Некорректный JSON')); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (req.method === 'GET' && (p === '/' || /^\/g\/[a-z0-9]+(\/admin)?\/?$/.test(p))) return send(res, 200, INDEX);
    if (req.method === 'GET' && p === '/healthz') return send(res, 200, { ok: true, store: store.kind });
    for (const [method, re, handler] of routes) {
      if (req.method !== method) continue;
      const m = p.match(re);
      if (!m) continue;
      const body = ['POST', 'PUT'].includes(method) ? await readBody(req) : {};
      const out = await handler(req, body, m.slice(1));
      if (out && out.error) return send(res, 400, { error: out.error });
      return send(res, 200, out);
    }
    send(res, 404, { error: 'Не найдено' });
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Ошибка сервера, попробуйте ещё раз' });
  }
});

store.init()
  .then(() => server.listen(PORT, () => console.log(`Secret Santa on :${PORT} (store: ${store.kind})`)))
  .catch((e) => { console.error('Не удалось подключиться к базе:', e.message); process.exit(1); });
