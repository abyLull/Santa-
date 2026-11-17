'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const createStore = require('./store');
const { toSvg } = require('./qr');

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
  return String(v == null ? '' : v).replace(/\r/g, '').replace(/\n{3,}/g, '\n\n').trim().slice(0, 500);
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

const pairKey = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
// Распределение: сначала пробуем одну общую цепочку (случайный поиск с возвратом),
// если исключения мешают — любую перестановку без «сам себе» и без запрещённых пар.
function drawPairs(ids, exclusions) {
  const banned = new Set((exclusions || []).map(([a, b]) => pairKey(a, b)));
  const ok = (a, b) => a !== b && !banned.has(pairKey(a, b));
  const n = ids.length;
  let budget = 200000;
  for (let attempt = 0; attempt < 30 && budget > 0; attempt++) {
    const start = ids[crypto.randomInt(n)];
    const path = [start], used = new Set([start]);
    const dfs = () => {
      if (--budget < 0) return false;
      if (path.length === n) return ok(path[n - 1], start);
      for (const nx of shuffle(ids)) {
        if (used.has(nx) || !ok(path[path.length - 1], nx)) continue;
        path.push(nx); used.add(nx);
        if (dfs()) return true;
        path.pop(); used.delete(nx);
      }
      return false;
    };
    if (dfs()) { const pairs = {}; path.forEach((id, i) => { pairs[id] = path[(i + 1) % n]; }); return pairs; }
  }
  for (let i = 0; i < 20000; i++) {
    const perm = shuffle(ids);
    if (ids.every((id, k) => ok(id, perm[k]))) { const pairs = {}; ids.forEach((id, k) => { pairs[id] = perm[k]; }); return pairs; }
  }
  return null;
}
// цепочки для финала: [[имя, имя, ...], ...]
function chainsOf(g) {
  if (!g.pairs) return [];
  const name = (id) => (g.players.find((p) => p.id === id) || {}).name || '—';
  const seen = new Set(), out = [];
  for (const p of g.players) {
    if (seen.has(p.id) || !g.pairs[p.id]) continue;
    const chain = []; let cur = p.id;
    while (cur && !seen.has(cur)) { seen.add(cur); chain.push(name(cur)); cur = g.pairs[cur]; }
    out.push(chain);
  }
  return out;
}
const santaOf = (g, pid) => (g.pairs ? Object.keys(g.pairs).find((k) => g.pairs[k] === pid) : null);
const recoveryCode = () => [randomId(4), randomId(4), randomId(4)].join('-');
const normCode = (c) => String(c || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/* ---------------- представления (что кому отдаём) ---------------- */
function publicGame(g) {
  return {
    id: g.id, title: g.title, budget: g.budget, date: g.date, status: g.status,
    players: g.players.map((p) => ({ id: p.id, name: p.name })),
    revealed: !!g.revealed,
    chains: g.revealed ? chainsOf(g) : null,
  };
}
function adminGame(g) {
  // Организатор видит участников и прогресс, но НЕ пары.
  return {
    ...publicGame(g),
    players: g.players.map((p) => ({ id: p.id, name: p.name, hasWish: !!p.wish, seen: !!p.seen, ready: !!p.ready, pinReset: !!p.mustChangePin })),
    exclusions: g.exclusions || [],
    hasRecovery: !!g.recoveryHash,
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
    const adminKey = token(), code = recoveryCode();
    const game = {
      id: randomId(8), title,
      budget: cleanText(body.budget, 30), date: cleanText(body.date, 30),
      status: 'open', adminHash: sha256(adminKey), recoveryHash: sha256(normCode(code)),
      players: [], pairs: null, exclusions: [], messages: {}, revealed: false,
      createdAt: new Date().toISOString(),
    };
    await store.create(game);
    return { id: game.id, adminKey, recoveryCode: code };
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
        fail(409, 'Такое имя уже есть. Если это вы — нажмите «Я уже подавал(а) заявку». Иначе добавьте фамилию.');
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
    const msgs = g.messages || {};
    const asSanta = msgs[me.id] || [], sid = santaOf(g, me.id), asRecipient = (sid && msgs[sid]) || [];
    return {
      game: publicGame(g),
      me: { id: me.id, name: me.name, wish: me.wish || '', mustChangePin: !!me.mustChangePin, ready: !!me.ready },
      recipient,
      unread: {
        fromRecipient: asSanta.filter((m) => m.from === 'recipient').length - (me.readR || 0),
        fromSanta: asRecipient.filter((m) => m.from === 'santa').length - (me.readS || 0),
      },
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

  // подарок готов / не готов
  ['PUT', /^\/api\/games\/([a-z0-9]+)\/me\/ready$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      if (g.status !== 'drawn') fail(409, 'Сначала дождитесь жеребьёвки');
      me.ready = !!body.ready;
      return { ready: me.ready };
    });
  }],

  // анонимная переписка: я как Санта ↔ мой получатель, и я как получатель ↔ мой Санта
  ['GET', /^\/api\/games\/([a-z0-9]+)\/me\/chat$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      if (g.status !== 'drawn' || !g.pairs) return { withRecipient: [], withSanta: [] };
      g.messages = g.messages || {};
      const mine = g.messages[me.id] || [], sid = santaOf(g, me.id), theirs = (sid && g.messages[sid]) || [];
      me.readR = mine.filter((m) => m.from === 'recipient').length;
      me.readS = theirs.filter((m) => m.from === 'santa').length;
      return {
        withRecipient: mine.map((m) => ({ mine: m.from === 'santa', text: m.text, at: m.at })),
        withSanta: theirs.map((m) => ({ mine: m.from === 'recipient', text: m.text, at: m.at })),
      };
    });
  }],
  ['POST', /^\/api\/games\/([a-z0-9]+)\/me\/chat$/, async (req, body, [id]) => {
    const text = String(body.text == null ? '' : body.text).replace(/\r/g, '').trim().slice(0, 300);
    if (!text) fail(400, 'Напишите сообщение');
    return mutate(id, (g) => {
      const me = findPlayerByToken(g, req);
      if (g.status !== 'drawn' || !g.pairs) fail(409, 'Переписка откроется после жеребьёвки');
      const now = Date.now();
      if (me.lastMsgAt && now - me.lastMsgAt < 1500) fail(429, 'Не так быстро 🙂');
      g.messages = g.messages || {};
      let key, from;
      if (body.to === 'recipient') { key = me.id; from = 'santa'; }
      else if (body.to === 'santa') { key = santaOf(g, me.id); from = 'recipient'; }
      else fail(400, 'Кому отправить?');
      if (!key) fail(409, 'Санта не найден');
      const thread = g.messages[key] = g.messages[key] || [];
      if (thread.length >= 200) fail(409, 'Слишком много сообщений в этой переписке');
      thread.push({ from, text, at: new Date().toISOString() });
      me.lastMsgAt = now;
      if (from === 'santa') me.readR = thread.filter((m) => m.from === 'recipient').length;
      else me.readS = thread.filter((m) => m.from === 'santa').length;
      return { ok: true };
    });
  }],

  // восстановить доступ организатора по резервному коду
  ['POST', /^\/api\/games\/([a-z0-9]+)\/recover$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      const now = Date.now();
      if ((g.recoverLockedUntil || 0) > now) fail(429, 'Слишком много попыток. Попробуйте через 10 минут.');
      if (!g.recoveryHash || !safeEqual(sha256(normCode(body.code)), g.recoveryHash)) {
        g.recoverFails = (g.recoverFails || 0) + 1;
        if (g.recoverFails >= 5) { g.recoverFails = 0; g.recoverLockedUntil = now + 10 * 60 * 1000; }
        return { error: 'Неверный резервный код' };
      }
      g.recoverFails = 0;
      const adminKey = token();
      g.adminHash = sha256(adminKey);
      return { adminKey };
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
      const pairs = drawPairs(g.players.map((p) => p.id), g.exclusions);
      if (!pairs) fail(400, 'С такими исключениями распределить не получается. Уберите часть исключений.');
      g.pairs = pairs;
      g.players.forEach((p) => { p.seen = false; p.ready = false; p.readR = 0; p.readS = 0; });
      g.messages = {}; g.revealed = false;
      g.status = 'drawn';
      return adminGame(g);
    });
  }],

  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/reset$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      g.pairs = null; g.status = 'open'; g.messages = {}; g.revealed = false;
      g.players.forEach((p) => { p.seen = false; p.ready = false; p.readR = 0; p.readS = 0; });
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
      g.exclusions = (g.exclusions || []).filter(([a, b]) => a !== pid && b !== pid);
      return adminGame(g);
    });
  }],

  // исключения: эти двое не дарят друг другу
  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/exclusions$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (g.status !== 'open') fail(409, 'Исключения меняются только до жеребьёвки');
      const { a, b } = body;
      if (!a || !b || a === b || !g.players.some((p) => p.id === a) || !g.players.some((p) => p.id === b)) fail(400, 'Выберите двух разных участников');
      g.exclusions = g.exclusions || [];
      if (g.exclusions.some(([x, y]) => pairKey(x, y) === pairKey(a, b))) fail(409, 'Такое исключение уже есть');
      if (g.exclusions.length >= 200) fail(409, 'Слишком много исключений');
      g.exclusions.push([a, b]);
      return adminGame(g);
    });
  }],
  ['DELETE', /^\/api\/games\/([a-z0-9]+)\/admin\/exclusions\/([a-z0-9]+)\/([a-z0-9]+)$/, async (req, body, [id, a, b]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (g.status !== 'open') fail(409, 'Исключения меняются только до жеребьёвки');
      g.exclusions = (g.exclusions || []).filter(([x, y]) => pairKey(x, y) !== pairKey(a, b));
      return adminGame(g);
    });
  }],

  // финал: раскрыть или снова скрыть цепочку
  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/reveal$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      if (g.status !== 'drawn') fail(409, 'Сначала проведите жеребьёвку');
      g.revealed = body.revealed !== false;
      return adminGame(g);
    });
  }],

  // удалить игру целиком (подтверждение — названием игры)
  ['DELETE', /^\/api\/games\/([a-z0-9]+)\/admin$/, async (req, body, [id]) => {
    const g = await loadOr404(id);
    requireAdmin(g, req);
    await store.remove(id);
    return { ok: true };
  }],

  // новый резервный код организатора (старый перестаёт работать)
  ['POST', /^\/api\/games\/([a-z0-9]+)\/admin\/recovery$/, async (req, body, [id]) => {
    return mutate(id, (g) => {
      requireAdmin(g, req);
      const code = recoveryCode();
      g.recoveryHash = sha256(normCode(code));
      return { recoveryCode: code };
    });
  }],
];

/* ---------------- HTTP ---------------- */
function send(res, status, data, headers = {}) {
  const isBuf = Buffer.isBuffer(data), isStr = typeof data === 'string';
  const payload = isBuf || isStr ? data : JSON.stringify(data);
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
      if (size > 16 * 1024) { reject(new HttpError(413, 'Слишком большой запрос')); req.destroy(); return; }
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
    if (req.method === 'GET' && (p === '/' || /^\/g\/[a-z0-9]+(\/admin|\/poster)?\/?$/.test(p))) return send(res, 200, INDEX);
    if (req.method === 'GET' && p === '/healthz') return send(res, 200, { ok: true, store: store.kind });
    const qm = req.method === 'GET' && p.match(/^\/api\/games\/([a-z0-9]+)\/qr\.svg$/);
    if (qm) {
      await loadOr404(qm[1]);
      const proto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0];
      const base = process.env.RENDER_EXTERNAL_URL || `${proto}://${req.headers.host}`;
      return send(res, 200, toSvg(base.replace(/\/$/, '') + '/g/' + qm[1]), { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
    }
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

// Бесплатный Render засыпает после 15 минут без запросов. Пока сервис работает,
// в рабочие часы он сам себя «пингует» раз в 10 минут. Ночью засыпает, чтобы
// не тратить общий лимит бесплатных часов. KEEP_AWAKE=0 — выключить, KEEP_AWAKE_HOURS=9-21 — часы по Астане.
// автоочистка: раз в сутки удаляем игры без активности дольше 90 дней (CLEANUP_DAYS — изменить срок)
function scheduleCleanup() {
  const days = Number(process.env.CLEANUP_DAYS || 90);
  const run = () => store.cleanup(days).then((n) => { if (n) console.log(`cleanup: удалено старых игр: ${n}`); }).catch((e) => console.error('cleanup:', e.message));
  run();
  setInterval(run, 24 * 60 * 60 * 1000).unref();
}

function keepAwake() {
  const url = process.env.RENDER_EXTERNAL_URL;
  if (!url || process.env.KEEP_AWAKE === '0') return;
  const [from, to] = String(process.env.KEEP_AWAKE_HOURS || '9-21').split('-').map(Number);
  setInterval(() => {
    const h = (new Date().getUTCHours() + 5) % 24;
    if (h >= from && h < to) fetch(url.replace(/\/$/, '') + '/healthz').catch(() => {});
  }, 10 * 60 * 1000).unref();
  console.log(`keep-awake: ${from}:00–${to}:00 (Астана)`);
}

store.init()
  .then(() => server.listen(PORT, () => { console.log(`Secret Santa on :${PORT} (store: ${store.kind})`); keepAwake(); scheduleCleanup(); }))
  .catch((e) => { console.error('Не удалось подключиться к базе:', e.message); process.exit(1); });
