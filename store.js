'use strict';
// Хранилище игр: одна запись JSON на игру.
// Если задан DATABASE_URL — PostgreSQL, иначе память (только для локальной разработки).

function createMemoryStore() {
  const games = new Map();
  const locks = new Map();
  const clone = (v) => (v == null ? v : JSON.parse(JSON.stringify(v)));

  return {
    kind: 'memory',
    async init() {},
    async create(game) {
      if (games.has(game.id)) throw new Error('duplicate id');
      games.set(game.id, clone(game));
    },
    async get(id) {
      return clone(games.get(id));
    },
    // fn(game) может изменить игру и вернуть результат; изменения сохраняются атомарно
    async update(id, fn) {
      const prev = locks.get(id) || Promise.resolve();
      let release;
      const next = new Promise((r) => (release = r));
      locks.set(id, prev.then(() => next));
      await prev;
      try {
        const game = clone(games.get(id));
        if (!game) return { notFound: true };
        const result = await fn(game);
        games.set(id, clone(game));
        return { result };
      } finally {
        release();
      }
    },
  };
}

function createPgStore(url) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, max: 5, idleTimeoutMillis: 30000 });
  pool.on('error', (err) => console.error('pg pool error', err.message));

  return {
    kind: 'postgres',
    async init() {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS santa_games (
          id         text PRIMARY KEY,
          data       jsonb NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        )`);
    },
    async create(game) {
      await pool.query('INSERT INTO santa_games (id, data) VALUES ($1, $2)', [game.id, game]);
    },
    async get(id) {
      const r = await pool.query('SELECT data FROM santa_games WHERE id = $1', [id]);
      return r.rows[0] ? r.rows[0].data : null;
    },
    async update(id, fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query('SELECT data FROM santa_games WHERE id = $1 FOR UPDATE', [id]);
        if (!r.rows[0]) {
          await client.query('ROLLBACK');
          return { notFound: true };
        }
        const game = r.rows[0].data;
        const result = await fn(game);
        await client.query('UPDATE santa_games SET data = $2, updated_at = now() WHERE id = $1', [id, game]);
        await client.query('COMMIT');
        return { result };
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
  };
}

module.exports = function createStore() {
  const url = process.env.DATABASE_URL;
  return url ? createPgStore(url) : createMemoryStore();
};
