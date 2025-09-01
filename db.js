// SQLite persistence implemented using sql.js (WASM)
import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const DB_PATH = process.env.DB_PATH || '/data/data.sqlite';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const SQL = await initSqlJs();
let db;
if (fs.existsSync(DB_PATH)) {
  const fileBuffer = fs.readFileSync(DB_PATH);
  db = new SQL.Database(fileBuffer);
} else {
  db = new SQL.Database();
}

db.run('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);');

function persist(){
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function init(smtpEnv){
  const stmt = db.prepare('SELECT value FROM kv WHERE key=?');
  stmt.bind(['data']);
  const hasRow = stmt.step();
  stmt.free();
  if(!hasRow){
    const initial = {
      secrets: { jwt: crypto.randomBytes(32).toString('hex') },
      users: [ {
        username: 'admin',
        passwordHash: bcrypt.hashSync('admin123', 10),
        role: 'admin',
        email: '',
        firstName: '',
        lastName: '',
        profileImage: null,
        totpSecret: null,
        failedLogins: 0,
        lockedUntil: null,
        lastLoginAt: null,
        preferences: { showNowPlaying: true, appOrder: [], theme: 'dark' },
        createdAt: new Date().toISOString()
      } ],
      invites: [],
      passwordResets: [],
      apps: [],
      features: { showNowPlaying: true },
      sabnzbd: { baseUrl: '', apiKey: '' },
      integrations: { plex: { baseUrl: '', token: '' } },
      smtp: {
        host: smtpEnv.host,
        port: smtpEnv.port,
        secure: smtpEnv.secure,
        user: smtpEnv.user,
        pass: smtpEnv.pass,
        from: smtpEnv.from
      },
      audit: []
    };
    save(initial);
  }
}

function load(){
  const stmt = db.prepare('SELECT value FROM kv WHERE key=?');
  stmt.bind(['data']);
  let result = {};
  if (stmt.step()) result = JSON.parse(stmt.getAsObject().value);
  stmt.free();
  return result;
}

function save(j){
  const stmt = db.prepare('INSERT OR REPLACE INTO kv (key,value) VALUES (?,?)');
  stmt.run(['data', JSON.stringify(j, null, 2)]);
  stmt.free();
  persist();
}

export { init, load, save, DB_PATH };

