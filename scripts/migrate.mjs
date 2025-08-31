import fs from 'fs';
import path from 'path';
import initSqlJs from 'sql.js';

const JSON_PATH = process.env.DATA_PATH || '/data/data.json';
const DB_PATH = process.env.DB_PATH || '/data/data.sqlite';

if (!fs.existsSync(JSON_PATH)) {
  console.log('No JSON data found at', JSON_PATH);
  process.exit(0);
}

const json = JSON.parse(fs.readFileSync(JSON_PATH, 'utf8'));
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const SQL = await initSqlJs();
const db = fs.existsSync(DB_PATH)
  ? new SQL.Database(fs.readFileSync(DB_PATH))
  : new SQL.Database();
db.run('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);');
const stmt = db.prepare('INSERT OR REPLACE INTO kv (key,value) VALUES (?,?)');
stmt.run(['data', JSON.stringify(json, null, 2)]);
stmt.free();
fs.writeFileSync(DB_PATH, Buffer.from(db.export()));

console.log(`Migrated ${JSON_PATH} to ${DB_PATH}`);

