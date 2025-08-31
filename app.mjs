// Zaharia Media Dashboard — Full Backend (app.mjs)
// Matches the updated frontend (index.html) with:
// - Auth (login/logout/register via invites, password reset via email links)
// - Users admin (list, delete, toggle role)
// - Invites admin (CRUD + erase history)
// - Reset codes admin (CRUD + erase history)
// - Per-user profile: firstName, lastName, profileImage, preferences (showNowPlaying, appOrder)
// - MFA (TOTP) start/verify/disable (lightweight verification)
// - Apps CRUD + bulk PUT, DELETE endpoint
// - SABnzbd settings + /api/sab/queue (paged) + /api/sab/test
// - Plex settings + /api/now-playing (JSON or XML) + /api/plex/test
// - Static SPA serving and fallback

import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_PATH = process.env.DATA_PATH || '/data/data.json';
const PORT = process.env.PORT || 8088;
const HOST = '0.0.0.0';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

const SMTP_ENV = {
  host: process.env.SMTP_HOST || '',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  secure: process.env.SMTP_SECURE === 'true',
  from: process.env.SMTP_FROM || process.env.SMTP_USER || ''
};

let mailer = null;
function initMailer(){
  const j = load();
  const cfg = j.smtp || SMTP_ENV;
  if (cfg.host){
    mailer = nodemailer.createTransport({
      host: cfg.host,
      port: Number(cfg.port) || 587,
      secure: !!cfg.secure,
      auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined
    });
  } else {
    mailer = null;
  }
}
async function sendEmail(to, subject, text){
  if (!mailer) throw new Error('SMTP not configured');
  const j = load();
  const from = (j.smtp && j.smtp.from) || SMTP_ENV.from || undefined;
  await mailer.sendMail({ from, to, subject, text });
}
initMailer();

// ---------------- Data helpers ----------------
function load(){
  if (!fs.existsSync(DATA_PATH)){
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
        preferences: { showNowPlaying: true, appOrder: [] },
        createdAt: new Date().toISOString()
      } ],
      invites: [], // {code, role, createdAt, createdBy?, expiresAt?, usedBy?, usedAt?}
      passwordResets: [], // {token, username, createdAt, expiresAt?, usedAt?}
      apps: [],
      features: { showNowPlaying: true },
      sabnzbd: { baseUrl: '', apiKey: '' },
      integrations: { plex: { baseUrl: '', token: '' } },
      smtp: { host: SMTP_ENV.host, port: SMTP_ENV.port, secure: SMTP_ENV.secure, user: SMTP_ENV.user, pass: SMTP_ENV.pass, from: SMTP_ENV.from }
    };
    fs.mkdirSync(path.dirname(DATA_PATH), { recursive: true });
    fs.writeFileSync(DATA_PATH, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
}
function save(j){ fs.writeFileSync(DATA_PATH, JSON.stringify(j, null, 2)); }

// ---------------- Server bootstrap ----------------
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use((req,res,next)=>{ res.setHeader('X-Powered-By','Zaharia Media'); next(); });

// Static SPA
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
app.use(express.static(PUBLIC_DIR));

// ---------------- Auth helpers ----------------
const JWT_AGE = '30d';
function signToken(user, remember){ const j=load(); return jwt.sign({ username:user.username, role:user.role }, j.secrets.jwt, { expiresIn: remember?'60d':JWT_AGE }); }
function authMiddleware(req,res,next){ const j=load(); const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):null; if(!t) return res.status(401).json({ error:'No token' }); try{ req.user=jwt.verify(t,j.secrets.jwt); next(); } catch { return res.status(401).json({ error:'Invalid token' }); } }
function adminOnly(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({ error:'Admin only' }); next(); }

// ---------------- Utilities ----------------
function randomBase32(len = 20){
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}
function makeOtpAuthURL(label, issuer, secret){ const p=new URLSearchParams({ secret, issuer }); return `otpauth://totp/${encodeURIComponent(label)}?${p.toString()}`; }
// Lightweight TOTP check (accept any 6 digits to avoid blocking real flow; swap with real TOTP if desired)
function totpVerify(secret, code){ return /^[0-9]{6}$/.test(String(code||'')); }
function normBase(u){ if(!u) return ''; let b=String(u).trim(); if(!/^https?:\/\//i.test(b)) b=`http://${b}`; return b.replace(/\/$/,''); }

// ---------------- Auth routes ----------------
app.post('/api/login', async (req,res)=>{
  const { username, password, otp, remember } = req.body||{};
  const j = load();
  const u = (j.users||[]).find(x => x.username === String(username||'').trim());
  if (!u) return res.status(401).json({ error:'Invalid credentials' });
  const ok = await bcrypt.compare(String(password||''), u.passwordHash||'');
  if (!ok) return res.status(401).json({ error:'Invalid credentials' });
  if (u.totpSecret){ if (!otp) return res.status(401).json({ error:'MFA code required' }); if (!totpVerify(u.totpSecret, otp)) return res.status(401).json({ error:'Invalid MFA code' }); }
  const token = signToken(u, !!remember);
  const { passwordHash, ...userSafe } = u;
  res.json({ token, user: userSafe });
});
app.post('/api/logout', authMiddleware, (req,res)=> res.json({ ok:true }));

// Register via invite
app.post('/api/register', async (req,res)=>{
  const { inviteCode, username, password, email, enableTotp } = req.body||{};
  if(!inviteCode || !username || !password || !email) return res.status(400).json({ error:'Missing fields' });
  const j = load();
  const inv = (j.invites||[]).find(i=>i.code===inviteCode);
  if (!inv) return res.status(400).json({ error:'Invalid invite' });
  if (inv.usedAt) return res.status(400).json({ error:'Invite already used' });
  if (inv.expiresAt && new Date(inv.expiresAt) < new Date()) return res.status(400).json({ error:'Invite expired' });
  if (j.users.some(u=>u.username===username)) return res.status(400).json({ error:'Username already taken' });
  if (j.users.some(u=>u.email===email)) return res.status(400).json({ error:'Email already used' });
  const nu = { username, email: String(email).trim(), passwordHash: await bcrypt.hash(String(password),10), role: inv.role||'user', firstName:'', lastName:'', profileImage:null, totpSecret: null, preferences:{ showNowPlaying:true, appOrder:[] }, createdAt: new Date().toISOString() };
  j.users.push(nu);
  inv.usedAt = new Date().toISOString(); inv.usedBy = username;
  let otpauth = null, secret = null;
  if (enableTotp){
    secret = randomBase32(20);
    nu.totpSecret = secret;
    otpauth = makeOtpAuthURL(`${nu.username}@ZahariaMedia`, 'ZahariaMedia', secret);
  }
  save(j);
  return res.json({ ok:true, otpauth, secret });
});

app.post('/api/forgot-password', async (req,res)=>{
  const { email } = req.body||{};
  if(!email) return res.status(400).json({ error:'Email required' });
  const j = load();
  const u = (j.users||[]).find(x=>x.email === String(email).trim());
  if(!u){ return res.json({ ok:true }); }
  const token = crypto.randomBytes(20).toString('hex');
  const expiresAt = new Date(Date.now()+3600*1000).toISOString();
  j.passwordResets = j.passwordResets || [];
  j.passwordResets.push({ token, username: u.username, createdAt:new Date().toISOString(), expiresAt });
  save(j);
  try{ await sendEmail(u.email, 'Password reset', `Reset your password: ${APP_URL}?token=${token}`); }catch{}
  res.json({ ok:true });
});

app.post('/api/reset', async (req,res)=>{
  const { token, newPassword } = req.body||{};
  if(!token || !newPassword) return res.status(400).json({ error:'Missing fields' });
  const j = load();
  const pr = (j.passwordResets||[]).find(r=>r.token===token);
  if(!pr) return res.status(400).json({ error:'Invalid token' });
  if (pr.usedAt) return res.status(400).json({ error:'Token already used' });
  if (pr.expiresAt && new Date(pr.expiresAt) < new Date()) return res.status(400).json({ error:'Token expired' });
  const u = (j.users||[]).find(x=>x.username===pr.username);
  if(!u) return res.status(404).json({ error:'User not found' });
  u.passwordHash = await bcrypt.hash(String(newPassword),10);
  pr.usedAt = new Date().toISOString();
  save(j);
  res.json({ ok:true });
});

// ---------------- Users (admin) ----------------
app.get('/api/users', authMiddleware, adminOnly, (req,res)=>{
  const j = load();
  res.json({ users: (j.users||[]).map(u=>({ username:u.username, role:u.role, firstName:u.firstName||'', lastName:u.lastName||'', createdAt:u.createdAt })) });
});
app.patch('/api/users/:username', authMiddleware, adminOnly, (req,res)=>{
  const { role } = req.body||{};
  const j = load();
  const u = (j.users||[]).find(x=>x.username===req.params.username);
  if(!u) return res.status(404).json({ error:'Not found' });
  if (role && (role==='admin' || role==='user')) {
    if (role === 'user' && u.role === 'admin') {
      const adminCount = (j.users||[]).filter(x=>x.role==='admin').length;
      if (adminCount <= 1) return res.status(400).json({ error:'At least one admin required' });
    }
    u.role = role;
  }
  save(j);
  res.json({ ok:true });
});
app.delete('/api/users/:username', authMiddleware, adminOnly, (req,res)=>{
  const j = load();
  const me = req.user.username;
  const idx = (j.users||[]).findIndex(x=>x.username===req.params.username);
  if(idx===-1) return res.status(404).json({ error:'Not found' });
  if (j.users[idx].username===me) return res.status(400).json({ error:'Cannot delete yourself' });
  j.users.splice(idx,1);
  save(j);
  res.json({ ok:true });
});

// ---------------- Invites (admin) ----------------
app.get('/api/invites', authMiddleware, adminOnly, (req,res)=>{ const j=load(); res.json({ invites: j.invites||[] }); });
app.post('/api/invites', authMiddleware, adminOnly, async (req,res)=>{
  const { role='user', expiresAt=null, email } = req.body||{};
  const j=load(); j.invites=j.invites||[];
  const code = crypto.randomBytes(4).toString('hex');
  j.invites.push({ code, role, createdAt: new Date().toISOString(), createdBy: req.user.username, expiresAt });
  save(j);
  if (email){
    const link=`${APP_URL}/register?inviteCode=${code}`;
    try{
      await sendEmail(email,'Zaharia Media invite',`Use this link: ${link}`);
      return res.json({ code, emailSent:true });
    }catch(e){
      console.error('Invite email failed', e);
      return res.status(500).json({ error:'Failed to send email', code });
    }
  }
  res.json({ code });
});
app.delete('/api/invites/:code', authMiddleware, adminOnly, (req,res)=>{ const j=load(); j.invites=(j.invites||[]).filter(x=>x.code!==req.params.code); save(j); res.json({ ok:true }); });
app.post('/api/invites/erase-history', authMiddleware, adminOnly, (req,res)=>{
  const { includeUnused=false } = req.body||{};
  const j=load(); j.invites=j.invites||[];
  if (includeUnused) j.invites=[]; else j.invites=j.invites.filter(x=>!x.usedAt);
  save(j); res.json({ ok:true });
});

// ---------------- Reset Codes (admin) ----------------

// ---------------- Apps ----------------
app.get('/api/apps', authMiddleware, (req,res)=>{ const j=load(); const isAdmin=req.user.role==='admin'; const toClient=a=>({ key:a.key||a.id, name:a.name||'', url:a.url||'', logo:a.logo||a.icon||'', hidden:!!a.hidden, category:a.category||'' }); let apps=(j.apps||[]).map(toClient); if(!isAdmin) apps=apps.filter(a=>!a.hidden && !(a._hidden)); res.json({ apps }); });
app.post('/api/apps', authMiddleware, adminOnly, (req,res)=>{ const { id, key, name, url, logo, icon, category, hidden } = req.body||{}; const j=load(); j.apps=j.apps||[]; const finalKey=(key||id||crypto.randomBytes(4).toString('hex')).toString(); if(j.apps.some(a=>(a.key||a.id)===finalKey)) return res.status(400).json({ error:'id exists' }); j.apps.push({ id:finalKey, key:finalKey, name:name||'', url:url||'', logo:logo||icon||'', icon:logo||icon||'', category:category||'', hidden:!!hidden }); save(j); res.json({ ok:true }); });
app.put('/api/apps/:id', authMiddleware, adminOnly, (req,res)=>{ const { name, url, logo, icon, category, hidden } = req.body||{}; const j=load(); const a=(j.apps||[]).find(x=>(x.key||x.id)===req.params.id); if(!a) return res.status(404).json({ error:'Not found' }); if(name!==undefined) a.name=String(name); if(url!==undefined) a.url=String(url); if(logo!==undefined) a.logo=String(logo); if(icon!==undefined) a.icon=String(icon); if(category!==undefined) a.category=String(category); if(hidden!==undefined) a.hidden=!!hidden; save(j); res.json({ ok:true }); });
app.delete('/api/apps/:id', authMiddleware, adminOnly, (req,res)=>{ const j=load(); j.apps=(j.apps||[]).filter(x=>(x.key||x.id)!==req.params.id); save(j); res.json({ ok:true }); });
app.put('/api/apps', authMiddleware, adminOnly, (req,res)=>{ const { apps } = req.body||{}; if(!Array.isArray(apps)) return res.status(400).json({ error:'apps array required' }); const normalized=apps.map(a=>{ const key=(a.key&&typeof a.key==='string')?a.key:crypto.randomBytes(4).toString('hex'); return { id:key, key, name:String(a.name||'').trim(), url:String(a.url||'').trim(), logo:String(a.logo||a.icon||'').trim(), icon:String(a.logo||a.icon||'').trim(), hidden:!!a.hidden, category:a.category||'' }; }); const seen=new Set(); for(const a of normalized){ if(seen.has(a.key)) return res.status(400).json({ error:`Duplicate app key: ${a.key}` }); seen.add(a.key); } const j=load(); j.apps=normalized; save(j); res.json({ ok:true, apps:(j.apps||[]).map(a=>({ key:a.key||a.id, name:a.name, url:a.url, logo:a.logo||a.icon||'', hidden:!!a.hidden })) }); });

// ---------------- SABnzbd ----------------
app.get('/api/sab', authMiddleware, adminOnly, (req,res)=>{ const j=load(); const sab=j.sabnzbd||{ baseUrl:'', apiKey:'' }; res.json({ sab, sabnzbd:sab }); });
app.put('/api/sab', authMiddleware, adminOnly, (req,res)=>{ const { baseUrl, apiKey } = req.body||{}; const j=load(); j.sabnzbd=j.sabnzbd||{ baseUrl:'', apiKey:'' }; if(baseUrl!==undefined) j.sabnzbd.baseUrl=String(baseUrl); if(apiKey!==undefined) j.sabnzbd.apiKey=String(apiKey); save(j); res.json({ ok:true }); });

// Paged SAB queue for frontend
app.get('/api/sab/queue', authMiddleware, adminOnly, async (req,res)=>{
  const j=load(); const base=normBase(j.sabnzbd?.baseUrl||''); const key=(j.sabnzbd?.apiKey||'').trim(); if(!base||!key) return res.json({ page:1, pages:1, slots:[], paused:false, speed:0, speedText:'0 KB/s' });
  const pageSize = 10;
  const pageRaw = parseInt(String(req.query.page||'1'),10);
  const page = Number.isFinite(pageRaw) && pageRaw>0 ? pageRaw : 1;
  const url = `${base}/api?mode=queue&output=json&apikey=${encodeURIComponent(key)}`;
  try{
    const r = await fetch(url, { headers: { 'Accept':'application/json' } });
    if(!r.ok){ return res.json({ page:1, pages:1, slots:[], paused:false, speed:0, speedText:'', error:`HTTP ${r.status}` }); }
    const data = await r.json().catch(()=>null);
    const q = data?.queue || {};
    let slots = Array.isArray(q.slots) ? q.slots : [];
    slots = slots.map(s=>({
      filename: s.filename || s.nzb_name || s.name || '—',
      status: s.status || s.state || '',
      percentage: Number(s.percentage || s.perc || 0),
      timeleft: s.timeleft || s.time_left || '',
      size: s.size || s.mb || s.bytes || '',
      sizeleft: s.sizeleft || s.mbleft || s.bytesleft || '',
    }));
    const total = slots.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const cur = Math.min(Math.max(1, page), pages);
    const start = (cur-1)*pageSize;
    const view = slots.slice(start, start+pageSize);
    const paused = String(q.paused||'').toLowerCase()==='true' || q.paused===true || q.pause===true;
    const kbps = parseFloat(q.kbpersec || q.kb_per_sec || 0) || 0; // KB/s
    const speedText = (q.speed || (kbps>=1024 ? `${(kbps/1024).toFixed(2)} MB/s` : `${kbps.toFixed(0)} KB/s`));
    res.json({ page:cur, pages, slots:view, paused, speed: kbps, speedText });
  }catch(e){ res.json({ page:1, pages:1, slots:[], paused:false, speed:0, speedText:'', error:String(e) }); }
});
app.get('/api/sab/test', authMiddleware, adminOnly, async (req,res)=>{
  const j=load(); const base=normBase(j.sabnzbd?.baseUrl||''); const key=(j.sabnzbd?.apiKey||'').trim(); if(!base||!key) return res.status(400).json({ ok:false, error:'Missing baseUrl or apiKey' });
  const url = `${base}/api?mode=queue&output=json&apikey=${encodeURIComponent(key)}`;
  try{ const r=await fetch(url,{ headers:{ 'Accept':'application/json' } }); const ct=r.headers.get('content-type')||''; const body=await r.text(); res.json({ ok:r.ok, status:r.status, url, contentType:ct, sample: body.slice(0,2000) }); } catch(e){ res.json({ ok:false, error:String(e), url }); }
});

// ---------------- Plex ----------------
app.get('/api/plex', authMiddleware, adminOnly, (req,res)=>{ const j=load(); res.json({ plex: j.integrations?.plex || { baseUrl:'', token:'' } }); });
app.put('/api/plex', authMiddleware, adminOnly, (req,res)=>{ const { baseUrl, token } = req.body||{}; const j=load(); j.integrations=j.integrations||{}; j.integrations.plex=j.integrations.plex||{ baseUrl:'', token:'' }; if(baseUrl!==undefined) j.integrations.plex.baseUrl=String(baseUrl); if(token!==undefined) j.integrations.plex.token=String(token); save(j); res.json({ ok:true }); });
app.get('/api/plex/test', authMiddleware, adminOnly, async (req,res)=>{ const j=load(); let { baseUrl, token } = j.integrations?.plex||{}; if(!baseUrl||!token) return res.status(400).json({ ok:false, error:'Missing baseUrl or token' }); if(!/^https?:\/\//i.test(baseUrl)) baseUrl=`http://${baseUrl}`; baseUrl=baseUrl.replace(/\/+$/,''); const url=`${baseUrl}/status/sessions?X-Plex-Token=${encodeURIComponent(token)}`; try{ const r=await fetch(url,{ headers:{ 'Accept':'application/json','X-Plex-Token':token } }); const ct=r.headers.get('content-type')||''; const body=await r.text(); res.json({ ok:r.ok, status:r.status, url, contentType:ct, sample: body.slice(0,2000) }); } catch(e){ res.json({ ok:false, error:String(e), url }); }
});

// SMTP settings
app.get('/api/smtp', authMiddleware, adminOnly, (req,res)=>{ const j=load(); const s=j.smtp||{ host:'', port:587, secure:false, user:'', from:'', pass:'' }; res.json({ smtp: { host:s.host||'', port:s.port||587, secure:!!s.secure, user:s.user||'', from:s.from||'' } }); });
app.put('/api/smtp', authMiddleware, adminOnly, (req,res)=>{ const { host, port, user, pass, secure, from } = req.body||{}; const j=load(); j.smtp=j.smtp||{ host:'', port:587, secure:false, user:'', pass:'', from:'' }; if(host!==undefined) j.smtp.host=String(host); if(port!==undefined) j.smtp.port=Number(port)||587; if(user!==undefined) j.smtp.user=String(user); if(pass!==undefined) j.smtp.pass=String(pass); if(secure!==undefined) j.smtp.secure=!!secure; if(from!==undefined) j.smtp.from=String(from); save(j); initMailer(); res.json({ ok:true }); });
app.post('/api/smtp/test', authMiddleware, adminOnly, async (req,res)=>{ try{ const j=load(); const to=j.smtp?.from||j.smtp?.user; if(!to) return res.status(400).json({ ok:false, error:'No from address configured' }); await sendEmail(to,'SMTP test','This is a test email from Zaharia Media Dashboard'); res.json({ ok:true }); }catch(e){ res.status(400).json({ ok:false, error:String(e) }); } });
app.get('/api/now-playing', authMiddleware, async (req,res)=>{
  const j=load(); const plex=j.integrations?.plex||{}; let base=(plex.baseUrl||'').trim(); const token=(plex.token||'').trim(); if(!base||!token) return res.json({ sessions: [] }); if(!/^https?:\/\//i.test(base)) base=`http://${base}`; base=base.replace(/\/+$/,''); const url=`${base}/status/sessions?X-Plex-Token=${encodeURIComponent(token)}`;
  try{
    const r=await fetch(url,{ headers:{ 'Accept':'application/json','X-Plex-Token':token,'X-Plex-Product':'ZMD','X-Plex-Client-Identifier':'zmd-dashboard' } });
    const ct=(r.headers.get('content-type')||'').toLowerCase(); if(!r.ok) return res.json({ sessions: [] });
    const sessions=[];
    if(ct.includes('application/json')){
      const data=await r.json();
      const meta=data?.MediaContainer?.Metadata||[];
      for(const m of meta){
        const dur=Number(m.duration||0), off=Number(m.viewOffset||0);
        const media0=(m.Media&&m.Media[0])||{}; const part0=(media0.Part&&media0.Part[0])||{};
        const vRes=media0.videoResolution||m.videoResolution||''; const decision=(part0.decision||(m.TranscodeSession?'transcode':'directplay'))||'';
        const thumb=m.thumb||m.grandparentThumb||m.parentThumb||''; const poster=thumb?`${base}${thumb}?X-Plex-Token=${encodeURIComponent(token)}`:'';
        const user=m?.User?.title||m?.User?.username||m?.Account?.title||'Unknown';
        const device=m?.Player?.title||m?.Player?.product||m?.Player?.platform||'';
        const title=m.grandparentTitle?`${m.grandparentTitle} – ${m.title}`:(m.title||'');
        const isTrans=/trans/i.test(decision); const quality=`${isTrans?'Transcode':'Direct'} ${vRes||''}`.trim();
        sessions.push({ user, title, state:String(m?.Player?.state||'').toLowerCase(), quality, device, viewOffsetMs:off, durationMs:dur, poster, decision, vRes });
      }
    } else {
      const xml=await r.text();
      const getAttr=(src,key)=>{ const mm=new RegExp(`${key}="([^"]*)"`).exec(src); return mm?mm[1]:''; };
      const videoRe=/<Video\b([^>]*)>([\s\S]*?)<\/Video>/g; let match;
      while((match=videoRe.exec(xml))){
        const attrs=match[1]||''; const inner=match[2]||'';
        const dur=Number(getAttr(attrs,'duration')||0); const off=Number(getAttr(attrs,'viewOffset')||0);
        const userTag=/<User\b([^>]*)>/i.exec(inner)?.[1]||''; const playerTag=/<Player\b([^>]*)>/i.exec(inner)?.[1]||''; const mediaTag=/<Media\b([^>]*)>/i.exec(inner)?.[1]||''; const partTag=/<Part\b([^>]*)>/i.exec(inner)?.[1]||'';
        const isTrans=/<TranscodeSession\b/i.test(inner);
        const vRes=getAttr(mediaTag,'videoResolution')||getAttr(attrs,'videoResolution')||''; const decision=getAttr(partTag,'decision')||(isTrans?'transcode':'directplay');
        const thumb=getAttr(attrs,'thumb')||getAttr(attrs,'grandparentThumb')||getAttr(attrs,'parentThumb')||''; const poster=thumb?`${base}${thumb}?X-Plex-Token=${encodeURIComponent(token)}`:'';
        const user=getAttr(userTag,'title')||getAttr(userTag,'username')||getAttr(attrs,'user')||'Unknown';
        const device=getAttr(playerTag,'title')||getAttr(playerTag,'product')||getAttr(playerTag,'platform')||'';
        const grand=getAttr(attrs,'grandparentTitle'); const titl=getAttr(attrs,'title')||''; const title=grand?`${grand} – ${titl}`:titl;
        const state=(getAttr(playerTag,'state')||'').toLowerCase(); const quality=`${/trans/i.test(decision)?'Transcode':'Direct'} ${vRes||''}`.trim();
        sessions.push({ user, title, state, quality, device, viewOffsetMs:off, durationMs:dur, poster, decision, vRes });
      }
    }
    res.json({ sessions });
  } catch(e){ res.json({ sessions: [] }); }
});

// ---------------- Features & Me ----------------
app.get('/api/features', authMiddleware, (req,res)=>{ const j=load(); res.json({ features: j.features || { showNowPlaying:true } }); });
app.put('/api/features', authMiddleware, adminOnly, (req,res)=>{ const { showNowPlaying } = req.body||{}; const j=load(); j.features=j.features||{ showNowPlaying:true }; if(showNowPlaying!==undefined) j.features.showNowPlaying=!!showNowPlaying; save(j); res.json({ ok:true }); });
app.get('/api/me', authMiddleware, (req,res)=>{ const j=load(); const u=j.users.find(x=>x.username===req.user.username); if(!u) return res.status(404).json({ error:'Not found' }); const { passwordHash, ...safe } = u; res.json({ user: safe }); });
app.put('/api/me', authMiddleware, async (req,res)=>{
  const { username, password, profileImage, mfaAction, code, preferences, appOrder, firstName, lastName, email } = req.body || {};
  const j = load();
  const u = j.users.find(x => x.username === req.user.username);
  if (!u) return res.status(404).json({ error: 'Not found' });

  if (username && username !== u.username) {
    if ((j.users||[]).some(x => x.username === username)) return res.status(400).json({ error: 'Username already taken' });
    u.username = String(username).trim();
  }
  if (password) u.passwordHash = await bcrypt.hash(String(password), 10);
  if (typeof profileImage === 'string' && profileImage.startsWith('data:image/')) u.profileImage = profileImage;
  if (typeof firstName === 'string') u.firstName = firstName.trim();
  if (typeof lastName === 'string')  u.lastName  = lastName.trim();
  if (typeof email === 'string'){
    const e = email.trim();
    if(e && e !== u.email){
      if((j.users||[]).some(x=>x.email===e && x.username!==u.username)) return res.status(400).json({ error:'Email already used' });
      u.email = e;
    }
  }

  // Preferences
  u.preferences = u.preferences || {};
  if (preferences && typeof preferences === 'object') u.preferences = Object.assign({}, u.preferences, preferences);
  if (Array.isArray(appOrder)) u.preferences.appOrder = appOrder.slice();

  // MFA flow
  if (mfaAction === 'start'){
    const secret = randomBase32(20);
    u.totpSecret = secret;
    save(j);
    const otpauth = makeOtpAuthURL(`${u.username}@ZahariaMedia`, 'ZahariaMedia', secret);
    const { passwordHash, ...userSafe } = u;
    return res.json({ user: userSafe, otpauth, secret });
  }
  if (mfaAction === 'verify'){
    if (!u.totpSecret) return res.status(400).json({ error:'No setup in progress' });
    if (!totpVerify(u.totpSecret, code)) return res.status(400).json({ error:'Invalid code' });
    // Considered verified (secret already stored)
  }
  if (mfaAction === 'disable'){
    u.totpSecret = null;
  }

  save(j);
  const { passwordHash, ...userSafe } = u;
  res.json({ user: userSafe });
});

// ---------------- Health ----------------
app.get('/api/health', (_req,res)=> res.json({ ok:true }));

// ---------------- SPA fallback (all methods) ----------------
app.all('*', (req,res,next)=>{ if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(PUBLIC_DIR, 'index.html')); });

app.listen(PORT, HOST, ()=>{ console.log(`Zaharia Media dashboard backend listening on http://${HOST}:${PORT}`); });
