const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Secret used to sign tokens. Set JWT_SECRET in the environment for production;
// the fallback only keeps local dev working.
const JWT_SECRET = process.env.JWT_SECRET || 'medsecure-dev-secret';

const app = express();
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()) : true,
  // Cross-origin JS can only read a custom response header when it is exposed.
  exposedHeaders: ['X-API-Key']
}));
app.use(express.json({ limit: '2mb' }));

// --- Mandatory API key ------------------------------------------------------
// Every API endpoint requires an `X-API-Key` header. The key is just the base64
// encoding of the caller's username, so it is constant per user:
//   apollo.admin -> YXBvbGxvLmFkbWlu      apollo.patient -> YXBvbGxvLnBhdGllbnQ=
// The server decodes it and proceeds only when the decoded value matches a
// username in the data store. No key -> 401 "API key is missing"; unreadable or
// unknown username -> 403 "API key is wrong".
// /api/signin is exempt: it takes only username + password, and a caller
// has no key to present until it answers. A successful login echoes the
// caller's key back in the X-API-Key response header, so a client reads it
// there and sends it on every later request.
const API_KEY_HEADER = 'x-api-key';
const apiKeyForUsername = username => Buffer.from(String(username), 'utf8').toString('base64');
// Sign-in issues the key, so it cannot require one. Swagger UI and the raw spec
// are plain browser assets - the page cannot attach a header to its own
// bootstrap request - so the docs stay open too.
const API_KEY_EXEMPT = new Set(['/api/signin', '/api/docs', '/api/openapi.yaml']);

// Buffer's base64 decoder silently drops invalid characters, so re-encode the
// result and compare: that is what actually rejects a non-base64 header.
// Padding and base64url (-_) spellings are both accepted.
function decodeApiKey(raw) {
  const s = String(raw).trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const decoded = Buffer.from(s, 'base64').toString('utf8');
  const strip = v => v.replace(/=+$/, '');
  if (!decoded || strip(Buffer.from(decoded, 'utf8').toString('base64')) !== strip(s)) return null;
  return decoded;
}

function apiKeyGate(req, res, next) {
  // CORS preflight carries no custom headers, so it must never be gated.
  if (req.method === 'OPTIONS') return next();
  if (!req.path.startsWith('/api/') || API_KEY_EXEMPT.has(req.path)) return next();
  const raw = req.headers[API_KEY_HEADER];
  if (!raw || !String(raw).trim()) return res.status(401).json({ error: 'API key is missing' });
  const username = decodeApiKey(raw);
  const user = username && read().users.find(u => u.username === username);
  if (!user) return res.status(403).json({ error: 'API key is wrong' });
  req.apiKeyUser = user;
  next();
}
// --- Inbound source IP logging ----------------------------------------------
// Logs the source IP of every request, on every endpoint, so a caller's egress
// address is visible in the Render log stream. Registered ahead of the API key
// gate so rejected requests are recorded too.
//
// Only req.socket.remoteAddress is a fact - it is the peer we actually
// completed a handshake with. Every X-Forwarded-For entry is a *claim* by the
// hop to its right, so the leftmost entry is whatever the caller chose to send
// and must never be trusted. Counting in from the right skips the proxies we
// operate and stops at the first address none of them vouched for. Render
// terminates TLS at its edge, so in that environment there is at least one hop.
// Measured from production logs, not guessed: a real request arrives as
// <caller> <- <Cloudflare edge> <- <Render proxy> <- 127.0.0.1, so three hops
// in front of this app are ours. The allow list below depends on this being
// right - at 1 the derived caller is Render's own proxy and a short, spoofed
// X-Forwarded-For would satisfy the list.
const TRUSTED_PROXY_HOPS = Number.parseInt(process.env.TRUSTED_PROXY_HOPS || '3', 10);
// Node reports IPv4 peers on a dual-stack socket as ::ffff:a.b.c.d.
const normalizeIp = ip => String(ip || '').replace(/^::ffff:/i, '').trim();

// Headers a fronting CDN sets to name the original caller outright. Cloudflare
// runs in front of this service on Render, so cf-connecting-ip is usually the
// straight answer and needs no hop arithmetic. It is only worth trusting
// because nothing reaches this app without crossing that edge first - a caller
// speaking to the origin directly could invent any of these headers.
const CDN_CALLER_HEADERS = ['cf-connecting-ip', 'true-client-ip', 'x-real-ip'];

function describeCaller(req) {
  const raw = req.headers['x-forwarded-for'];
  const forwarded = (Array.isArray(raw) ? raw.join(',') : raw || '')
    .split(',').map(normalizeIp).filter(Boolean);
  const chain = [...forwarded, normalizeIp(req.socket.remoteAddress)];
  const index = chain.length - 1 - TRUSTED_PROXY_HOPS;
  const cdnHeaders = {};
  for (const h of CDN_CALLER_HEADERS) if (req.headers[h]) cdnHeaders[h] = normalizeIp(req.headers[h]);
  const cdnKey = CDN_CALLER_HEADERS.find(h => cdnHeaders[h]);
  return {
    callerIP: chain[Math.max(index, 0)],
    trustworthy: index >= 0,
    cdnReportedIP: cdnKey ? cdnHeaders[cdnKey] : null,
    cdnHeaders,
    hopChain: chain,
    xForwardedFor: forwarded.length ? forwarded.join(', ') : null,
    trustedProxyHops: TRUSTED_PROXY_HOPS,
    // What each possible hop count would have yielded. This removes the
    // guesswork from tuning TRUSTED_PROXY_HOPS: find your own public address in
    // this table and the number beside it is the value to set.
    ifTrustedProxyHopsWere: Object.fromEntries(chain.map((_, n) => [n, chain[chain.length - 1 - n]]))
  };
}

app.use((req, res, next) => {
  // Stashed so the block list below reads the same verdict this line reports.
  const c = req.caller = describeCaller(req);
  // Method and path only. Request bodies carry patient data and must never be
  // written to a log stream.
  const parts = [`[inbound] ${req.method} ${req.originalUrl}`, `caller IP: ${c.callerIP}`];
  if (c.cdnReportedIP) {
    parts.push(`Cloudflare says: ${c.cdnReportedIP}` +
      (c.cdnReportedIP === c.callerIP ? ' (agrees)' : ' (DISAGREES - fix TRUSTED_PROXY_HOPS)'));
  }
  parts.push(`hops: ${c.hopChain.length > 1 ? c.hopChain.join(' <- ') : 'direct, no X-Forwarded-For'}`);
  if (!c.trustworthy) parts.push('WARNING: fewer hops than TRUSTED_PROXY_HOPS, caller IP is NOT trustworthy');
  console.log(parts.join(' | '));
  next();
});

// --- Allowed source IPs (allow list) ----------------------------------------
// The API is closed by default: every request is refused unless the caller's
// address is on this list. Seeded below and extended at deploy time through a
// comma-separated ALLOWED_IPS environment variable, so access can be granted or
// withdrawn without a code change. Registered ahead of the API key gate, so a
// caller that is not on the list never reaches authentication or patient data.
//
// This is the inverse of a block list, and the difference matters: a block list
// that fails to identify the caller lets them through, while an allow list that
// fails to identify them must refuse. So it fails closed.
//
// Only the two fields we treat as the caller are matched: the hop-derived
// callerIP, and the one a fronting CDN names outright. X-Forwarded-For entries
// further left are the caller's own claim and are never matched - honouring
// them would let anyone write themselves onto the list.
//
// callerIP counts only when the hop chain is long enough for TRUSTED_PROXY_HOPS
// to mean something. On a short chain describeCaller falls back to the leftmost
// X-Forwarded-For entry, which is precisely the value a caller controls, so an
// untrustworthy chain is refused rather than guessed at.
//
// Standing caveat: cf-connecting-ip is only meaningful because traffic reaches
// this app through Cloudflare. Anyone who can talk to the Render origin directly
// can invent that header, so this list is only as strong as that assumption.
const ALLOWED_IPS = new Set([
  // The addresses permitted to reach the API.
  '51.81.125.179',
  '40.160.10.27',
  ...String(process.env.ALLOWED_IPS || '').split(',').map(normalizeIp).filter(Boolean)
]);

app.use((req, res, next) => {
  const c = req.caller;
  const candidates = [];
  if (c.trustworthy) candidates.push(c.callerIP);
  if (c.cdnReportedIP) candidates.push(c.cdnReportedIP);
  if (candidates.some(ip => ALLOWED_IPS.has(ip))) return next();
  const parts = [
    `[blocked] ${req.method} ${req.originalUrl}`,
    `IP ${c.cdnReportedIP || c.callerIP} tried to access the app and was refused: not on the allow list`,
    `caller IP: ${c.callerIP}`
  ];
  if (c.cdnReportedIP) parts.push(`Cloudflare says: ${c.cdnReportedIP}`);
  parts.push(`hops: ${c.hopChain.length > 1 ? c.hopChain.join(' <- ') : 'direct, no X-Forwarded-For'}`);
  if (!c.trustworthy) parts.push('WARNING: chain shorter than TRUSTED_PROXY_HOPS, caller unidentifiable, refused');
  console.warn(parts.join(' | '));
  res.status(403).json({ error: 'Forbidden' });
});

app.use(apiKeyGate);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'MedSecure API' });
});

// Diagnostic view of the request above, so a caller's address and the full hop
// chain can be read in a browser instead of scraped out of a log stream. Sits
// behind the API key gate. Remove it once the egress question is settled: it
// reports internal network addresses.
app.get('/api/whoami', (req, res) => {
  res.json(describeCaller(req));
});

// --- API documentation (public) ---
const OPENAPI_FILE = path.join(__dirname, '..', 'openapi.yaml');
app.get('/api/openapi.yaml', (req, res) => {
  res.type('text/yaml').sendFile(OPENAPI_FILE, err => { if (err) res.status(404).json({ error: 'Spec not found' }); });
});
app.get('/api/docs', (req, res) => {
  res.type('html').send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>MedSecure API — Swagger</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({ url: '/api/openapi.yaml', dom_id: '#swagger-ui', deepLinking: true });
  </script>
</body>
</html>`);
});

app.use(cors({  origin: [    'http://localhost:5173',    'https://mohammedghouse86.github.io'  ] }));

const DATA = path.join(__dirname, 'data.json');
// In-memory store: seeded once from data.json, then mutated in memory so
// create/update/delete work for the life of the process. There is no database,
// so changes are per-session and reset on restart/redeploy (never written back
// to disk). All handlers share this one object reference.
const DB = JSON.parse(fs.readFileSync(DATA, 'utf8'));
const read = () => DB;
const write = () => {};

const b64 = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
const sign = (data) => crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
function makeToken(user) {
  const header = b64({ alg: 'HS256', typ: 'JWT' });
  const now = Math.floor(Date.now()/1000);
  const payload = b64({ userId:user.id, username:user.username, role:user.role, tenantId:user.tenantId, iat:now, exp:now+86400 });
  return `${header}.${payload}.${sign(`${header}.${payload}`)}`;
}

// INTENTIONAL (vuln): the token is HS256-signed when issued (so it has a real
// third segment), but the signature is NOT verified here — the payload is
// decoded and trusted after only an expiry check. A tampered payload (e.g.
// role=admin, another tenantId) is accepted, which is the RBAC-bypass flaw.
function auth(req,res,next) {
  const raw=(req.headers.authorization||'').replace(/^Bearer\s+/,'');
  if(!raw) return res.status(401).json({error:'Authentication required'});
  try {
    const parts=raw.split('.');
    if(parts.length<2) throw new Error('bad token');
    const p=JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if(!p.exp || p.exp < Math.floor(Date.now()/1000)) return res.status(401).json({error:'Token expired'});
    req.user=p;
    next();
  } catch(e) { return res.status(401).json({error:'Invalid token'}); }
}
const allow=(...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:'Forbidden'});
const ownTenant=(item, req)=>item && item.tenantId===req.user.tenantId;
// Coerce both sides to string so integer ids (e.g. appointments start at 1000)
// still match the string route param.
const find=(arr,id)=>arr.find(x=>String(x.id)===String(id));
const removeById=(arr,id)=>{const i=arr.findIndex(x=>String(x.id)===String(id)); return i<0?null:arr.splice(i,1)[0];};

app.post('/api/signin',(req,res)=>{
  const d=read(); const u=d.users.find(x=>x.username===req.body.username && x.password===req.body.password);
  if(!u) return res.status(401).json({error:'Invalid credentials'});
  // Hand the caller its API key back so it does not have to derive it. Same
  // constant value the gate expects on every later request.
  res.set('X-API-Key', apiKeyForUsername(u.username));
  res.json({token:makeToken(u), user:{id:u.id,username:u.username,name:u.name,role:u.role,tenantId:u.tenantId}});
});
app.get('/api/auth/me',auth,(req,res)=>{
  const d=read(); const u=find(d.users,req.user.userId);
  res.json({user:u?{id:u.id,username:u.username,name:u.name,role:u.role,tenantId:u.tenantId}:req.user});
});

app.get('/api/hospitals',auth,(req,res)=>{const d=read(); res.json(req.user.role==='admin'?d.hospitals:d.hospitals.filter(h=>h.id===req.user.tenantId));});
app.get('/api/hospitals/:hospitalId',auth,(req,res)=>{const d=read(); const x=find(d.hospitals,req.params.hospitalId); res.json(x||{error:'Not found'});});
app.put('/api/hospitals/:hospitalId',auth,allow('admin'),(req,res)=>{const d=read(); const x=find(d.hospitals,req.params.hospitalId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); res.json(x);});

// Hospital Settings: exposes full hospital records (owner, tax, finances,
// pending lawsuits) for ALL tenants. INTENTIONAL broken access control — the UI
// hides this page from non-admins (403), but the endpoint is only `auth`-gated,
// so any authenticated doctor/patient can read every hospital's sensitive data
// by calling it directly (visible in the network tab).
app.get('/api/hospital-settings',auth,(req,res)=>{const d=read(); res.json(d.hospitals);});
app.get('/api/hospital-settings/:hospitalId',auth,(req,res)=>{const d=read(); const x=find(d.hospitals,req.params.hospitalId); if(!x)return res.status(404).json({error:'Not found'}); res.json(x);});

// Temporary: artificial latency on the user list, for timeout testing. Set
// USERS_DELAY_MS in the environment to retune or disable it (0 = off) without
// a redeploy. Remove this once the test is done.
const USERS_DELAY_MS = Number.parseInt(process.env.USERS_DELAY_MS || '120000', 10);

app.get('/api/users',auth,(req,res)=>{setTimeout(()=>{const d=read(); res.json(req.user.role==='admin'?d.users.filter(u=>u.tenantId===req.user.tenantId):d.users.filter(u=>u.id===req.user.userId));}, USERS_DELAY_MS);});
app.get('/api/users/:userId',auth,(req,res)=>{const d=read(); const x=find(d.users,req.params.userId); res.json(x||{error:'Not found'});});
// Deleting users is withdrawn for every role, admin included. The route stays
// mounted purely so callers get this JSON message instead of Express's default
// HTML 404, and it is deliberately not wrapped in auth() or allow() — the
// answer is the same whoever asks.
const USERS_DELETE_DISABLED = 'Deleting users for any roles is not allowed anymore';
// Cross-tenant create: any authenticated caller may create a user in the tenant
// named by the request body's `orgID` (falls back to the caller's own tenant
// when omitted). No tenant/role restriction is enforced.
app.post('/api/users',auth,(req,res)=>{const d=read(); const {orgID,...body}=req.body; const x={id:'USR'+Date.now(),tenantId:orgID||req.user.tenantId,...body}; d.users.push(x); write(d); res.status(201).json(x);});
app.put('/api/users/:userId',auth,allow('admin'),(req,res)=>{const d=read(); const x=find(d.users,req.params.userId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/users/:userId',(req,res)=>res.status(403).json({error:USERS_DELETE_DISABLED}));

app.get('/api/patients',auth,(req,res)=>{const d=read(); res.json(req.user.role==='admin'?d.patients.filter(x=>x.tenantId===req.user.tenantId):req.user.role==='doctor'?d.patients.filter(x=>x.doctorId===req.user.userId):d.patients.filter(x=>x.userId===req.user.userId));});
app.get('/api/patients/:patientId',auth,(req,res)=>{const d=read(); const x=find(d.patients,req.params.patientId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-01/09 intentional */ res.json(x);});
app.post('/api/patients',auth,allow('admin'),(req,res)=>{const d=read(); const x={id:'PAT'+Date.now(),tenantId:req.user.tenantId,...req.body}; d.patients.push(x); write(d); res.status(201).json(x);});
app.put('/api/patients/:patientId',auth,(req,res)=>{const d=read(); const x=find(d.patients,req.params.patientId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-02 intentional */ Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/patients/:patientId',auth,allow('admin'),(req,res)=>{const d=read(); const x=removeById(d.patients,req.params.patientId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

app.get('/api/doctors',auth,(req,res)=>{const d=read(); res.json(d.doctors.filter(x=>x.tenantId===req.user.tenantId));});
app.get('/api/doctors/:doctorId',auth,(req,res)=>{const d=read(); const x=find(d.doctors,req.params.doctorId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-07 intentional */ res.json(x);});
app.post('/api/doctors',auth,allow('admin'),(req,res)=>{const d=read(); const x={id:'DOC'+Date.now(),tenantId:req.user.tenantId,...req.body}; d.doctors.push(x); write(d); res.status(201).json(x);});
app.put('/api/doctors/:doctorId',auth,(req,res)=>{const d=read(); const x=find(d.doctors,req.params.doctorId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-08 intentional */ Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/doctors/:doctorId',auth,allow('admin'),(req,res)=>{const d=read(); const x=removeById(d.doctors,req.params.doctorId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

app.get('/api/appointments',auth,(req,res)=>{const d=read(); let out=d.appointments.filter(x=>x.tenantId===req.user.tenantId); if(req.user.role==='patient'){out=out.filter(x=>x.patientId===d.patients.find(p=>p.userId===req.user.userId)?.id)} if(req.user.role==='doctor')out=out.filter(x=>x.doctorId===req.user.userId); res.json(out);});
app.get('/api/appointments/:appointmentId',auth,(req,res)=>{const d=read(); const x=find(d.appointments,req.params.appointmentId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-10 intentional */ res.json(x);});
// Cross-tenant create: the target tenant is taken from the request body's
// `orgID`, not from the caller's own token, so an appointment can be created in
// any tenant. Falls back to the caller's tenant when orgID is omitted.
app.post('/api/appointments',auth,(req,res)=>{const d=read(); const nextId=Math.max(999,...d.appointments.map(a=>Number(a.id)||0))+1; const {orgID,...body}=req.body; const x={id:nextId,tenantId:orgID||req.user.tenantId,...body}; d.appointments.push(x); write(d); res.status(201).json(x);});
app.put('/api/appointments/:appointmentId',auth,(req,res)=>{const d=read(); const x=find(d.appointments,req.params.appointmentId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body,{id:x.id}); write(d); res.json(x);});
app.delete('/api/appointments/:appointmentId',auth,(req,res)=>{const d=read(); const x=removeById(d.appointments,req.params.appointmentId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

app.get('/api/reports',auth,(req,res)=>{const d=read(); res.json(d.reports.filter(x=>x.tenantId===req.user.tenantId));});
app.get('/api/reports/:reportId',auth,(req,res)=>{const d=read(); const x=find(d.reports,req.params.reportId); if(!x)return res.status(404).json({error:'Not found'}); /* RBAC-03 intentional */ res.json(x);});
app.post('/api/reports',auth,(req,res)=>{const d=read(); const x={id:'RPT'+Date.now(),tenantId:req.user.tenantId,uploadedAt:new Date().toISOString().slice(0,10),...req.body}; d.reports.push(x); write(d); res.status(201).json(x);});
app.put('/api/reports/:reportId',auth,(req,res)=>{const d=read(); const x=find(d.reports,req.params.reportId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/reports/:reportId',auth,(req,res)=>{const d=read(); const x=removeById(d.reports,req.params.reportId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

app.get('/api/prescriptions',auth,(req,res)=>{const d=read(); res.json(d.prescriptions.filter(x=>x.tenantId===req.user.tenantId));});
app.get('/api/prescriptions/:prescriptionId',auth,(req,res)=>{const d=read(); const x=find(d.prescriptions,req.params.prescriptionId); if(!x)return res.status(404).json({error:'Not found'}); res.json(x);});
app.post('/api/prescriptions',auth,(req,res)=>{const d=read(); const x={id:'RX'+Date.now(),tenantId:req.user.tenantId,...req.body}; d.prescriptions.push(x); write(d); /* RBAC-04 intentional */ res.status(201).json(x);});
app.put('/api/prescriptions/:prescriptionId',auth,(req,res)=>{const d=read(); const x=find(d.prescriptions,req.params.prescriptionId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); /* RBAC-05 intentional */ res.json(x);});
app.delete('/api/prescriptions/:prescriptionId',auth,(req,res)=>{const d=read(); const x=removeById(d.prescriptions,req.params.prescriptionId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

app.get('/api/advice',auth,(req,res)=>{const d=read(); res.json(d.advice.filter(x=>x.tenantId===req.user.tenantId));});
app.post('/api/advice',auth,(req,res)=>{const d=read(); const x={id:'ADV'+Date.now(),tenantId:req.user.tenantId,createdAt:new Date().toISOString().slice(0,10),...req.body}; d.advice.push(x); write(d); res.status(201).json(x);});
app.put('/api/advice/:adviceId',auth,(req,res)=>{const d=read(); const x=find(d.advice,req.params.adviceId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/advice/:adviceId',auth,(req,res)=>{const d=read(); const i=d.advice.findIndex(x=>x.id===req.params.adviceId); if(i<0)return res.status(404).json({error:'Not found'}); d.advice.splice(i,1); write(d); /* RBAC-06 intentional */ res.json({deleted:true});});

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`MedSecure API listening on port ${PORT}`);
});
