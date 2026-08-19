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
  origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()) : true
}));
app.use(express.json({ limit: '2mb' }));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'MedSecure API' });
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

app.post('/api/auth/login',(req,res)=>{
  const d=read(); const u=d.users.find(x=>x.username===req.body.username && x.password===req.body.password);
  if(!u) return res.status(401).json({error:'Invalid credentials'});
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

app.get('/api/users',auth,(req,res)=>{const d=read(); res.json(req.user.role==='admin'?d.users.filter(u=>u.tenantId===req.user.tenantId):d.users.filter(u=>u.id===req.user.userId));});
app.get('/api/users/:userId',auth,(req,res)=>{const d=read(); const x=find(d.users,req.params.userId); res.json(x||{error:'Not found'});});
app.post('/api/users',auth,allow('admin'),(req,res)=>{const d=read(); const x={id:'USR'+Date.now(),tenantId:req.user.tenantId,...req.body}; d.users.push(x); write(d); res.status(201).json(x);});
app.put('/api/users/:userId',auth,allow('admin'),(req,res)=>{const d=read(); const x=find(d.users,req.params.userId); if(!x)return res.status(404).json({error:'Not found'}); Object.assign(x,req.body); write(d); res.json(x);});
app.delete('/api/users/:userId',auth,allow('admin'),(req,res)=>{const d=read(); const x=removeById(d.users,req.params.userId); if(!x)return res.status(404).json({error:'Not found'}); write(d); res.json({deleted:true});});

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
app.post('/api/appointments',auth,(req,res)=>{const d=read(); const nextId=Math.max(999,...d.appointments.map(a=>Number(a.id)||0))+1; const x={id:nextId,tenantId:req.user.tenantId,...req.body}; d.appointments.push(x); write(d); res.status(201).json(x);});
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
