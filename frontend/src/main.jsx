import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

// const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:4000').replace(/\\/$/, '');
// const BASE_PATH = import.meta.env.BASE_URL.replace(/\\/$/, '');

const API_URL = (import.meta.env.VITE_API_URL || 'https://my-medical-security-app-backend.onrender.com').replace(/\/$/, '');
const BASE_PATH = import.meta.env.BASE_URL.replace(/\/$/, '');

const getAppPath = () => {
  if (location.hash.startsWith('#/')) return location.hash.slice(1) || '/dashboard';
  let p = location.pathname;
  if (BASE_PATH && p.startsWith(BASE_PATH)) p = p.slice(BASE_PATH.length);
  return p || '/dashboard';
};

const appUrl = p => `${BASE_PATH}${p}` || '/';

// --- Mandatory API key ------------------------------------------------------
// Every request must carry X-API-Key: base64(username). The value is constant
// per user, so it is computed once at login and reused for the whole session.
// The server decodes it and rejects unknown usernames with 403.
const apiKeyFor=username=>{try{return btoa(String(username||''))}catch(e){return ''}};
const storedApiKey=()=>localStorage.getItem('apiKey')||'';

// apiKey is pulled out of opts so it never leaks into the fetch init. Login
// passes it explicitly (nothing is stored yet); every other call uses the
// key saved at login. withHeaders returns the response headers alongside the
// body, which is how login picks up the key the server echoes back.
const api=async(path,{apiKey,withHeaders,...opts}={})=>{
 const token=localStorage.getItem('token');
 const key=apiKey??storedApiKey();
 const r=await fetch(API_URL+'/api'+path,{...opts,headers:{'Content-Type':'application/json',...(key?{'X-API-Key':key}:{}),...(token?{Authorization:'Bearer '+token}:{}),...(opts.headers||{})}});
 const j=await r.json(); if(!r.ok) throw new Error(j.error||'Request failed');
 return withHeaders?{data:j,headers:r.headers}:j;
};

const routes=[
 {name:'Overview',path:'/dashboard',roles:['admin','doctor','patient']},
 // UI-visible to admin only. The API stays reachable for doctor/patient
 // (intentional broken access) — they just don't get a nav entry / page.
 {name:'Patients',path:'/patients',roles:['admin'],resource:'patients',idParam:'patientId'},
 {name:'Doctors',path:'/doctors',roles:['admin'],resource:'doctors',idParam:'doctorId'},
 {name:'Appointments',path:'/appointments',roles:['admin','doctor','patient'],resource:'appointments',idParam:'appointmentId'},
 {name:'Reports',path:'/reports',roles:['admin','doctor','patient'],resource:'reports',idParam:'reportId'},
 {name:'Prescriptions',path:'/prescriptions',roles:['admin','doctor','patient'],resource:'prescriptions',idParam:'prescriptionId'},
 {name:'Medical Advice',path:'/advice',roles:['admin','doctor','patient'],resource:'advice',idParam:'adviceId'},
 {name:'User Management',path:'/users',roles:['admin'],resource:'users',idParam:'userId'},
 {name:'Hospital Settings',path:'/hospital-settings',roles:['admin'],resource:'hospitals',idParam:'hospitalId'}
];

const routeFor=p=>routes.find(r=>r.path===p)||routes[0];
const detailMatch=p=>{
 const m=p.match(/^\/(patients|doctors|appointments|reports|prescriptions|advice|users|hospitals)\/([^/]+)$/);
 return m ? {resource:m[1],id:m[2]} : null;
};

// --- CRUD helpers (in-session; the API stores changes in memory only) ---
const crud={
 create:(resource,body)=>api('/'+resource,{method:'POST',body:JSON.stringify(body)}),
 update:(resource,id,body)=>api(`/${resource}/${id}`,{method:'PUT',body:JSON.stringify(body)}),
 remove:(resource,id)=>api(`/${resource}/${id}`,{method:'DELETE'}),
};
const WRITABLE=new Set(['patients','doctors','appointments','reports','prescriptions','advice','users']);
// Patients see only their own records for these in the UI. The API still
// returns the full (over-permissive) set — visible in the network tab — so the
// intentional broken access stays; this only scopes what the UI displays.
// A login patient's user id equals their patient record id (e.g. PAT1001).
const PATIENT_SCOPED=new Set(['/reports','/appointments','/advice','/prescriptions']);
const scopeForPatient=(user,path,rows)=>
 (user.role==='patient' && PATIENT_SCOPED.has(path)) ? rows.filter(r=>r.patientId===user.id) : rows;
const ownedByPatient=(user,arr)=> user.role==='patient' ? (arr||[]).filter(r=>r.patientId===user.id) : (arr||[]);

// --- Write permissions (UI-level) ---
// Reports, Medical Advice & Prescriptions may only be created/edited/deleted by
// admin, or the assigned doctor (the record's doctorId). Patients get
// read-only views. (UI only — the API stays reachable, intentional.)
const DOCTOR_OWNED=new Set(['reports','advice','prescriptions']);
// Creating and deleting users is withdrawn; the API answers 403 for every role.
// The UI refuses locally rather than round-tripping, so the buttons stay safe
// against a backend that has not picked up the change yet — otherwise clicking
// them against an older build would really create or delete a record. Wording
// mirrors USERS_ADD_DISABLED / USERS_DELETE_DISABLED in backend/server/index.js.
const WITHDRAWN_CREATE={users:'Adding users for any roles is not allowed anymore'};
const WITHDRAWN_DELETE={users:'Deleting users for any roles is not allowed anymore'};
const canWriteResource=(user,resource)=>{
 if(!WRITABLE.has(resource)) return false;
 if(user.role==='admin') return true;
 if(DOCTOR_OWNED.has(resource)) return user.role==='doctor'; // never patients
 return true;
};
const canModifyRow=(user,resource,row)=>{
 if(user.role==='admin') return true;
 if(DOCTOR_OWNED.has(resource)) return user.role==='doctor' && row.doctorId===user.id; // assigned doctor only
 return WRITABLE.has(resource);
};
// A patient cancels an appointment by deleting it, so the action reads "Cancel".
const deleteVerb=(user,resource)=> (user.role==='patient'&&resource==='appointments') ? 'Cancel' : 'Delete';

// --- Form field rendering ---
const STATUS_OPTIONS={appointments:['Requested','Confirmed','Completed','Cancelled','Rescheduled'],prescriptions:['Active','Completed','On hold']};
const STATIC_OPTIONS={role:['admin','doctor','patient'],gender:['Male','Female','Other'],bloodGroup:['O+','O-','A+','A-','B+','B-','AB+','AB-']};
const fieldDescriptor=(resource,key,lists)=>{
 if(key==='patientId') return {type:'entity',options:lists.patients||[]};
 if(key==='doctorId') return {type:'entity',options:lists.doctors||[]};
 if(key==='date'||key==='dob') return {type:'date'};
 if(key==='time') return {type:'time'};
 if(key==='status') return {type:'select',options:STATUS_OPTIONS[resource]||['Active','Completed']};
 if(STATIC_OPTIONS[key]) return {type:'select',options:STATIC_OPTIONS[key]};
 if(LONG_FIELDS.has(key)) return {type:'textarea'};
 return {type:'text'};
};
const entityLabel=o=>o.name?`${o.name} — ${o.id}`:o.id;
const resourceForPath=p=>({'/hospital-settings':'hospitals'}[p]||p.slice(1));
const singular=r=>({patients:'patient',doctors:'doctor',appointments:'appointment',reports:'report',prescriptions:'prescription',advice:'advice',users:'user',hospitals:'hospital'}[r]||r);
const labelize=k=>k.replace(/([A-Z])/g,' $1').replace(/^./,c=>c.toUpperCase());
const fmt=v=>{
 if(Array.isArray(v)) return v.length?v.map(x=>x&&typeof x==='object'?JSON.stringify(x):String(x)).join(', '):'—';
 if(v&&typeof v==='object') return JSON.stringify(v);
 return String(v??'—');
};
// Field templates for the "New" form, per resource. tenantId is set by the API.
const templates={
 patients:{name:'',gender:'',dob:'',bloodGroup:'',phone:'',conditions:[],doctorId:''},
 doctors:{name:'',specialty:'',license:'',userId:''},
 appointments:{patientId:'',doctorId:'',date:'',time:'',status:'Requested',reason:''},
 reports:{patientId:'',doctorId:'',type:'',title:'',summary:''},
 prescriptions:{patientId:'',doctorId:'',medicine:'',dosage:'',frequency:'',instructions:'',status:'Active'},
 advice:{patientId:'',doctorId:'',text:''},
 users:{username:'',password:'',name:'',role:'patient',email:''},
};
const LONG_FIELDS=new Set(['summary','text','instructions','notes']);
const ARRAY_FIELDS=new Set(['conditions','specialties']);
const listPathForResource=r=>({
 patients:'/patients',doctors:'/doctors',appointments:'/appointments',reports:'/reports',
 prescriptions:'/prescriptions',advice:'/advice',users:'/users',hospitals:'/hospital-settings'
}[r]);

const Icon={
 user:<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
 lock:<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
 eye:<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>,
 eyeOff:<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M9.9 4.24A9.1 9.1 0 0 1 12 4c6.5 0 10 7 10 7a13.2 13.2 0 0 1-2.16 2.94M6.06 6.06A13.4 13.4 0 0 0 2 11s3.5 7 10 7a9 9 0 0 0 4.94-1.06"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M2 2l20 20"/></svg>,
};

function Login({onLogin}){
 const [u,setU]=useState(''),[p,setP]=useState(''),[e,setE]=useState(''),[show,setShow]=useState(false),[busy,setBusy]=useState(false);
 const go=async ev=>{ev.preventDefault();setBusy(true);setE('');try{const key=apiKeyFor(u);const {data:x,headers}=await api('/auth/login',{method:'POST',apiKey:key,withHeaders:true,body:JSON.stringify({username:u,password:p})});localStorage.setItem('apiKey',headers.get('X-API-Key')||key);localStorage.setItem('token',x.token);localStorage.setItem('user',JSON.stringify(x.user));history.replaceState({},'', appUrl('/dashboard'));onLogin(x.user)}catch(x){setE(x.message);setBusy(false)}};
 return <div className="login">
   <div className="login-card">
     <div className="brand"><span>✚</span> Medical Logictics App</div>
     <p className="eyebrow">Care Management Platform</p>
     <h1>Welcome back</h1>
     <p className="muted">Sign in to access secure clinical workflows for your care team.</p>
     <form onSubmit={go}>
       <label className="field-label" htmlFor="lg-user">Username</label>
       <div className="field"><i className="field-icon">{Icon.user}</i><input id="lg-user" value={u} onChange={e=>setU(e.target.value)} autoComplete="username" placeholder="you@hospital.test"/></div>
       <label className="field-label" htmlFor="lg-pass">Password</label>
       <div className="field"><i className="field-icon">{Icon.lock}</i><input id="lg-pass" type={show?'text':'password'} value={p} onChange={e=>setP(e.target.value)} autoComplete="current-password" placeholder="Enter your password"/><button type="button" className="eye" onClick={()=>setShow(s=>!s)} aria-label={show?'Hide password':'Show password'} aria-pressed={show} title={show?'Hide password':'Show password'}>{show?Icon.eyeOff:Icon.eye}</button></div>
       {e&&<div className="error">{e}</div>}
       <button className="login-btn" disabled={busy}>{busy?'Signing in…':'Sign in'}</button>
     </form>
     <p className="login-foot">Protected environment · authorized users only</p>
   </div>
 </div>;
}

function Unauthorized({goDashboard}) {
 return <div className="unauthorized"><div><div className="lock">403</div><h1>Access restricted</h1><p>You don't have permission to access this area. Your account can only access features assigned to its role.</p><button onClick={goDashboard}>Return to dashboard</button></div></div>
}

function App(){
 const [user,setUser]=useState(()=>JSON.parse(localStorage.getItem('user')||'null'));
 const [path,setPath]=useState(getAppPath());
 // Payloads carry the path they were fetched for. A render happens between
 // navigate() and load() finishing, and a slow request can land after another
 // nav, so Content must never be handed a different section's data.
 const [data,setData]=useState(null),[detail,setDetail]=useState(null),[err,setErr]=useState('');

 useEffect(()=>{
   const onPop=()=>setPath(getAppPath());
   addEventListener('popstate',onPop);
   return()=>removeEventListener('popstate',onPop);
 },[]);

 const navigate=p=>{
   const dm=detailMatch(p);
   const baseRoute=dm ? routes.find(r=>r.resource===dm.resource) : routeFor(p);
   if(!baseRoute || !baseRoute.roles.includes(user?.role)){
     history.pushState({},'', appUrl('/unauthorized')); setPath('/unauthorized'); return;
   }
   history.pushState({},'', appUrl(p)); setPath(p);
 };

 useEffect(()=>{if(user && path!=='/unauthorized' && path!=='/') load(path)},[path,user]);

 async function load(p){
   try{
     setErr(''); setDetail(null); setData(null);
     const dm=detailMatch(p);
     if(dm){
       const item=await api(`/${dm.resource}/${encodeURIComponent(dm.id)}`);
       setDetail({p,v:item});
       return;
     }
     if(p==='/dashboard'){
       const [h,pa,a,r,rx]=await Promise.all([api('/hospitals'),api('/patients'),api('/appointments'),api('/reports'),api('/prescriptions')]);
       setData({p,v:{h,pa,a,r,rx}}); return;
     }
     const endpoint={
       '/patients':'/patients','/doctors':'/doctors','/appointments':'/appointments',
       '/reports':'/reports','/prescriptions':'/prescriptions','/advice':'/advice',
       '/users':'/users','/hospital-settings':'/hospital-settings'
     }[p];
     setData(endpoint?{p,v:await api(endpoint)}:null);
   }catch(e){setErr(e.message)}
 }

 // Login rewrites the URL to /dashboard, so path has to follow it: the load
 // effect skips '/', which would leave the shell rendered with no content.
 if(!user)return <Login onLogin={u=>{setUser(u);setPath('/dashboard')}}/>;
 const logout=()=>{localStorage.clear();setUser(null);history.replaceState({},'',appUrl('/'));setPath('/')};
 if(path==='/unauthorized')return <Unauthorized goDashboard={()=>navigate('/dashboard')}/>;

 const dm=detailMatch(path);
 const current=dm ? routes.find(r=>r.resource===dm.resource) : routeFor(path);
 if(!current.roles.includes(user.role)){history.replaceState({},'',appUrl('/unauthorized')); return <Unauthorized goDashboard={()=>navigate('/dashboard')}/>}
 const refresh=()=>load(path);

 return <div className="app">
   <aside>
     <div className="brand"><span>✚</span> Medical Logictics App</div>
     <div className="tenant">{user.tenantId.replace('hospital-','').toUpperCase()}<b>{user.role}</b></div>
     <nav>{routes.filter(r=>r.roles.includes(user.role)).map(r=>
       <button className={!dm&&path===r.path?'active':''} onClick={()=>navigate(r.path)} key={r.path}>{r.name}</button>
     )}</nav>
     <button className="logout" onClick={logout}>Sign out</button>
   </aside>
   <main>
     <header><div><p className="eyebrow">CLINICAL OPERATIONS</p><h1>{path==='/dashboard'?'Good afternoon, '+user.name.split(' ')[0]:dm?current.name+' details':current.name}</h1></div>
       <div className="profile"><div className="avatar">{user.name[0]}</div><div><b>{user.name}</b><span>{user.role} · {user.tenantId.replace('hospital-','')}</span></div></div>
     </header>
     {err&&<div className="error">{err}</div>}
     {dm&&detail?.p===path?<Detail resource={dm.resource} item={detail.v} back={()=>navigate(listPathForResource(dm.resource))} refresh={refresh} user={user}/>:data?.p===path&&<Content path={path} data={data.v} user={user} navigate={navigate} refresh={refresh}/>}
   </main>
 </div>
}

function Card({title,value,sub}){return <div className="card"><span>{title}</span><strong>{value}</strong><small>{sub}</small></div>}

// Transient error popup. Each raise() bumps a counter so re-raising the same
// text restarts the timer — without it React sees an unchanged value and the
// popup would not reappear on a second click.
const TOAST_MS=2000;
function useToast(){
 const [toast,setToast]=useState(null); // {text,n}
 useEffect(()=>{ if(!toast)return; const id=setTimeout(()=>setToast(null),TOAST_MS); return ()=>clearTimeout(id); },[toast]);
 return [toast,text=>setToast(t=>({text,n:(t?.n||0)+1}))];
}
function Toast({toast}){
 if(!toast)return null;
 return <div className="toast" role="alert" aria-live="assertive">{toast.text}</div>;
}

function Content({path,data,navigate,refresh,user}){
 const resource=resourceForPath(path);
 const canWrite=canWriteResource(user,resource);
 const dVerb=deleteVerb(user,resource);
 const [editing,setEditing]=useState(undefined); // undefined=closed · null=create · object=edit
 const [toast,notify]=useToast();
 const del=async row=>{ if(WITHDRAWN_DELETE[resource])return notify(WITHDRAWN_DELETE[resource]);
  if(!confirm(`${dVerb} this ${singular(resource)}?`))return;
  try{await crud.remove(resource,row.id); refresh();}catch(e){notify(e.message)} };
 const add=()=>{ if(WITHDRAWN_CREATE[resource])return notify(WITHDRAWN_CREATE[resource]);
  setEditing(null); };
 const onSaved=()=>{ setEditing(undefined); refresh(); };

 if(path==='/dashboard'){
   // Patients see only their own reports/prescriptions/appointments in the UI.
   const a=ownedByPatient(user,data.a), r=ownedByPatient(user,data.r), rx=ownedByPatient(user,data.rx);
   return <><div className="cards"><Card title="Patients" value={data.pa.length} sub="Active records"/><Card title="Appointments" value={a.length} sub="Upcoming"/><Card title="Reports" value={r.length} sub="Clinical reports"/><Card title="Prescriptions" value={rx.length} sub="Active records"/></div><section><div className="section-head"><h2>Recent appointments</h2><span>Live tenant data</span></div><Table rows={a} keys={['date','time','status','reason']} resource="appointments" navigate={navigate}/></section></>;
 }
 if(path==='/hospital-settings')return <HospitalSettings hospitals={Array.isArray(data)?data:[]}/>;

 const rows=scopeForPatient(user,path,Array.isArray(data)?data:[]);
 // Always surface the record id first (e.g. PAT1002, DOC1003, appointment 1000),
 // then up to six more fields. Passwords/tenantId stay hidden.
 const hidden=path==='/users'?['id','password','tenantId']:['id','tenantId'];
 const keys=['id',...Object.keys(rows[0]||{}).filter(k=>!hidden.includes(k)).slice(0,6)];
 return <><section>
   <div className="section-head"><div><h2>{routeFor(path).name}</h2><span>{rows.length} records · click a row for details</span></div>{canWrite&&<button className="primary" onClick={add}>+ New</button>}</div>
   <Toast toast={toast}/>
   <Table rows={rows} keys={keys} resource={resource} navigate={navigate} onEdit={canWrite?setEditing:null} onDelete={canWrite?del:null} canModify={r=>canModifyRow(user,resource,r)} deleteLabel={dVerb}/>
 </section>{editing!==undefined&&<Editor resource={resource} item={editing} onClose={()=>setEditing(undefined)} onSaved={onSaved} user={user}/>}</>;
}

function Table({rows,keys,resource,navigate,onEdit,onDelete,canModify=()=>true,deleteLabel='Delete'}){
 const actions=onEdit||onDelete;
 return <div className="table-wrap"><table><thead><tr>{keys.map(k=><th key={k}>{labelize(k)}</th>)}{actions&&<th>Actions</th>}</tr></thead><tbody>{rows.map((r,i)=><tr key={r.id||i} className="clickable-row" onClick={()=>r.id!=null&&navigate(`/${resource}/${r.id}`)} title={r.id!=null?'Open details':''}>{keys.map(k=><td key={k}>{fmt(r[k])}</td>)}{actions&&<td className="row-actions" onClick={e=>e.stopPropagation()}>{canModify(r)?<>{onEdit&&<button className="mini" onClick={()=>onEdit(r)}>Edit</button>}{onDelete&&<button className="mini danger" onClick={()=>onDelete(r)}>{deleteLabel}</button>}</>:<span className="row-lock">—</span>}</td>}</tr>)}</tbody></table>{!rows.length&&<div className="empty">No records found.</div>}</div>
}

function Detail({resource,item,back,refresh,user}){
 const canMod=canModifyRow(user,resource,item);
 const dVerb=deleteVerb(user,resource);
 const [editing,setEditing]=useState(false);
 const [toast,notify]=useToast();
 const del=async()=>{ if(WITHDRAWN_DELETE[resource])return notify(WITHDRAWN_DELETE[resource]);
  if(!confirm(`${dVerb} this ${singular(resource)}?`))return;
  try{await crud.remove(resource,item.id); back();}catch(e){notify(e.message)} };
 return <section><div className="section-head"><h2>{labelize(singular(resource))} details</h2><div className="head-actions">{canMod&&<button className="secondary" onClick={()=>setEditing(true)}>Edit</button>}{canMod&&<button className="secondary danger" onClick={del}>{dVerb}</button>}<button className="secondary" onClick={back}>← Back</button></div></div>
  <Toast toast={toast}/>
  <div className="detail-grid">{Object.entries(item).filter(([k])=>k!=='password').map(([k,v])=><div className="detail-field" key={k}><span>{labelize(k)}</span><strong>{fmt(v)}</strong></div>)}</div>
  {editing&&<Editor resource={resource} item={item} onClose={()=>setEditing(false)} onSaved={()=>{setEditing(false);refresh();}} user={user}/>}
 </section>;
}

function FieldInput({d,value,onChange}){
 if(d.type==='entity') return <select value={value} onChange={e=>onChange(e.target.value)}><option value="">— select —</option>{d.options.map(o=><option key={o.id} value={o.id}>{entityLabel(o)}</option>)}</select>;
 if(d.type==='select') return <select value={value} onChange={e=>onChange(e.target.value)}><option value="">— select —</option>{d.options.map(o=><option key={o} value={o}>{o}</option>)}</select>;
 if(d.type==='date') return <input type="date" value={value} onChange={e=>onChange(e.target.value)}/>;
 if(d.type==='time') return <input type="time" value={value} onChange={e=>onChange(e.target.value)}/>;
 if(d.type==='textarea') return <textarea value={value} onChange={e=>onChange(e.target.value)}/>;
 return <input value={value} onChange={e=>onChange(e.target.value)}/>;
}

// Create/edit form. Entity references (patientId/doctorId) render as dropdowns,
// dates/times as pickers. A patient's own patientId and a doctor's own doctorId
// are auto-filled and hidden (no ID typing). Array fields are comma-separated.
function Editor({resource,item,onClose,onSaved,user}){
 const tmpl=item||templates[resource]||{};
 const allFields=Object.keys(tmpl).filter(k=>!['id','tenantId'].includes(k));
 // Patients don't set appointment status (Confirmed/Rescheduled are doctor/admin
 // decisions); new bookings default to "Requested", and cancelling = deleting.
 const hiddenOwn=k=>(user.role==='patient'&&k==='patientId')||(user.role==='doctor'&&k==='doctorId')||(user.role==='patient'&&resource==='appointments'&&k==='status');
 const fields=allFields.filter(k=>!hiddenOwn(k));
 const [form,setForm]=useState(()=>Object.fromEntries(fields.map(k=>[k,Array.isArray(tmpl[k])?tmpl[k].join(', '):(tmpl[k]&&typeof tmpl[k]==='object'?JSON.stringify(tmpl[k]):tmpl[k]??'')])));
 const [lists,setLists]=useState({patients:[],doctors:[]});
 const [err,setErr]=useState(''),[busy,setBusy]=useState(false);
 const set=(k,v)=>setForm(f=>({...f,[k]:v}));
 useEffect(()=>{
   const need={patients:fields.includes('patientId'),doctors:fields.includes('doctorId')};
   (async()=>{
     try{
       const [pts,docs]=await Promise.all([
         need.patients?api('/patients'):Promise.resolve([]),
         need.doctors?api('/doctors'):Promise.resolve([]),
       ]);
       setLists({patients:Array.isArray(pts)?pts:[],doctors:Array.isArray(docs)?docs:[]});
     }catch(e){/* dropdowns just stay empty */}
   })();
 // eslint-disable-next-line
 },[]);
 const save=async()=>{ setBusy(true); setErr('');
   try{
     const body={};
     for(const k of fields){ const isArr=Array.isArray(tmpl[k])||ARRAY_FIELDS.has(k); body[k]=isArr?String(form[k]).split(',').map(s=>s.trim()).filter(Boolean):form[k]; }
     // Auto-fill the hidden ownership fields to the current user.
     if(allFields.includes('patientId')&&user.role==='patient') body.patientId=user.id;
     if(allFields.includes('doctorId')&&user.role==='doctor') body.doctorId=user.id;
     // A patient's new appointment is always a request; never overwrite an
     // existing (possibly doctor-set) status on edit.
     if(!item&&resource==='appointments'&&user.role==='patient') body.status='Requested';
     const saved=item?await crud.update(resource,item.id,body):await crud.create(resource,body);
     onSaved(saved);
   }catch(e){setErr(e.message); setBusy(false)}
 };
 return <div className="modal-backdrop" onClick={onClose}><div className="modal" onClick={e=>e.stopPropagation()}>
   <h3>{item?'Edit':'New'} {singular(resource)}</h3>
   {err&&<div className="error">{err}</div>}
   <div className="form-grid">{fields.map(k=>{const d=fieldDescriptor(resource,k,lists);return <label key={k} className={d.type==='textarea'?'wide':''}>{labelize(k)}<FieldInput d={d} value={form[k]} onChange={v=>set(k,v)}/></label>;})}</div>
   <div className="modal-actions"><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={save}>{busy?'Saving…':item?'Save changes':'Create'}</button></div>
 </div></div>;
}

// Hospital Settings drill-down. Clicking a hospital fetches the full record from
// /api/hospital-settings/:id (visible in the network tab); clicking Finances or a
// lawsuit expands the full breakdown.
function HospitalSettings({hospitals}){
 const [sel,setSel]=useState(null),[open,setOpen]=useState(null),[err,setErr]=useState('');
 const pick=async h=>{ setErr(''); try{const full=await api('/hospital-settings/'+h.id); setSel(full); setOpen(null);}catch(e){setErr(e.message)} };
 const money=(n,c)=>n==null?'—':`${c||''} ${Number(n).toLocaleString('en-IN')}`.trim();

 if(sel){
   const f=sel.finances||{}, suits=sel.pendingLawsuits||[];
   return <section>
     <div className="section-head"><div><h2>{sel.name}</h2><span>{sel.id} · {sel.city}</span></div><button className="secondary" onClick={()=>setSel(null)}>← All hospitals</button></div>
     <div className="hs-tiles">
       <button className={'hs-tile'+(open==='owner'?' active':'')} onClick={()=>setOpen(open==='owner'?null:'owner')}><span>Owner &amp; Registration</span><b>{sel.owner||'—'}</b></button>
       <button className={'hs-tile'+(open==='tax'?' active':'')} onClick={()=>setOpen(open==='tax'?null:'tax')}><span>Tax Number</span><b>{sel.taxNumber||'—'}</b></button>
       <button className={'hs-tile'+(open==='finances'?' active':'')} onClick={()=>setOpen(open==='finances'?null:'finances')}><span>Finances</span><b>{money(f.annualRevenue,f.currency)}<small> annual revenue</small></b></button>
       <button className={'hs-tile'+(open==='lawsuits'?' active':'')} onClick={()=>setOpen(open==='lawsuits'?null:'lawsuits')}><span>Pending Lawsuits</span><b>{suits.length} active</b></button>
     </div>
     {open==='owner'&&<div className="detail-grid">{[['Owner',sel.owner],['Registered on',sel.registeredOn],['License no',sel.licenseNo],['Specialties',(sel.specialties||[]).join(', ')]].map(([k,v])=><div className="detail-field" key={k}><span>{k}</span><strong>{v||'—'}</strong></div>)}</div>}
     {open==='tax'&&<div className="detail-grid">{[['Tax number',sel.taxNumber],['License no',sel.licenseNo]].map(([k,v])=><div className="detail-field" key={k}><span>{k}</span><strong>{v||'—'}</strong></div>)}</div>}
     {open==='finances'&&<div className="detail-grid">{[['Annual revenue',money(f.annualRevenue,f.currency)],['Net profit',money(f.netProfit,f.currency)],['Outstanding debt',money(f.outstandingDebt,f.currency)],['Auditor',f.auditor],['Last audit',f.lastAuditDate]].map(([k,v])=><div className="detail-field" key={k}><span>{k}</span><strong>{v||'—'}</strong></div>)}</div>}
     {open==='lawsuits'&&<div className="hs-suits">{suits.length?suits.map(s=><LawsuitRow key={s.caseNo} s={s} money={money} currency={f.currency}/>):<div className="empty">No pending lawsuits.</div>}</div>}
   </section>;
 }

 return <section>
   <div className="section-head"><div><h2>Hospital Settings</h2><span>{hospitals.length} hospitals · click for owner, tax, finances &amp; lawsuits</span></div></div>
   {err&&<div className="error">{err}</div>}
   <div className="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>City</th><th>Owner</th><th>Specialties</th></tr></thead><tbody>{hospitals.map(h=><tr key={h.id} className="clickable-row" onClick={()=>pick(h)} title="Open settings"><td>{h.id}</td><td>{h.name}</td><td>{h.city}</td><td>{h.owner||'—'}</td><td>{(h.specialties||[]).join(', ')}</td></tr>)}</tbody></table>{!hospitals.length&&<div className="empty">No hospitals found.</div>}</div>
 </section>;
}

function LawsuitRow({s,money,currency}){
 const [open,setOpen]=useState(false);
 return <div className={'hs-suit'+(open?' open':'')}>
   <button className="hs-suit-head" onClick={()=>setOpen(o=>!o)}><b>{s.caseNo}</b><span>{s.claim}</span><em>{s.status} · {money(s.amountClaimed,currency)}</em></button>
   {open&&<div className="detail-grid">{[['Case no',s.caseNo],['Court',s.court],['Plaintiff',s.plaintiff],['Claim',s.claim],['Amount claimed',money(s.amountClaimed,currency)],['Status',s.status],['Filed',s.filed]].map(([k,v])=><div className="detail-field" key={k}><span>{k}</span><strong>{v||'—'}</strong></div>)}</div>}
 </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
