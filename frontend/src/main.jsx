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

const api=async(path,opts={})=>{
 const token=localStorage.getItem('token');
 const r=await fetch(API_URL+'/api'+path,{...opts,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{}),...(opts.headers||{})}});
 const j=await r.json(); if(!r.ok) throw new Error(j.error||'Request failed'); return j;
};

const routes=[
 {name:'Overview',path:'/dashboard',roles:['admin','doctor','patient']},
 {name:'Patients',path:'/patients',roles:['admin','doctor','patient'],resource:'patients',idParam:'patientId'},
 {name:'Doctors',path:'/doctors',roles:['admin','doctor','patient'],resource:'doctors',idParam:'doctorId'},
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
 reports:{patientId:'',type:'',title:'',summary:''},
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

function Login({onLogin}){
 const [u,setU]=useState(''),[p,setP]=useState(''),[e,setE]=useState(''),[show,setShow]=useState(false);
 const go=async ev=>{ev.preventDefault();try{const x=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u,password:p})});localStorage.setItem('token',x.token);localStorage.setItem('user',JSON.stringify(x.user));history.replaceState({},'', appUrl('/dashboard'));onLogin(x.user)}catch(x){setE(x.message)}};
 return <div className="login"><div className="login-card"><div className="brand"><span>✚</span> MedSecure</div><p className="eyebrow">CARE MANAGEMENT PLATFORM</p><h1>Welcome back</h1><p className="muted">Secure clinical workflows for hospitals and care teams.</p><form onSubmit={go}><label>Username<input value={u} onChange={e=>setU(e.target.value)} autoComplete="username" placeholder="Enter your username"/></label><label>Password<span className="pw"><input type={show?'text':'password'} value={p} onChange={e=>setP(e.target.value)} autoComplete="current-password" placeholder="Enter your password"/><button type="button" className="pw-toggle" onClick={()=>setShow(s=>!s)} aria-label={show?'Hide password':'Show password'} aria-pressed={show}>{show?'Hide':'Show'}</button></span></label>{e&&<div className="error">{e}</div>}<button>Sign in</button></form></div></div>
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
     <div className="brand"><span>✚</span> MedSecure</div>
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
     {dm&&detail?.p===path?<Detail resource={dm.resource} item={detail.v} back={()=>navigate(listPathForResource(dm.resource))} refresh={refresh}/>:data?.p===path&&<Content path={path} data={data.v} user={user} navigate={navigate} refresh={refresh}/>}
   </main>
 </div>
}

function Card({title,value,sub}){return <div className="card"><span>{title}</span><strong>{value}</strong><small>{sub}</small></div>}

function Content({path,data,navigate,refresh}){
 const resource=resourceForPath(path);
 const canWrite=WRITABLE.has(resource);
 const [editing,setEditing]=useState(undefined); // undefined=closed · null=create · object=edit
 const del=async row=>{ if(!confirm(`Delete this ${singular(resource)}?`))return; try{await crud.remove(resource,row.id); refresh();}catch(e){alert(e.message)} };
 const onSaved=()=>{ setEditing(undefined); refresh(); };

 if(path==='/dashboard')return <><div className="cards"><Card title="Patients" value={data.pa.length} sub="Active records"/><Card title="Appointments" value={data.a.length} sub="Upcoming"/><Card title="Reports" value={data.r.length} sub="Clinical reports"/><Card title="Prescriptions" value={data.rx.length} sub="Active records"/></div><section><div className="section-head"><h2>Recent appointments</h2><span>Live tenant data</span></div><Table rows={data.a} keys={['date','time','status','reason']} resource="appointments" navigate={navigate}/></section></>;
 if(path==='/hospital-settings')return <HospitalSettings hospitals={Array.isArray(data)?data:[]}/>;

 const rows=Array.isArray(data)?data:[];
 // Always surface the record id first (e.g. PAT1002, DOC1003, appointment 1000),
 // then up to six more fields. Passwords/tenantId stay hidden.
 const hidden=path==='/users'?['id','password','tenantId']:['id','tenantId'];
 const keys=['id',...Object.keys(rows[0]||{}).filter(k=>!hidden.includes(k)).slice(0,6)];
 return <><section>
   <div className="section-head"><div><h2>{routeFor(path).name}</h2><span>{rows.length} records · click a row for details</span></div>{canWrite&&<button className="primary" onClick={()=>setEditing(null)}>+ New</button>}</div>
   <Table rows={rows} keys={keys} resource={resource} navigate={navigate} onEdit={canWrite?setEditing:null} onDelete={canWrite?del:null}/>
 </section>{editing!==undefined&&<Editor resource={resource} item={editing} onClose={()=>setEditing(undefined)} onSaved={onSaved}/>}</>;
}

function Table({rows,keys,resource,navigate,onEdit,onDelete}){
 const actions=onEdit||onDelete;
 return <div className="table-wrap"><table><thead><tr>{keys.map(k=><th key={k}>{labelize(k)}</th>)}{actions&&<th>Actions</th>}</tr></thead><tbody>{rows.map((r,i)=><tr key={r.id||i} className="clickable-row" onClick={()=>r.id!=null&&navigate(`/${resource}/${r.id}`)} title={r.id!=null?'Open details':''}>{keys.map(k=><td key={k}>{fmt(r[k])}</td>)}{actions&&<td className="row-actions" onClick={e=>e.stopPropagation()}>{onEdit&&<button className="mini" onClick={()=>onEdit(r)}>Edit</button>}{onDelete&&<button className="mini danger" onClick={()=>onDelete(r)}>Delete</button>}</td>}</tr>)}</tbody></table>{!rows.length&&<div className="empty">No records found.</div>}</div>
}

function Detail({resource,item,back,refresh}){
 const canWrite=WRITABLE.has(resource);
 const [editing,setEditing]=useState(false);
 const del=async()=>{ if(!confirm(`Delete this ${singular(resource)}?`))return; try{await crud.remove(resource,item.id); back();}catch(e){alert(e.message)} };
 return <section><div className="section-head"><h2>{labelize(singular(resource))} details</h2><div className="head-actions">{canWrite&&<button className="secondary" onClick={()=>setEditing(true)}>Edit</button>}{canWrite&&<button className="secondary danger" onClick={del}>Delete</button>}<button className="secondary" onClick={back}>← Back</button></div></div>
  <div className="detail-grid">{Object.entries(item).filter(([k])=>k!=='password').map(([k,v])=><div className="detail-field" key={k}><span>{labelize(k)}</span><strong>{fmt(v)}</strong></div>)}</div>
  {editing&&<Editor resource={resource} item={item} onClose={()=>setEditing(false)} onSaved={()=>{setEditing(false);refresh();}}/>}
 </section>;
}

// Generic create/edit form. Fields come from the record (edit) or a per-resource
// template (create); array fields are comma-separated. tenantId/id stay server-side.
function Editor({resource,item,onClose,onSaved}){
 const tmpl=item||templates[resource]||{};
 const fields=Object.keys(tmpl).filter(k=>!['id','tenantId'].includes(k));
 const [form,setForm]=useState(()=>Object.fromEntries(fields.map(k=>[k,Array.isArray(tmpl[k])?tmpl[k].join(', '):(tmpl[k]&&typeof tmpl[k]==='object'?JSON.stringify(tmpl[k]):tmpl[k]??'')])));
 const [err,setErr]=useState(''),[busy,setBusy]=useState(false);
 const set=(k,v)=>setForm(f=>({...f,[k]:v}));
 const save=async()=>{ setBusy(true); setErr('');
   try{
     const body={};
     for(const k of fields){ const isArr=Array.isArray(tmpl[k])||ARRAY_FIELDS.has(k); body[k]=isArr?String(form[k]).split(',').map(s=>s.trim()).filter(Boolean):form[k]; }
     const saved=item?await crud.update(resource,item.id,body):await crud.create(resource,body);
     onSaved(saved);
   }catch(e){setErr(e.message); setBusy(false)}
 };
 return <div className="modal-backdrop" onClick={onClose}><div className="modal" onClick={e=>e.stopPropagation()}>
   <h3>{item?'Edit':'New'} {singular(resource)}</h3>
   {err&&<div className="error">{err}</div>}
   <div className="form-grid">{fields.map(k=><label key={k} className={LONG_FIELDS.has(k)?'wide':''}>{labelize(k)}{LONG_FIELDS.has(k)?<textarea value={form[k]} onChange={e=>set(k,e.target.value)}/>:<input value={form[k]} onChange={e=>set(k,e.target.value)}/>}</label>)}</div>
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
