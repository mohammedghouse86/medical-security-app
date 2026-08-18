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
const listPathForResource=r=>({
 patients:'/patients',doctors:'/doctors',appointments:'/appointments',reports:'/reports',
 prescriptions:'/prescriptions',advice:'/advice',users:'/users',hospitals:'/hospital-settings'
}[r]);

function Login({onLogin}){
 const [u,setU]=useState('apollo.admin'),[p,setP]=useState('Admin@12345'),[e,setE]=useState('');
 const go=async ev=>{ev.preventDefault();try{const x=await api('/auth/login',{method:'POST',body:JSON.stringify({username:u,password:p})});localStorage.setItem('token',x.token);localStorage.setItem('user',JSON.stringify(x.user));history.replaceState({},'', appUrl('/dashboard'));onLogin(x.user)}catch(x){setE(x.message)}};
 return <div className="login"><div className="login-card"><div className="brand"><span>✚</span> MedSecure</div><p className="eyebrow">CARE MANAGEMENT PLATFORM</p><h1>Welcome back</h1><p className="muted">Secure clinical workflows for hospitals and care teams.</p><form onSubmit={go}><label>Username<input value={u} onChange={e=>setU(e.target.value)}/></label><label>Password<input type="password" value={p} onChange={e=>setP(e.target.value)}/></label>{e&&<div className="error">{e}</div>}<button>Sign in</button></form><small>Demo: apollo.admin / Admin@12345</small></div></div>
}

function Unauthorized({goDashboard}) {
 return <div className="unauthorized"><div><div className="lock">403</div><h1>Access restricted</h1><p>You don't have permission to access this area. Your account can only access features assigned to its role.</p><button onClick={goDashboard}>Return to dashboard</button></div></div>
}

function App(){
 const [user,setUser]=useState(()=>JSON.parse(localStorage.getItem('user')||'null'));
 const [path,setPath]=useState(getAppPath());
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
     setErr(''); setDetail(null);
     const dm=detailMatch(p);
     if(dm){
       const item=await api(`/${dm.resource}/${encodeURIComponent(dm.id)}`);
       setDetail(item);
       return;
     }
     if(p==='/dashboard'){
       const [h,pa,a,r,rx]=await Promise.all([api('/hospitals'),api('/patients'),api('/appointments'),api('/reports'),api('/prescriptions')]);
       setData({h,pa,a,r,rx}); return;
     }
     const endpoint={
       '/patients':'/patients','/doctors':'/doctors','/appointments':'/appointments',
       '/reports':'/reports','/prescriptions':'/prescriptions','/advice':'/advice',
       '/users':'/users','/hospital-settings':'/hospitals'
     }[p];
     setData(endpoint?await api(endpoint):null);
   }catch(e){setErr(e.message)}
 }

 if(!user)return <Login onLogin={setUser}/>;
 const logout=()=>{localStorage.clear();setUser(null);history.replaceState({},'',appUrl('/'));setPath('/')};
 if(path==='/unauthorized')return <Unauthorized goDashboard={()=>navigate('/dashboard')}/>;

 const dm=detailMatch(path);
 const current=dm ? routes.find(r=>r.resource===dm.resource) : routeFor(path);
 if(!current.roles.includes(user.role)){history.replaceState({},'',appUrl('/unauthorized')); return <Unauthorized goDashboard={()=>navigate('/dashboard')}/>}

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
     {dm&&detail?<Detail resource={dm.resource} item={detail} back={()=>navigate(listPathForResource(dm.resource))}/>:data&&<Content path={path} data={data} user={user} navigate={navigate}/>}
   </main>
 </div>
}

function Card({title,value,sub}){return <div className="card"><span>{title}</span><strong>{value}</strong><small>{sub}</small></div>}

function Content({path,data,navigate}){
 if(path==='/dashboard')return <><div className="cards"><Card title="Patients" value={data.pa.length} sub="Active records"/><Card title="Appointments" value={data.a.length} sub="Upcoming"/><Card title="Reports" value={data.r.length} sub="Clinical reports"/><Card title="Prescriptions" value={data.rx.length} sub="Active records"/></div><section><div className="section-head"><h2>Recent appointments</h2><span>Live tenant data</span></div><Table rows={data.a} keys={['date','time','status','reason']} resource="appointments" navigate={navigate}/></section></>;
 if(path==='/users')return <section><div className="section-head"><h2>User Management</h2><span>Administrator only</span></div><Table rows={data} keys={Object.keys(data[0]||{}).filter(k=>!['id','password'].includes(k)).slice(0,6)} resource="users" navigate={navigate}/></section>;
 if(path==='/hospital-settings')return <section><div className="section-head"><h2>Hospital Settings</h2><span>Administrator only</span></div><Table rows={data} keys={['id','name','city','specialties']} resource="hospitals" navigate={navigate}/></section>;
 const rows=Array.isArray(data)?data:[];
 const resource=path.slice(1);
 return <section><div className="section-head"><h2>{routeFor(path).name}</h2><span>{rows.length} records · click a row for details</span></div><Table rows={rows} keys={Object.keys(rows[0]||{}).filter(k=>!['id','tenantId'].includes(k)).slice(0,6)} resource={resource} navigate={navigate}/></section>
}

function Table({rows,keys,resource,navigate}){
 return <div className="table-wrap"><table><thead><tr>{keys.map(k=><th key={k}>{k.replace(/([A-Z])/g,' $1')}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={r.id||i} className="clickable-row" onClick={()=>r.id&&navigate(`/${resource}/${r.id}`)} title={r.id?'Open details':''}>{keys.map(k=><td key={k}>{Array.isArray(r[k])?r[k].join(', '):String(r[k]??'—')}</td>)}</tr>)}</tbody></table>{!rows.length&&<div className="empty">No records found.</div>}</div>
}

function Detail({resource,item,back}){
 const label=resource.replace(/s$/,'').replace(/^\w/,c=>c.toUpperCase());
 return <section><div className="section-head"><h2>{label} details</h2><button className="secondary" onClick={back}>← Back to {resource}</button></div><div className="detail-grid">{Object.entries(item).filter(([k])=>k!=='password').map(([k,v])=><div className="detail-field" key={k}><span>{k.replace(/([A-Z])/g,' $1')}</span><strong>{Array.isArray(v)?v.join(', '):String(v??'—')}</strong></div>)}</div></section>
}

createRoot(document.getElementById('root')).render(<App/>);
