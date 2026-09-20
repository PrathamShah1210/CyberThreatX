'use strict';
const $ = id => document.getElementById(id);
const state = {csrf:'', schema:{}, table:null, page:1, q:'', rows:[], total:0, editing:null, generation:0};
const names = {iocs:'Indicators of compromise',threat_actors:'Threat actors',incident_ioc:'Incident indicators',incident_vuln:'Incident vulnerabilities',actor_campaign:'Actor campaigns',m_att_sys:'Affected systems',user_role:'User roles',data_breach_datatypes:'Breach data types'};
const title = value => names[value] || value.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());
function el(tag,text,cls){ const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e; }
function notice(text,error=false){ $('notice').textContent=text; $('notice').className=error?'error':''; $('notice').hidden=false; }
async function api(path,options={}){
 const response=await fetch('/api/'+path,{...options,headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf,...options.headers}});
 const result=await response.json();
 if(!response.ok){if(response.status===401 && path!=='login')showLogin();throw new Error(result.error||'Request failed.');}
 return result;
}
function showLogin(){ $('workspace').hidden=true;$('login').hidden=false; }
function keyFor(row){return Object.fromEntries(state.schema[state.table].pk.map(k=>[k,row[k]]));}
function pretty(value){return value===null?'—':String(value);}
function badge(value){return el('span',pretty(value),'badge '+String(value||'').toLowerCase());}
async function initialize(){
 try{
  const s=await api('session');state.csrf=s.csrf;state.role=s.role;state.username=s.username;
  if(!s.authenticated){showLogin();return;}
  const result=await api('schema');state.schema=Object.fromEntries(result.tables.map(t=>[t.name,t]));
  $('login').hidden=true;$('workspace').hidden=false;buildNav();document.querySelector('.sidebar-foot strong').textContent=state.username;document.querySelector('.sidebar-foot span').textContent=title(state.role);await (state.role==='viewer'?workspacePage('research'):workspacePage('desk'));
 }catch(e){$('login-error').textContent=e.message;showLogin();}
}
function buildNav(){
 const nav=$('navigation');nav.replaceChildren();
 const add=(table,label)=>{const b=el('button',label);b.dataset.table=table||'';b.onclick=()=>navigate(table);nav.append(b);};
 if(state.role!=='viewer')add(null,'Overview');
 for(const page of ['public',...(state.role!=='viewer'?['desk']:[]),'research','reports',...(state.role==='admin'?['accounts','sources','imports','audit']:[])]){const b=el('button',title(page));b.onclick=()=>workspacePage(page);nav.append(b);}
 const groups={Intelligence:['incidents','vulnerabilities','iocs','threats','threat_actors','campaigns','sources'],Relationships:['incident_ioc','incident_vuln','actor_campaign','targets'],Evidence:['security_incidents','data_breaches','malware_incidents','attachments','attachment_hashes','threat_actor_aliases','campaign_objectives','source_urls','data_breach_datatypes','m_att_sys'],People:['users','roles','permissions','user_role','user_phones']};
 for(const [group,tables]of Object.entries(groups)){const visible=tables.filter(t=>state.schema[t]);if(visible.length)nav.append(el('h3',group));visible.forEach(t=>add(t,title(t)));}
}
async function navigate(table){
 $('extras').hidden=true;state.hiddenColumns=new Set();state.table=table;state.sort='';state.direction='asc';state.filter='';state.page=1;state.q='';state.generation++;$('search').value='';$('notice').hidden=true;
 for(const b of $('navigation').querySelectorAll('button'))b.classList.toggle('active',b.dataset.table===(table||''));
 $('dashboard').hidden=!!table;$('records').hidden=!table;
 $('title').textContent=table?title(table):'Intelligence overview';
 $('eyebrow').textContent=table?'INTELLIGENCE / '+title(table).toUpperCase():'OPERATIONS / OVERVIEW';
 $('subtitle').textContent=table?'Browse and manage records in your PostgreSQL database.':'Live records from your connected PostgreSQL database.';
 if(table==='permissions'||table==='roles'||table==='users')$('subtitle').textContent='Project directory records. Website sign-in is configured separately.';
 $('column-options').replaceChildren();if(table)for(const c of state.schema[table].columns){const label=el('label',title(c.name)),input=el('input');input.type='checkbox';input.checked=true;input.onchange=()=>{if(input.checked)state.hiddenColumns.delete(c.name);else state.hiddenColumns.add(c.name);loadRows().catch(e=>notice(e.message,true));};label.prepend(input);$('column-options').append(label);}
 const filter=$('record-filter');filter.replaceChildren();const all=el('option','All classifications');all.value='';filter.append(all);const field=table&&state.schema[table].columns.find(c=>['severity','status'].includes(c.name));state.filterField=field?.name;filter.hidden=!field;
 if(field){const options=field.name==='severity'?['Critical','High','Medium','Low','Unknown','CRITICAL','HIGH','MEDIUM','LOW']:['Open','Investigating','Resolved','Closed'];options.forEach(x=>{const o=el('option',x);o.value=x;filter.append(o);});}
 await reload();
}
async function reload(){try{if(state.table)await loadRows();else await dashboard();}catch(e){notice(e.message,true);}}
function bars(target,values){
 const root=$(target);root.replaceChildren();const max=Math.max(...values.map(x=>Number(x.count)),1);
 if(!values.length){root.append(el('p','No incidents recorded yet. Add an incident to begin.','empty'));return;}
 for(const v of values){const row=el('div',undefined,'bar-row');row.append(el('span',v.label));const track=el('div',undefined,'bar-track');const progress=el('progress');progress.max=max;progress.value=Number(v.count);progress.setAttribute('aria-label',v.label);track.append(progress);row.append(track,el('strong',Number(v.count).toLocaleString()));root.append(row);}
}
async function dashboard(){
 const generation=++state.generation;const data=await api('dashboard');if(generation!==state.generation)return;
 $('subtitle').textContent='Connected to '+data.database+' · Refresh to see the latest database changes.';
 $('metrics').replaceChildren();
 for(const t of ['vulnerabilities','incidents','iocs','threat_actors']){const card=el('button',undefined,'metric');card.append(el('span',title(t)),el('strong',data.counts[t].toLocaleString()),el('small','View records →'));card.onclick=()=>navigate(t);$('metrics').append(card);}
 bars('severity',data.severity);bars('statuses',data.status);$('latest').replaceChildren();
 if(!data.latest.length){$('latest').append(el('p','No incidents yet. Your vulnerability records are available in the navigation.','empty'));return;}
 const wrap=el('div',undefined,'table-wrap'),table=el('table'),body=el('tbody');
 for(const r of data.latest){const tr=el('tr');tr.append(el('td','#'+r.incident_id),el('td',r.incident_type));const status=el('td');status.append(badge(r.status));tr.append(status,el('td',r.description||'No description'));body.append(tr);}
 table.append(body);wrap.append(table);$('latest').append(wrap);
}
async function loadRows(){
 const table=state.table;const generation=++state.generation;
 $('table-body').replaceChildren();$('row-count').textContent='Loading…';
 const data=await api('tables/'+table+'?'+new URLSearchParams({page:state.page,q:state.q,sort:state.sort||'',direction:state.direction||'asc',...(state.filterField?{[state.filterField]:state.filter||''}:{})}));if(generation!==state.generation)return;
 state.rows=data.rows;state.total=data.total;
 $('row-count').textContent=data.total.toLocaleString()+' records';$('export').href='/api/export/'+table+'?'+new URLSearchParams({q:state.q,...(state.filterField?{[state.filterField]:state.filter||''}:{})});
 const meta=state.schema[table];const head=el('tr');
 for(const c of meta.columns.filter(c=>!state.hiddenColumns.has(c.name))){const th=el('th');const b=el('button',title(c.name)+(state.sort===c.name?(state.direction==='asc'?' ↑':' ↓'):''),'sort-button');b.onclick=()=>{state.direction=state.sort===c.name&&state.direction==='asc'?'desc':'asc';state.sort=c.name;reload();};th.append(b);head.append(th);}head.append(el('th','Actions'));$('table-head').replaceChildren(head);
 const body=$('table-body');body.replaceChildren();
 for(const row of data.rows){const tr=el('tr');for(const c of meta.columns.filter(c=>!state.hiddenColumns.has(c.name))){const td=el('td');td.title=pretty(row[c.name]);if(['severity','status'].includes(c.name))td.append(badge(row[c.name]));else td.textContent=pretty(row[c.name]);tr.append(td);}
  const actions=el('td');for(const [label,fn]of [['View',()=>details(row)],['Edit',()=>edit(row)],['Delete',()=>remove(row)]]){if(label==='Delete'&&state.role!=='admin')continue;if(label==='Edit'&&!meta.columns.some(c=>!meta.pk.includes(c.name)))continue;const b=el('button',label,'row-action'+(label==='Delete'?' danger':''));b.onclick=fn;actions.append(b);}tr.append(actions);body.append(tr);
 }
 if(!data.rows.length){const tr=el('tr'),td=el('td',state.q?'No matching records. Try a different search.':'No records yet. Add the first record.','empty');td.colSpan=meta.columns.length+1;tr.append(td);body.append(tr);}
 $('page-info').textContent='Page '+state.page+' of '+Math.max(1,Math.ceil(data.total/25));$('previous').disabled=state.page<=1;$('next').disabled=state.page*25>=data.total;
}
function details(row){$('detail-fields').replaceChildren();for(const [key,value] of Object.entries(row))$('detail-fields').append(el('dt',title(key)),el('dd',pretty(value)));$('details').showModal();}
function edit(row=null){
 state.editing=row;$('editor-title').textContent=row?'Edit record':'Add record';$('editor-table').textContent=title(state.table);$('form-error').textContent='';$('fields').replaceChildren();$('save').disabled=false;
 const meta=state.schema[state.table];
 for(const c of meta.columns){
  const generated=c.default&&c.default.startsWith('nextval(');if(generated&&!row)continue;
  const label=el('label',title(c.name)+(c.nullable||c.default?'':' *'));label.dataset.field=c.name;
  let input;
  if(c.type==='text'){input=el('textarea');label.classList.add('wide');}else{input=el('input');input.type=c.type.includes('integer')?'number':c.type==='date'?'date':c.type.startsWith('timestamp')?'datetime-local':'text';if(input.type==='number')input.step='1';}
  input.name=c.name;input.required=!c.nullable&&!c.default;input.disabled=!!row&&meta.pk.includes(c.name);if(c.max_length)input.maxLength=c.max_length;
  if(row&&row[c.name]!==null){let value=String(row[c.name]);if(c.type==='date')value=new Date(value).toISOString().slice(0,10);if(c.type.startsWith('timestamp'))value=new Date(value).toISOString().slice(0,19);input.value=value;}
  if(!row&&c.name==='detected_at'){const now=new Date();input.value=new Date(now-now.getTimezoneOffset()*60000).toISOString().slice(0,16);}
  if(!row&&c.default&&!generated)input.placeholder='Database default: '+c.default;
  label.append(input);
  const fk=meta.foreign_keys.find(f=>f.column===c.name);
  if(fk&&!input.disabled){const hint=el('span','Select an existing '+title(fk.target)+' record, or enter its ID.','field-hint');label.append(hint);const search=el('input');search.type='search';search.placeholder='Find '+title(fk.target)+'…';search.setAttribute('aria-label','Find linked '+title(fk.target));const choices=el('div',undefined,'fk-options');label.append(search,choices);let timer,seq=0;
   const lookup=async()=>{const current=++seq;try{const result=await api(fk.target==='ctx_accounts'?'assignees':'tables/'+fk.target+'?'+new URLSearchParams({q:search.value,limit:8}));if(current!==seq)return;choices.replaceChildren();for(const item of result.rows){const value=item[fk.target_column];const display=item.cve_id||item.username||item.name||item.actor_name||item.source_name||item.raw_data||item.description||item.role_name||Object.values(item).join(' · ');const b=el('button',value+' · '+String(display).slice(0,110));b.type='button';b.onclick=()=>{input.value=value;choices.replaceChildren();search.value='';};choices.append(b);}if(!result.rows.length)choices.append(el('span','No matches.','field-hint'));}catch(e){$('form-error').textContent=e.message;}};
   search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(lookup,250);});search.addEventListener('focus',lookup);
  }
  $('fields').append(label);
 }
 $('editor').showModal();
}
async function save(event){
 event.preventDefault();$('save').disabled=true;$('form-error').textContent='';
 try{const values={};const meta=state.schema[state.table];for(const c of meta.columns){const input=$('record-form').elements.namedItem(c.name);if(!input||input.disabled)continue;const value=input.value;if(!value&&!state.editing&&c.default)continue;values[c.name]=value===''&&c.nullable?null:value;}
  const payload={values};if(state.editing)payload.key=keyFor(state.editing);
  await api('tables/'+state.table,{method:state.editing?'PUT':'POST',body:JSON.stringify(payload)});
  $('editor').close();await loadRows();notice('Saved to PostgreSQL.');
 }catch(e){$('form-error').textContent=e.message;}finally{$('save').disabled=false;}
}
async function remove(row){
 if(!confirm('Delete this record from PostgreSQL? Linked child records may also be deleted by your database cascade rules.'))return;
 try{await api('tables/'+state.table,{method:'DELETE',body:JSON.stringify({key:keyFor(row)})});if(state.rows.length===1&&state.page>1)state.page--;await loadRows();notice('Record deleted from PostgreSQL.');}catch(e){notice(e.message,true);}
}
$('login-form').onsubmit=async event=>{event.preventDefault();$('login-error').textContent='';const submit=event.submitter;submit.disabled=true;try{const form=new FormData(event.target);const s=await api('login',{method:'POST',body:JSON.stringify(Object.fromEntries(form))});state.csrf=s.csrf;event.target.reset();await initialize();}catch(e){$('login-error').textContent=e.message;}finally{submit.disabled=false;}};
$('logout').onclick=async()=>{try{await api('logout',{method:'POST'});await initialize();}catch(e){notice(e.message,true);}};
$('refresh').onclick=()=>initialize();$('view-incidents').onclick=()=>navigate('incidents');$('add').onclick=()=>edit();$('record-form').onsubmit=save;
$('close-editor').onclick=$('cancel-editor').onclick=()=>$('editor').close();$('close-details').onclick=()=>$('details').close();
$('previous').onclick=()=>{state.page--;reload();};$('next').onclick=()=>{state.page++;reload();};
let searchTimer;$('search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.q=$('search').value;state.page=1;reload();},300);};
$('record-filter').onchange=()=>{state.filter=$('record-filter').value;state.page=1;reload();};
initialize();

// Personal workspace, reports and administration use the same authenticated API.
async function workspacePage(page){
 if(page==='public'){window.location.href='/';return;}
 state.table=null;state.generation++;$('dashboard').hidden=true;$('records').hidden=true;$('extras').hidden=false;$('extras').replaceChildren();$('title').textContent=title(page);$('subtitle').textContent='Signed in as '+state.username+' · '+state.role;$('notice').hidden=true;
 const root=$('extras');
 const button=(text,fn)=>{const b=el('button',text,'secondary');b.onclick=async()=>{try{await fn();}catch(e){notice(e.message,true);}};return b;};
 const listing=(rows,action)=>{const wrap=el('div',undefined,'table-wrap panel'),t=el('table');if(!rows.length){root.append(el('p','Nothing here yet.','empty'));return;}const h=el('tr');Object.keys(rows[0]).forEach(k=>h.append(el('th',title(k))));if(action)h.append(el('th','Actions'));t.append(h);rows.forEach(r=>{const tr=el('tr');Object.values(r).forEach(v=>tr.append(el('td',v===null?'—':typeof v==='object'?JSON.stringify(v):String(v))));if(action){const td=el('td');action(r,td);tr.append(td);}t.append(tr);});wrap.append(t);root.append(wrap);};
 if(page==='desk'){await intelligenceDesk();return;}
 if(page==='sources'){await sourceManagement();return;}
 if(page==='research'){
  const form=el('form',undefined,'panel research-form'),kind=el('select');for(const k of ['watchlist','bookmark','note','search','review']){const o=el('option',title(k));o.value=k;kind.append(o);}const name=el('input');name.placeholder='Title / technology name';name.required=true;name.maxLength=200;const content=el('textarea');content.placeholder='Notes, CVE identifier, or saved search text';const submit=el('button','Save to my workspace','primary');submit.type='submit';form.append(kind,name,content,submit);form.onsubmit=async e=>{e.preventDefault();try{await api('research',{method:'POST',body:JSON.stringify({kind:kind.value,title:name.value,content:content.value})});await workspacePage(page);}catch(e){notice(e.message,true);}};root.append(form);
  const data=await api('research');listing(data.rows,(r,td)=>{td.append(button('Delete',async()=>{await api('research',{method:'DELETE',body:JSON.stringify({id:r.id})});await workspacePage(page);}));if(r.kind==='review')td.append(button(r.status==='done'?'Reopen':'Complete',async()=>{await api('research',{method:'PUT',body:JSON.stringify({id:r.id,status:r.status==='done'?'open':'done'})});await workspacePage(page);}));if(r.kind==='search'&&state.role!=='viewer')td.append(button('Run search',async()=>{await navigate('vulnerabilities');$('search').value=r.content||r.title;state.q=$('search').value;await reload();}));});
  root.append(el('h2','Possible watchlist matches'));const matches=await api('watchlist-matches');root.append(el('p',matches.note,'muted'));listing(matches.rows);
 }else if(page==='accounts'){
  const form=el('form',undefined,'panel research-form');const username=el('input');username.placeholder='Username';username.required=true;const password=el('input');password.type='password';password.placeholder='Password (12+ characters)';password.minLength=12;const role=el('select');['viewer','analyst','admin'].forEach(r=>{const o=el('option',title(r));o.value=r;role.append(o);});const active=el('input');active.type='checkbox';active.checked=true;const label=el('label','Account active');label.append(active);const submit=el('button','Create account','primary');let editing=null;form.append(username,password,role,label,submit);form.onsubmit=async e=>{e.preventDefault();try{await api('accounts',{method:editing?'PUT':'POST',body:JSON.stringify({id:editing,username:username.value,password:password.value,role:role.value,active:active.checked})});await workspacePage(page);}catch(e){notice(e.message,true);}};root.append(form);listing((await api('accounts')).rows,(r,td)=>td.append(button('Edit / reset password',()=>{editing=r.id;username.value=r.username;role.value=r.role;active.checked=r.active;password.value='';submit.textContent='Update account';username.focus();})));
 }else if(page==='imports'){
  root.append(el('p','Import public CISA KEV intelligence. Existing CVE descriptions and severity values are preserved. New entries have Unknown severity unless already classified.','muted'));
  const b=button('Synchronize CISA KEV',async()=>{b.disabled=true;b.textContent='Importing…';try{const r=await api('imports',{method:'POST'});await workspacePage(page);notice('Imported '+r.records+' KEV entries.');}finally{b.disabled=false;b.textContent='Synchronize CISA KEV';}});root.append(b);listing((await api('imports')).rows);
 }else if(page==='audit')listing((await api('audit')).rows);
 else{
  const select=el('select');const views=state.role==='viewer'?['vw_viewer_intelligence']:['vw_vulnerability_summary','vw_active_incidents','vw_ioc_context','vw_campaign_overview','vw_analyst_workload','vw_viewer_intelligence'];views.forEach(v=>{const o=el('option',title(v.replace('vw_','')));o.value=v;select.append(o);});root.append(select,el('p','SQL view results · Up to 200 rows. Use Vulnerabilities for full search and pagination.','muted'));const output=el('div');root.append(output);select.onchange=async()=>{try{root.querySelectorAll('.table-wrap,.empty').forEach(e=>e.remove());listing((await api('reports/'+select.value)).rows);}catch(e){notice(e.message,true);}};await select.onchange();
 }
}
