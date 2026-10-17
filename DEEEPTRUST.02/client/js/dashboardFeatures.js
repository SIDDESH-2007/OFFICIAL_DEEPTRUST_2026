// Additive controls for existing dashboard views. All scope checks remain server-side.
export function initDashboardFeatures({headers,escapeHtml,openSession}) {
    const api='/api/v1/admin/dashboard/features';
    const safe=escapeHtml;
    const message=(node,text)=>{node.textContent=text;};
    async function request(path,options={}) {
        const response=await fetch(path,{...options,headers:{...headers(),...(options.body?{'Content-Type':'application/json'}:{})}});
        if(!response.ok){const body=await response.json().catch(()=>({}));throw Error(body.detail || 'Request failed ('+response.status+')');}
        return response;
    }
    const today=new Date().toISOString().slice(0,10),past=new Date(Date.now()-29*86400000).toISOString().slice(0,10);
    function addPanel(viewId,kind,title) {
        const view=document.getElementById('view-'+viewId);if(!view)return;
        const panel=document.createElement('div');panel.className='card dashboard-feature-panel';panel.dataset.feature=kind;
        panel.innerHTML=`<h2>${title}</h2><div class="feature-controls">${kind==='audit'||kind==='health'?`<label>From (UTC)<input type="date" data-filter="start" value="${past}"></label><label>Through (UTC)<input type="date" data-filter="end" value="${today}"></label>`:''}${kind==='audit'?'<label>User email<input type="email" data-filter="email" placeholder="All users in your scope"></label>':''}<label>Hospital<select data-filter="organization_id"><option value="">All permitted hospitals</option></select></label><button class="btn btn-secondary" data-refresh>Refresh</button>${kind==='audit'?'<button class="btn btn-primary" data-export>Export CSV</button>':''}</div><p data-feature-status role="status">Loading recorded data…</p><div class="table-responsive" data-feature-body></div>`;
        view.appendChild(panel);
        panel.querySelector('[data-refresh]').addEventListener('click',()=>load(panel));
        panel.querySelector('[data-export]')?.addEventListener('click',()=>exportAudit(panel));
        panel.querySelectorAll('[data-filter]').forEach(input=>input.addEventListener('change',()=>load(panel)));
    }
    for(const id of ['admin-organizations','org-overview'])addPanel(id,'overview','Hospital Access Overview');
    for(const id of ['admin-system-health','org-reports'])addPanel(id,'health','Authentication Outcomes');
    for(const id of ['admin-audit-logs','org-audit'])addPanel(id,'audit','Filtered Audit Export');
    function params(panel){const p=new URLSearchParams();panel.querySelectorAll('[data-filter]').forEach(el=>{if(el.value)p.set(el.dataset.filter,el.value);});return p;}
    function table(columns,rows) {
        return `<table class="data-table"><thead><tr>${columns.map(c=>'<th>'+safe(c)+'</th>').join('')}</tr></thead><tbody>${rows.length?rows.map(row=>'<tr>'+row.map(cell=>'<td>'+safe(String(cell??'Not recorded'))+'</td>').join('')+'</tr>').join(''):'<tr><td colspan="'+columns.length+'">No recorded data for these filters.</td></tr>'}</tbody></table>`;
    }
    const pendingLoads = new WeakMap();
    async function load(panel) {
        const requestId=(pendingLoads.get(panel)||0)+1;pendingLoads.set(panel,requestId);panel.dataset.busy='true';
        const status=panel.querySelector('[data-feature-status]'),body=panel.querySelector('[data-feature-body]');
        message(status,'Loading selected filters…');body.replaceChildren();
        try {
            const kind=panel.dataset.feature,path=kind==='health'?'auth-analytics':kind;
            const data=await (await request(api+'/'+path+'?'+params(panel))).json();
            if(pendingLoads.get(panel)!==requestId)return;
            if(kind==='overview')body.innerHTML=table(['Hospital','Users / roles','Active sessions','Pending accounts','Pending approvals','Open alerts'],data.organizations.map(o=>[o.name,o.users+' / '+Object.entries(o.roles).map(([k,v])=>k+': '+v).join(', '),o.active_sessions,o.pending_accounts,o.pending_requests,o.open_alerts]));
            if(kind==='health') {
                body.innerHTML='<div class="feature-engine-list">'+Object.entries(data.engines).map(([k,v])=>'<span>'+safe(k.replaceAll('_',' '))+': <strong>'+safe(v)+'</strong></span>').join('')+'</div>'+table(['Stage','Verified','Failed','Recovery used','Pending','Not recorded','Failure %'],data.stages.map(s=>[s.stage,s.verified,s.failed,s.recovery_used,s.pending,s.not_recorded,s.failure_rate===null?'No completed attempts':s.failure_rate+'%']));
            }
            if(kind==='audit')body.innerHTML=table(['UTC time','User','Event','Session','Action','Risk','Masked IP'],data.events.slice(0,100).map(e=>[e.timestamp,e.email,e.event_type,e.session_id,e.action,e.risk,e.ip_masked]));
            message(status,kind==='audit'?`${data.count} matching events. Preview shows up to 100; CSV includes all matches.${data.truncated?' Limit exceeded; narrow filters before export.':''}`:kind==='health'?`${data.verification_sessions} verification sessions. ${data.note}${data.truncated?' Latest 10,000 only; narrow dates.':''}`:'Updated '+new Date().toLocaleTimeString());
        } catch(error){if(pendingLoads.get(panel)===requestId){body.replaceChildren();message(status,error.message);}}finally{if(pendingLoads.get(panel)===requestId)panel.dataset.busy='false';}
    }
    async function exportAudit(panel) {
        const button=panel.querySelector('[data-export]');button.disabled=true;
        try {
            const query=params(panel);query.set('download','true');
            const response=await request(api+'/audit?'+query),url=URL.createObjectURL(await response.blob());
            const link=document.createElement('a');link.href=url;link.download='DeepTrust-audit.csv';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
            message(panel.querySelector('[data-feature-status]'),'Filtered audit CSV downloaded.');
        } catch(error){message(panel.querySelector('[data-feature-status]'),error.message);}finally{button.disabled=false;}
    }
    async function populateHospitals(){
        try {
            const data=await (await request(api+'/overview')).json();
            document.querySelectorAll('[data-feature] select[data-filter="organization_id"]').forEach(select=>{for(const org of data.organizations){const option=document.createElement('option');option.value=org.organization_id;option.textContent=org.name;select.appendChild(option);}});
        }catch{}
    }
    document.addEventListener('deeptrust:view',event=>document.querySelectorAll('#view-'+event.detail+' [data-feature]').forEach(load));
    const drawer=document.getElementById('sessionDetailsDrawer'),footer=drawer?.querySelector('.drawer-footer');
    if(footer){const button=document.createElement('button');button.id='sessionDrawerReverifyBtn';button.className='btn btn-secondary';button.textContent='Request Re-verification';footer.appendChild(button);}
    document.addEventListener('deeptrust:session',event=>{
        const s=event.detail,button=document.getElementById('sessionDrawerReverifyBtn');if(!button)return;
        button.textContent='Request Re-verification';
        button.disabled=!['ACTIVE','IDLE'].includes(s.status);
        button.onclick=async()=>{
            if(!confirm('End this session and require a fresh five-stage login?'))return;
            button.disabled=true;
            try{await request('/api/v1/admin/sessions/'+encodeURIComponent(s.session_id)+'/reverify',{method:'POST',body:JSON.stringify({reason:'Administrator requested full authentication'})});button.textContent='Re-verification required';openSession(s.session_id);}
            catch(error){button.disabled=false;alert(error.message);}
        };
    });
    document.addEventListener('deeptrust:alert',event=>{
        const evt=event.detail,box=document.getElementById('drawerAuditTimeline');if(!box)return;
        document.getElementById('featureAlertLinks')?.remove();const controls=document.createElement('div');controls.id='featureAlertLinks';controls.className='feature-controls';
        const status=document.createElement('p');status.textContent=evt.auth_session_id?'Correlated session available.':'No completed login session recorded for this alert.';controls.appendChild(status);
        if(evt.auth_session_id){
            const session=document.createElement('button');session.className='btn btn-secondary';session.textContent='View Session';session.onclick=()=>{document.getElementById('investigationDrawer')?.classList.remove('open');openSession(evt.auth_session_id);};controls.appendChild(session);
            const audit=document.createElement('button');audit.className='btn btn-secondary';audit.textContent='View Audit';audit.onclick=async()=>{
                try{const data=await (await request('/api/v1/admin/audit/identity/'+encodeURIComponent(evt.identity_id)+'/session/'+encodeURIComponent(evt.auth_session_id)+'/timeline')).json();box.innerHTML=table(['UTC time','Event','Action'],[...data.authentication_timeline,...data.activity_timeline].map(e=>[e.timestamp,e.event_type,e.action]));}
                catch(error){message(status,error.message);}
            };controls.appendChild(audit);
        }
        box.before(controls);
    });
    populateHospitals();document.querySelectorAll('.view-section.active [data-feature]').forEach(load);
}
