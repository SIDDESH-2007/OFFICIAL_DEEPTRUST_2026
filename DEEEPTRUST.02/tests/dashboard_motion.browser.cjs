const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const {chromium}=require(root+'/node_modules/@playwright/test');
const output=path.join(root,'test-results','dashboard-motion');fs.mkdirSync(output,{recursive:true});
const results=[];
async function check(name,fn){try{await fn();results.push({name,passed:true});console.log('PASS '+name)}catch(e){results.push({name,passed:false,error:e.message});console.log('FAIL '+name+': '+e.message)}}
(async()=>{
 const server=http.createServer((req,res)=>{const file=path.resolve(root,'client','.'+new URL(req.url,'http://localhost').pathname);if(!file.startsWith(path.resolve(root,'client')+path.sep))return res.writeHead(403).end();fs.readFile(file,(err,body)=>{if(err)return res.writeHead(404).end();res.writeHead(200,{'Content-Type':{'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream'});res.end(body)});});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser;
 try{
  browser=await chromium.launch({headless:true,channel:'chrome'});
  const page=await browser.newPage({viewport:{width:1440,height:900}});page.setDefaultTimeout(5000);const errors=[],writes=[];
  page.on('pageerror',e=>errors.push(e.message));
  let month=3;
  await page.route('**/*',async route=>{
   const url=new URL(route.request().url()),p=url.pathname;
   if(url.hostname!=='127.0.0.1')return route.abort();if(!p.startsWith('/api/'))return route.continue();
   if(route.request().method()!=='GET')writes.push(p);
   let body={},status=200;
   const org={organization_id:'qa-hospital',name:'QA Medical Center',domain:'qa.example.test',industry:'Healthcare',status:'ACTIVE',identities_count:2,users:2,roles:{doctor:1,admin:1},active_sessions:1};
   if(p==='/api/v1/auth/me')body={user:{id:'qa-user',email:'qa@example.test',full_name:'Motion QA',role:'DEEPTRUST_OWNER'}};
   else if(p.endsWith('/features/overview'))body={organizations:[org]};
   else if(p.endsWith('/features/audit'))body={events:[],count:0};
   else if(p.endsWith('/features/auth-analytics'))body={engines:{voice:'Operational'},stages:[],verification_sessions:0,note:'QA fixture'};
   else if(p==='/api/v1/admin/overview')body={organizations_protected:1,total_identities:2,active_sessions:1,high_risk_events:1};
   else if(p==='/api/v1/admin/accounts')body={accounts:[{id:'qa-user',full_name:'Motion QA',email:'qa@example.test',role:'DEEPTRUST_ADMIN',account_type:'DEEPTRUST_ADMIN',status:'active',mfa_enabled:true,created_at:1791600000},{id:'other',full_name:'Doctor QA',email:'doctor@example.test',role:'doctor',status:'active'}]};
   else if(p==='/api/v1/admin/organizations')body={organizations:[org]};
   else if(p==='/api/v1/admin/identity-security')body={metrics:{total_identities:1,face_enrolled:1,voice_enrolled:1,mfa_enabled:1},identities:[{name:'Motion QA',email:'qa@example.test',role:'DEEPTRUST_ADMIN',face_enrolled:true,voice_enrolled:true,mfa_enabled:true,status:'ACTIVE'}]};
   else if(p.includes('system-health'))body={engines:{face_presence:{status:'Operational'},face_identity:{status:'Operational'},liveness:{status:'Operational'},voice_biometrics:{status:'Unavailable'},authenticator_mfa:{status:'Operational'},zero_trust_risk:{status:'Operational'}}};
   else if(p==='/api/v1/admin/integrations')body={integrations:[{name:'QA Connector',type:'SSO',endpoint:'https://qa.example.test',status:'Connected',connected:true,detail:'QA fixture'},{name:'Disconnected QA',type:'SSO',endpoint:'https://offline.example.test',status:'Disconnected',connected:false}]};
   else if(p==='/api/v1/admin/risk-evaluations')body={metrics:{allowed:1,blocked:1},evaluations:[{timestamp:new Date().toISOString(),user_id:'qa-user',risk_score:78,risk_level:'HIGH',decision:'BLOCK',reason_codes:['QA_INDICATOR']}]};
   else if(p==='/api/v1/security-events')body={events:[{event_id:'qa-event',timestamp:new Date().toISOString(),identity:'qa@example.test',event_type:'QA_ALERT',risk_score:78,severity:'HIGH',status:'OPEN'}]};
   else if(p.includes('/features/alerts/'))body={event:{event_id:'qa-event',identity:'qa@example.test',event_type:'QA_ALERT',severity:'HIGH',risk_score:78,audit_timeline:[{action:'QA recorded action',timestamp:new Date().toISOString()}]}};
   else if(p.startsWith('/api/v1/security-events/'))body={event:{event_id:'qa-event',identity:'qa@example.test',event_type:'QA_ALERT',severity:'HIGH',risk_score:78},timeline:[]};
   else if(p.includes('/sessions/detail/'))body={session:{session_id:'qa-session',email:'qa@example.test',role:'doctor',organization_name:org.name,status:'ACTIVE',duration_running:true,identity_id:'qa-user'},network_context:{},device_context:{browser:'Chrome',os:'Windows',category:'DESKTOP',device_trust:'TRUSTED'},security:{risk_score:21,risk_level:'LOW'},assurance:{face:'VERIFIED',voice:'VERIFIED',mfa:'VERIFIED'},behavior:{status:'NORMAL',sample_count:120,scroll_events:8,swipe_count:2}};
   else if(p==='/api/v1/admin/sessions/control')body={sessions:[{session_id:'qa-session',email:'qa@example.test',status:'ACTIVE',role:'doctor',risk_score:21,risk_level:'LOW',duration_running:true}],summary:{}};
   else if(p.endsWith('/reports/monthly')){month=Number(url.searchParams.get('month'))||3;body={metrics:{total_login_attempts:month*10,successful_authentications:month*8,blocked_attempts:month*2,generated_at:new Date().toISOString(),organizations:[{name:org.name,auth_count:month*10,successful_access:month*8,blocked_access:month*2,security_events:1}]}};}
   else if(p==='/api/v1/ai/query'){await new Promise(r=>setTimeout(r,180));body={title:'QA analysis',analysis:'Fixture response',disclaimer:'QA only',evidence:['Recorded QA evidence'],recommendations:['Review QA event']};}
   else if(p==='/api/v1/notifications')body={notifications:[],unread_count:0};
   else if(p==='/api/v1/admin/audit/identities')body={identities:[]};
   else if(p.includes('/integrity'))body={integrity:{status:'VERIFIED',signed_records:1}};
   else if(p.startsWith('/api/v1/session/'))body={status:'ACTIVE'};
   else status=403;
   await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
  });
  await page.addInitScript(()=>{sessionStorage.setItem('dt_admin_token','isolated-fixture');sessionStorage.setItem('dt_admin_token_exp',String(Date.now()+3600000));sessionStorage.setItem('dt_admin_token_storage','session');});
  await page.goto(`http://127.0.0.1:${server.address().port}/dashboard.html`);await page.locator('#deeptrustAdminNav').waitFor({state:'visible'});
  const nav=async view=>{await page.locator(`#deeptrustAdminNav [data-view="${view}"]`).click();await page.waitForTimeout(140);};
  await check('Overview shared-element card uses original navigation',async()=>{await page.locator('#adminKpiOrgs').click();await page.locator('#view-admin-organizations.active').waitFor();assert.equal(await page.locator('.view-section.active').count(),1);});
  await check('Organization row preserves original detail drawer',async()=>{await page.locator('#adminOrgsTable tbody tr').first().click();await page.locator('#orgDetailsDrawer.open').waitFor();assert.match(await page.locator('#orgDrawerBody').textContent(),/QA Medical Center/);await page.locator('#orgDrawerCloseBtn').click();});
  await nav('admin-accounts');
  await check('Account keyboard drawer is read-only and close restores focus',async()=>{const row=page.locator('#adminAccountsTable tbody tr').first();await row.focus();await row.press('Enter');await page.locator('#dtAccountMotionDrawer').waitFor({state:'visible'});assert.match(await page.locator('#dtAccountMotionDrawer').textContent(),/qa@example.test/);assert.equal(await page.locator('#dtAccountMotionDrawer input').count(),0);await page.keyboard.press('Escape');assert.equal(await page.locator('#dtAccountMotionDrawer').isVisible(),false);assert.equal(await row.evaluate(n=>n===document.activeElement),true);assert.equal(await row.locator('.btn-action-disable').isDisabled(),true);});
  await nav('admin-identity-sec');
  await check('Existing action button keyboard events are not intercepted',async()=>{const untouched=await page.locator('#adminAccountsTable .btn-action-reset-mfa').first().evaluate(node=>{const event=new KeyboardEvent('keydown',{key:'Enter',bubbles:true,cancelable:true});node.dispatchEvent(event);return !event.defaultPrevented;});assert.equal(untouched,true);});
  await check('Verified identity icons follow recorded enrollment',async()=>assert.equal(await page.locator('#adminIdentitySecurityTable .dt-verify-mark').count(),3));
  await nav('admin-risk-engine');
  await check('Risk gauge reflects exact backend score',async()=>{assert.match(await page.locator('#adminRiskTable tbody').textContent(),/78\/100/);assert.equal(await page.locator('#adminRiskTable .dt-risk-track>span').evaluate(n=>n.style.transform),'scaleX(0.78)');});
  await nav('admin-threat-investigation');
  await check('Threat investigation reveals the selected recorded timeline',async()=>{await page.locator('#adminThreatsTable button').filter({hasText:'Investigate'}).click();await page.locator('#investigationDrawer.open').waitFor();await page.locator('#drawerAuditTimeline').filter({hasText:'QA recorded action'}).waitFor();assert.equal((await page.locator('#drawerEventId').textContent()).trim(),'qa-event');await page.locator('#drawerCloseBtn').click();});
  await nav('admin-system-health');
  await check('Health rings distinguish unavailable from operational',async()=>{assert.ok(await page.locator('#adminSystemHealthGrid [data-state="healthy"]').count()>0);assert.ok(await page.locator('#adminSystemHealthGrid [data-state="unavailable"]').count()>0);assert.equal(await page.locator('#adminSystemHealthGrid [data-state="checking"]').count(),0);});
  await nav('admin-integrations');
  await check('Handshake only confirms backend-connected integrations',async()=>{assert.equal(await page.locator('.dt-handshake[data-connected="true"]').count(),1);assert.equal(await page.locator('.dt-handshake[data-connected="false"]').count(),1);});
  await nav('admin-reports');
  await check('Report bars use real returned values and update on month change',async()=>{await page.locator('.dt-report-chart').waitFor();await page.locator('#reportMonthSelect').selectOption('2');await page.waitForTimeout(180);assert.equal((await page.locator('#repTotalLogins').textContent()).trim(),'20');assert.equal(await page.locator('.dt-report-bar').first().getAttribute('title'),'success: 16');});
  await nav('admin-copilot');
  await check('Copilot dots exist only during actual pending query',async()=>{await page.locator('#copilotInput').fill('QA query');await page.locator('#copilotSubmitBtn').click();await page.locator('.dt-thinking-dots').waitFor();await page.locator('.copilot-message.agent').filter({hasText:'Fixture response'}).waitFor();await page.waitForTimeout(50);assert.equal(await page.locator('.dt-thinking-dots').count(),0);});
  await nav('admin-session-control');
  await check('Unchanged polling labels and live clocks do not rescan tables',async()=>{
   await page.waitForTimeout(400);
   const reads=await page.evaluate(async()=>{
    const original=Element.prototype.getClientRects;let count=0;
    Element.prototype.getClientRects=function(...args){count++;return original.apply(this,args);};
    try{for(let i=0;i<5;i++){
     document.getElementById('scMonitorStatus').textContent='Live session monitoring';
     document.getElementById('scMonitorUpdated').textContent='QA tick '+i;
     const kpi=document.getElementById('scKpiActive');kpi.textContent=kpi.textContent;
     await new Promise(r=>setTimeout(r,25));
    }await new Promise(r=>setTimeout(r,80));return count;}finally{Element.prototype.getClientRects=original;}
   });assert.ok(reads<10,'Polling triggered '+reads+' geometry reads');
  });
  await check('Session connection and Canvas use returned session metrics only',async()=>{await page.locator('#adminSessionControlTable button').filter({hasText:/Details|View/}).first().click();await page.locator('#sessionDetailsDrawer.open').waitFor();await page.locator('.dt-session-connection').waitFor();assert.match(await page.locator('.dt-session-connection').textContent(),/qa@example.test/);assert.match(await page.locator('.dt-behavior-chart canvas').getAttribute('aria-label'),/Pointer samples: 120/);await page.locator('#sessionDrawerCloseBtn').click();});
  await check('Toast insertion and removal reflow preserve dismiss behavior',async()=>{await page.evaluate(()=>{const host=document.createElement('div');host.id='staff-login-popups';host.style.cssText='position:fixed;right:24px;top:88px;display:grid;gap:12px;z-index:10000';document.body.append(host);for(let i=0;i<3;i++){const popup=document.createElement('div');popup.textContent='QA login '+i;const b=document.createElement('button');b.textContent='Dismiss';b.onclick=()=>popup.remove();popup.append(b);host.append(popup);}});await page.locator('#staff-login-popups button').first().click();assert.equal(await page.locator('#staff-login-popups>div').count(),2);});
  await check('Rapid section switching keeps only latest view active',async()=>{await page.evaluate(()=>{for(const id of ['admin-accounts','admin-risk-engine','admin-reports','admin-audit-logs'])document.querySelector(`[data-view="${id}"]`).click();});await page.waitForTimeout(150);assert.equal(await page.locator('.view-section.active').getAttribute('id'),'view-admin-audit-logs');assert.equal(await page.locator('.view-section.active').count(),1);});
  await check('Reduced motion cancels animation and preserves navigation',async()=>{await page.emulateMedia({reducedMotion:'reduce'});await nav('admin-overview');await page.waitForTimeout(450);assert.equal(await page.locator('.dt-motion-transfer').count(),0);assert.equal(await page.locator('#view-admin-overview').evaluate(n=>n.getAnimations({subtree:true}).filter(a=>a.playState==='running').length),0);});
  await check('Animation layer sends no extra network writes',async()=>assert.deepEqual(writes.filter(p=>!p.startsWith('/api/v1/session/')&&p!=='/api/v1/ai/query'),[]));
  await check('No uncaught JavaScript exceptions',async()=>assert.deepEqual(errors,[]));
  if(process.env.DT_PERF_CAPTURE){
   await page.emulateMedia({reducedMotion:'no-preference'});
   await nav('admin-session-control');
   const metrics=await page.evaluate(async()=>{
    const body=document.querySelector('#adminSessionControlTable tbody');
    body.innerHTML=Array.from({length:180},(_,i)=>`<tr><td>QA ${i}</td><td>qa-${i}@example.test</td><td><span data-live-duration="0">00:00:00</span></td><td>ACTIVE</td></tr>`).join('');
    await new Promise(r=>setTimeout(r,500));
    const originalRects=Element.prototype.getClientRects,originalRaf=window.requestAnimationFrame;
    let layoutReads=0,callbackMs=0,callbacks=0;
    Element.prototype.getClientRects=function(...args){layoutReads++;return originalRects.apply(this,args);};
    window.requestAnimationFrame=function(fn){return originalRaf.call(window,time=>{const start=performance.now();try{return fn(time);}finally{callbackMs+=performance.now()-start;callbacks++;}});};
    for(let tick=1;tick<=8;tick++){
     body.querySelectorAll('[data-live-duration]').forEach(n=>n.textContent='00:00:'+String(tick).padStart(2,'0'));
     await new Promise(r=>setTimeout(r,70));
    }
    await new Promise(r=>setTimeout(r,100));
    Element.prototype.getClientRects=originalRects;window.requestAnimationFrame=originalRaf;
    return {layoutReads,callbackMs:Number(callbackMs.toFixed(2)),callbacks,rows:180,ticks:8};
   });
   fs.writeFileSync(path.join(output,process.env.DT_PERF_CAPTURE+'.json'),JSON.stringify(metrics,null,2));console.log('PERFORMANCE '+JSON.stringify(metrics));
  }
  await page.evaluate(()=>document.getElementById('staff-login-popups')?.remove());
  await page.emulateMedia({reducedMotion:'no-preference'});await nav('admin-reports');await page.waitForTimeout(450);
  await page.screenshot({path:path.join(output,'report-motion-qa.png'),fullPage:true});
  fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({fixtureOnly:true,results},null,2));console.log(JSON.stringify({fixtureOnly:true,results},null,2));
  if(results.some(r=>!r.passed))process.exitCode=1;
 }finally{await browser?.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1});
