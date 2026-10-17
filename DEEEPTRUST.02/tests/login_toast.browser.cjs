const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const {chromium}=require(root+'/node_modules/@playwright/test');
const source=fs.readFileSync(root+'/client/js/dashboard.js','utf8');
const a=source.indexOf('let notificationSyncBusy = false;'),b=source.indexOf('// ── 11.',a);
let rows=[];
const script=`const getAuthorizationHeader=()=>({});const escapeHtml=s=>String(s||'').replaceAll('<','&lt;');${source.slice(a,b)}`;
const notification=(id,age=0)=>({notification_id:id,type:'HOSPITAL_STAFF_LOGIN',title:'New login — NovaCare Medical Center',message:'admin@novacaremedical.org • Admin • Device: UNTRUSTED • Risk: 8/100 (LOW)',created_at:Date.now()/1000-age,timestamp:new Date().toISOString(),read:false});
const server=http.createServer((req,res)=>{
 if(req.url==='/app.js'){res.setHeader('Content-Type','text/javascript');res.end(script);return;}
 if(req.url==='/motion.js'){res.setHeader('Content-Type','text/javascript');res.end(fs.readFileSync(root+'/client/js/dashboard-motion.js'));return;}
 if(req.url==='/style.css'){res.setHeader('Content-Type','text/css');res.end(fs.readFileSync(root+'/client/css/dashboard-motion.css'));return;}
 if(req.url==='/api/v1/notifications'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({notifications:rows,unread_count:rows.length}));return;}
 res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head><body data-page="dashboard" style="background:#101010"><main id="mainContentArea"><section class="view-section active" id="overview">Overview</section><section class="view-section" id="accounts">Accounts</section><section class="view-section" id="audit">Audit</section></main><span id="unreadNotifCount"></span><div id="notifListBody"></div><script src="/app.js"></script><script src="/motion.js"></script></body></html>');
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({channel:'chrome',headless:true});
try{const page=await browser.newPage({viewport:{width:1440,height:900}});const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto('http://127.0.0.1:'+server.address().port);
rows=[notification('old',3600)];await page.evaluate(()=>syncNotifications());assert.equal(await page.locator('#staff-login-popups').count(),0);
for(const section of ['overview','accounts','audit']){
 await page.evaluate(id=>{document.querySelectorAll('.view-section').forEach(e=>e.classList.toggle('active',e.id===id));},section);
 rows.unshift(notification(section));await page.evaluate(()=>syncNotifications());await page.waitForTimeout(400);
 const host=page.locator('#staff-login-popups');assert.equal(await host.evaluate(e=>e.parentElement===document.body),true);
 const box=await host.boundingBox();assert.ok(box.x>900&&box.y<120);
 await page.locator('.dt-staff-login-toast').last().waitFor();
 assert.match(await host.innerText(),/admin@novacaremedical.org/);assert.match(await host.innerText(),/UNTRUSTED/);
 console.log('PASS global animated popup while using '+section);
}
assert.equal(await page.locator('.dt-staff-login-toast').count(),3);await page.evaluate(()=>syncNotifications());assert.equal(await page.locator('.dt-staff-login-toast').count(),3);
await page.locator('.dt-login-toast-dismiss').first().click();assert.equal(await page.locator('.dt-staff-login-toast').count(),2);
await page.screenshot({path:root+'/test-results/novacare-login-toast-qa.png'});
await page.reload();rows=[notification('recent')];await page.evaluate(()=>syncNotifications());assert.equal(await page.locator('.dt-staff-login-toast').count(),1);
await page.emulateMedia({reducedMotion:'reduce'});rows.unshift(notification('reduced'));await page.evaluate(()=>syncNotifications());assert.equal(await page.locator('.dt-staff-login-toast').count(),2);
assert.deepEqual(errors,[]);console.log('PASS historical suppression, duplicate prevention, dismiss, recent initial login, reduced motion and no runtime exceptions');
}finally{await browser.close();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);server.close();process.exitCode=1});
