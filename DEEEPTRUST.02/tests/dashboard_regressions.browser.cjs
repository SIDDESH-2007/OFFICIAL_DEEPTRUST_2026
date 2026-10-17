const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
const output=path.join(root,'test-results','dashboard-regressions');
fs.mkdirSync(output,{recursive:true});
const {chromium}=require(root+'/node_modules/@playwright/test');
const results=[];
async function check(name,fn){try{await fn();results.push({name,passed:true})}catch(e){results.push({name,passed:false,error:e.message})}}
function assert(value,message){if(!value)throw Error(message)}
(async()=>{
 const server=http.createServer((req,res)=>{
  const file=path.resolve(root,'client','.'+new URL(req.url,'http://localhost').pathname);
  if(!file.startsWith(path.resolve(root,'client')+path.sep)){res.writeHead(403).end();return;}
  fs.readFile(file,(err,body)=>{if(err){res.writeHead(404).end();return;}const type={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream';res.writeHead(200,{'Content-Type':type});res.end(body)});
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try{
  browser=await chromium.launch({headless:true,channel:'chrome'});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',async route=>{
   const url=new URL(route.request().url());
   if(url.hostname!=='127.0.0.1'){await route.abort();return;}
   if(!url.pathname.startsWith('/api/')){await route.continue();return;}
   requests.push(url.pathname);
   if(url.pathname==='/api/v1/admin/accounts'){await route.abort('failed');return;}
   let body={},status=200;
   if(url.pathname==='/api/v1/auth/me')body={user:{full_name:'Dashboard QA',role:'DEEPTRUST_OWNER',email:'qa@example.test'}};
   else if(url.pathname.endsWith('/features/overview'))body={organizations:[]};
   else if(url.pathname.endsWith('/features/audit')){
    const email=url.searchParams.get('email')||'none';
    if(email==='first@example.test')await new Promise(r=>setTimeout(r,350));
    body={count:email==='latest@example.test'?22:11,events:[]};
   }else if(url.pathname==='/api/v1/admin/audit/identities')body={identities:[]};
   else if(url.pathname==='/api/v1/admin/audit/integrity')body={integrity:{status:'VERIFIED',signed_records:1,legacy_unsigned_records:0}};
   else if(url.pathname.endsWith('/reports/monthly')){
    const month=url.searchParams.get('month');if(month==='1')await new Promise(r=>setTimeout(r,350));
    body={metrics:{total_login_attempts:Number(month),organizations:[],generated_at:new Date().toISOString()}};
   }else if(url.pathname.startsWith('/api/v1/session/'))body={status:'ACTIVE'};
   else status=403;
   await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
  });
  await page.addInitScript(()=>{sessionStorage.setItem('dt_admin_token','isolated-test-fixture');sessionStorage.setItem('dt_admin_token_exp',String(Date.now()+3600000));sessionStorage.setItem('dt_admin_token_storage','session');});
  await page.goto(`http://127.0.0.1:${server.address().port}/dashboard.html`);
  await page.locator('#deeptrustAdminNav').waitFor({state:'visible'});
  await check('Dashboard IDs are unique',async()=>{const dup=await page.evaluate(()=>{const ids=[...document.querySelectorAll('[id]')].map(e=>e.id);return ids.filter((v,i)=>ids.indexOf(v)!==i)});assert(!dup.length,'Duplicate IDs: '+dup.join(', '))});
  await check('Centered pill navigation uses the existing dashboard routes',async()=>{
   const nav=page.locator('.obsidian-nav');await nav.waitFor();
   assert(await nav.locator('button').count()===5,'Five main sections should be visible');
   await nav.locator('button[data-view="admin-session-control"]').click();
   assert((await page.locator('.view-section.active').getAttribute('id'))==='view-admin-session-control','Session pill did not open existing section');
   assert((await nav.locator('button[data-view="admin-session-control"]').getAttribute('aria-current'))==='page','Selected pill did not update');
   const aligned=await nav.evaluate(node=>{const a=node.getBoundingClientRect(),b=node.closest('.main-wrapper').getBoundingClientRect();return Math.abs(a.left+a.width/2-(b.left+b.width/2))<12});
   assert(aligned,'Top pill navigation is not centered in workspace');
  });
  await page.locator('.obsidian-nav button[data-view="admin-overview"]').click();
  await page.waitForTimeout(420);
  await page.screenshot({path:path.join(output,'dashboard-overview-obsidian.png'),fullPage:true});
  await page.locator('.nav-item[data-view="admin-audit-logs"]').click();
  await check('Audit directory loads when section opens',async()=>{await page.waitForFunction(()=>document.querySelector('#auditIdentitiesList').textContent.includes('No enrolled identities'),{},{timeout:2500})});
  await check('Latest audit filter wins while a request is pending',async()=>{
   const panel=page.locator('#view-admin-audit-logs [data-feature="audit"]');
   await panel.locator('[data-feature-status]').filter({hasText:'matching events'}).waitFor();
   await panel.locator('[data-filter="email"]').fill('first@example.test');await panel.locator('[data-filter="email"]').dispatchEvent('change');
   await page.waitForTimeout(50);await panel.locator('[data-filter="email"]').fill('latest@example.test');await panel.locator('[data-filter="email"]').dispatchEvent('change');
   await page.waitForTimeout(650);assert((await panel.locator('[data-feature-status]').textContent()).startsWith('22 '),'Displayed result does not match latest email filter');
  });
  await page.locator('.nav-item[data-view="admin-reports"]').click();
  await check('Latest monthly report selection wins',async()=>{
   await page.locator('#reportMonthSelect').selectOption('1');await page.waitForTimeout(50);await page.locator('#reportMonthSelect').selectOption('2');await page.waitForTimeout(650);
   assert((await page.locator('#repTotalLogins').textContent()).trim()==='2','Old month response overwrote latest report');
  });
  await check('All visible console navigation opens exactly one section',async()=>{
   const views=await page.locator('#deeptrustAdminNav .nav-item[data-view]').evaluateAll(nodes=>nodes.map(n=>n.dataset.view));
   for(const view of views){await page.locator(`#deeptrustAdminNav .nav-item[data-view="${view}"]`).click();const active=await page.locator('.view-section.active').evaluateAll(nodes=>nodes.map(n=>n.id));assert(active.length===1&&active[0]==='view-'+view,'Invalid active section for '+view)}
  });
  await check('Failed-data Retry button retries inside module scope',async()=>{
   await page.locator('.nav-item[data-view="admin-accounts"]').click();
   const retry=page.locator('#view-admin-accounts button').filter({hasText:'Retry'});await retry.waitFor();
   const before=requests.filter(p=>p==='/api/v1/admin/accounts').length;
   await retry.click();await page.waitForTimeout(150);
   assert(requests.filter(p=>p==='/api/v1/admin/accounts').length>before,'Retry did not request accounts again');
  });
  await check('Dashboard shell fits viewport and scroll stays inside content',async()=>{
   await page.setViewportSize({width:1280,height:720});
   const fits=await page.evaluate(()=>{
    const content=document.getElementById('mainContentArea'),bar=document.querySelector('.topbar');
    const extra=document.createElement('div');extra.style.height='1500px';content.appendChild(extra);
    const top=bar.getBoundingClientRect().top;content.scrollTop=500;
    const valid=document.documentElement.scrollHeight<=innerHeight+1 && scrollY===0 && content.scrollTop>0 && bar.getBoundingClientRect().top===top;
    extra.remove();return valid;
   });assert(fits,'Dashboard document scrolls or header moves');
  });
  await check('Reference navigation remains usable at compact widths',async()=>{
   for(const size of [{width:1024,height:768},{width:768,height:850},{width:390,height:844}]){
    await page.setViewportSize(size);
    const metrics=await page.evaluate(()=>{const nav=document.querySelector('.obsidian-nav'),r=nav.getBoundingClientRect();return {docWidth:document.documentElement.scrollWidth,navLeft:r.left,navRight:r.right,buttons:nav.querySelectorAll('button').length}});
    assert(metrics.docWidth<=size.width+1,`Document overflows at ${size.width}px`);
    assert(metrics.navLeft>=-1&&metrics.navRight<=size.width+1&&metrics.buttons===5,`Navigation clipped at ${size.width}px`);
    await page.locator('.obsidian-nav button[data-view="admin-audit-logs"]').click();
    assert((await page.locator('.view-section.active').getAttribute('id'))==='view-admin-audit-logs',`Pill failed at ${size.width}px`);
   }
   await page.setViewportSize({width:1440,height:900});
  });
  await check('No uncaught dashboard JavaScript exceptions',async()=>assert(!errors.length,errors.join('; ')));
  await page.locator('.nav-item[data-view="admin-audit-logs"]').click();await page.waitForTimeout(450);
  await page.screenshot({path:path.join(output,'dashboard-audit-qa.png'),fullPage:true});
  console.log(JSON.stringify({fixtureOnly:true,results},null,2));
  fs.writeFileSync(path.join(output,'dashboard-browser-check.json'),JSON.stringify({fixtureOnly:true,results},null,2));
  if(results.some(r=>!r.passed))process.exitCode=1;
 }finally{await browser?.close();await new Promise(r=>server.close(r))}
})().catch(e=>{console.error(e);process.exitCode=1});
