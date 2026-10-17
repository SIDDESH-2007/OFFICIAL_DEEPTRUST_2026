const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('@playwright/test');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(root+'/client/js/app_rework.js','utf8');
assert.match(source.slice(source.indexOf("document.addEventListener('DOMContentLoaded'"),source.indexOf('/* ============================================================',source.indexOf("document.addEventListener('DOMContentLoaded'"))),/initFinalAccessButton\(\)/);
const start=source.indexOf('function initFinalAccessButton()'),end=source.indexOf('/* ============================================================',start);
const button=fs.readFileSync(root+'/client/login.html','utf8').match(/<button[^>]+id="btn-finalize-dashboard"[^>]*>[\s\S]*?<\/button>/)[0];
for(const file of ['login.html','index.html'])assert.doesNotMatch(fs.readFileSync(root+'/client/'+file,'utf8').match(/<button[^>]+id="btn-finalize-dashboard"[^>]*>/)[0],/onclick=/);
const csp="default-src 'self'; script-src 'self' 'unsafe-inline'; script-src-attr 'none'; connect-src 'self'";
const script=`let currentSessionId='vs_fixture',currentVerificationToken='fixture';
window.Session={save:()=>{},getToken:()=> 'fixture'};
${source.slice(start,end)}
document.addEventListener('DOMContentLoaded',()=>{initFinalAccessButton();initFinalAccessButton();});`;
let calls=[],failed=false;
const server=http.createServer((req,res)=>{
 res.setHeader('Content-Security-Policy',csp);
 if(req.url==='/app.js'){res.setHeader('Content-Type','text/javascript');res.end(script);return;}
 if(req.url.startsWith('/api/')){
   calls.push(req.url);res.setHeader('Content-Type','application/json');
   if(failed&&req.url.endsWith('/risk/evaluate')){res.statusCode=403;res.end(JSON.stringify({detail:'Access denied'}));return;}
   const data=req.url.endsWith('/auth/finalize')?{success:true,access_token:'fixture',user:{email:'fixture@example.invalid'}}:req.url.endsWith('/oauth/authorize')?{redirect_url:'/hospital-callback'}:{decision:'ALLOW'};
   res.end(JSON.stringify(data));return;
 }
 if(['/dashboard.html','/hospital-callback'].includes(req.url)){res.end('<h1>Fixture destination</h1>');return;}
 res.setHeader('Content-Type','text/html');res.end(`<!doctype html><html><body>${button}<script src="/app.js"></script></body></html>`);
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({channel:'chrome',headless:true});
 try{
 const page=await browser.newPage();const origin=`http://127.0.0.1:${server.address().port}`;
 page.on('dialog',d=>d.dismiss());
 for(const mode of ['platform','hospital','blocked']){
  calls=[];failed=mode==='blocked';await page.goto(origin);
  if(mode==='hospital')await page.evaluate(()=>sessionStorage.setItem('dt_oauth_params',JSON.stringify({client_id:'fixture',redirect_uri:'/hospital-callback',state:'fixture',code_challenge:'fixture',role:'admin'})));
  else await page.evaluate(()=>sessionStorage.clear());
  await page.locator('#btn-finalize-dashboard').click();
  if(failed){await page.waitForFunction(()=>!document.getElementById('btn-finalize-dashboard').disabled);assert.equal(new URL(page.url()).pathname,'/');assert.deepEqual(calls,['/api/v1/risk/evaluate']);}
  else{await page.waitForURL('**/'+(mode==='hospital'?'hospital-callback':'dashboard.html'));assert.equal(calls.filter(x=>x.endsWith('/auth/finalize')).length,1);if(mode==='hospital')assert.ok(calls.includes('/api/v1/oauth/authorize'));}
  console.log('PASS actual button click under restrictive CSP: '+mode);
 }
 }finally{await browser.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e);server.close();process.exitCode=1});
