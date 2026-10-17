const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');const {chromium}=require(root+'/node_modules/@playwright/test');
const source=fs.readFileSync(root+'/client/js/app_rework.js','utf8');
const a=source.indexOf('let loginEntryInitialized = false;'),b=source.indexOf('async function initBootExperience()',a);
let authHeader;
const server=http.createServer((req,res)=>{
 if(req.url==='/session.js'){res.setHeader('Content-Type','text/javascript');res.end(fs.readFileSync(root+'/client/session.js'));return;}
 if(req.url==='/entry.js'){res.setHeader('Content-Type','text/javascript');res.end(`let currentVerificationToken='old';${source.slice(a,b)}sessionStorage.setItem('dt_oauth_params','fixture-hospital');sessionStorage.setItem('dt_verification_token','stale');checkExistingSession().then(result=>window.fixtureResult={result,verification:currentVerificationToken,stored:sessionStorage.getItem('dt_verification_token')});`);return;}
 if(req.url==='/api/v1/notifications'){authHeader=req.headers.authorization;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({success:authHeader==='Bearer fixture-monitor'}));return;}
 res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><body><script src="/session.js"></script>'+(req.url==='/sso'?'<script src="/entry.js"></script>':'')+'</body></html>');
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({channel:'chrome',headless:true});try{
 const context=await browser.newContext();const monitor=await context.newPage();const origin='http://127.0.0.1:'+server.address().port;
 await monitor.goto(origin);await monitor.evaluate(()=>Session.save('fixture-monitor',{email:'monitor@example.invalid'},true));
 const hospital=await context.newPage();await hospital.goto(origin+'/sso');await hospital.waitForFunction(()=>window.fixtureResult);
 const state=await hospital.evaluate(()=>window.fixtureResult);assert.deepEqual(state,{result:false,verification:null,stored:null});
 assert.equal(await monitor.evaluate(()=>Session.getToken()),'fixture-monitor');
 const response=await monitor.evaluate(async()=>{const r=await fetch('/api/v1/notifications',{headers:{Authorization:'Bearer '+Session.getToken()}});return r.json()});assert.equal(response.success,true);
 assert.equal(authHeader,'Bearer fixture-monitor');console.log('PASS real two-tab storage: fresh hospital verification preserves monitoring notification authorization');
 }finally{await browser.close();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);server.close();process.exitCode=1});
