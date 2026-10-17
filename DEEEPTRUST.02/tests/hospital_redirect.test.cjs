const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),path=require('path');
const source=fs.readFileSync(path.resolve(__dirname,'../client/js/app_rework.js'),'utf8');
const a=source.indexOf('let dashboardFinalizing = false;'),b=source.indexOf('/* ============================================================',a);
async function scenario(failFirst=false) {
 const values=new Map([['dt_oauth_params',JSON.stringify({client_id:'client',redirect_uri:'http://localhost:5176',role:'doctor',state:'state',code_challenge:'challenge'})]]);
 const button={classList:{s:new Set(),add(v){this.s.add(v)},remove(v){this.s.delete(v)},contains(v){return this.s.has(v)}}};
 const calls=[],alerts=[];
 let attempts=0;
 const context=vm.createContext({console:{error(){}},sessionStorage:{getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,String(v)),removeItem:k=>values.delete(k)},window:{location:{},Session:{save:()=>{throw Error('Hospital SSO must not overwrite the platform monitoring session')}}},document:{getElementById:id=>id==='btn-finalize-dashboard'?button:{textContent:''},querySelector:()=>null},currentSessionId:'vs_1',currentVerificationToken:'verification',setTimeout:fn=>fn(),alert:v=>alerts.push(v),encodeURIComponent,fetch:async(url,options)=>{
 calls.push({url,options});
 if(url.endsWith('/risk/evaluate'))return {ok:true,json:async()=>({decision:'ALLOW'})};
 if(url.endsWith('/auth/finalize'))return {ok:true,json:async()=>({success:true,access_token:'final-token',user:{email:'person@gmail.com'}})};
 attempts++;
 if(failFirst&&attempts===1)return {ok:false,json:async()=>({detail:'Temporary hospital authorization failure'})};
 return {ok:true,json:async()=>({redirect_url:'http://localhost:5176/?code=issued&state=state'})};
 }});
 vm.runInContext(source.slice(a,b),context);
 await context.window.finalizeAndGoToDashboard();
 if(failFirst){assert.equal(context.window.location.href,undefined);assert.equal(button.disabled,false);assert.ok(values.has('dt_oauth_completed_access'));await context.window.finalizeAndGoToDashboard();}
 assert.equal(context.window.location.href,'http://localhost:5176/?code=issued&state=state');
 assert.equal(calls.filter(c=>c.url.endsWith('/auth/finalize')).length,1);
 assert.equal(calls.filter(c=>c.url.endsWith('/risk/evaluate')).length,1);
 const authorization=calls.find(c=>c.url.endsWith('/oauth/authorize'));
 assert.equal(authorization.options.headers.Authorization,'Bearer final-token');assert.equal(JSON.parse(authorization.options.body).requested_role,'doctor');
 assert.equal(values.has('dt_oauth_params'),false);assert.equal(values.has('dt_oauth_completed_access'),false);
}
(async()=>{await scenario();await scenario(true);console.log('Hospital redirect tests passed: all-factor finalization, signed OAuth authorization, hospital callback, failed authorization stays put, retry without re-finalizing, platform token preserved.');})().catch(e=>{console.error(e);process.exitCode=1});
