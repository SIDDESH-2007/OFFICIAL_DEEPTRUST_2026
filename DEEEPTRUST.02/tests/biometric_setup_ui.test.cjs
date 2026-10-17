const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../client/js/app_rework.js'),'utf8');
const snippet=source.slice(source.indexOf('function setBiometricSetupDisplay('),source.indexOf('function resetFaceState()'));
function harness(response){
 const elements=new Map();const containers=new Map();
 const element=id=>{if(!elements.has(id))elements.set(id,{style:{},value:'',disabled:false,textContent:''});return elements.get(id);};
 element('view-verify').querySelector=selector=>{if(!containers.has(selector))containers.set(selector,{style:{}});return containers.get(selector);};
 const ctx={currentSessionId:'session',currentVerificationToken:'verification',getActiveUser:()=>({email:'admin@novacaremedical.org'}),console:{warn(){}},cameraRequests:0,stopped:false,
  document:{getElementById:element},
  resetFaceState(){},stopCameraFeed(){ctx.stopped=true;},requestCameraAccess:async()=>{ctx.cameraRequests++;},
  fetch:async(url,options)=>{ctx.request={url,options};return{ok:response.ok,status:response.status,json:async()=>response.data};}};
 vm.createContext(ctx);
 const headersStart=source.indexOf('function voiceHeaders()');
 assert(headersStart>=0);
 const headersEnd=source.indexOf('\n}',headersStart)+2;
 vm.runInContext(source.slice(headersStart,headersEnd),ctx);
 vm.runInContext(snippet,ctx);return{ctx,element,containers};
}
(async()=>{
 let h=harness({ok:true,data:{available:true,authorized:false}});
 assert.equal(await h.ctx.loadBiometricSetup(),true);
 assert.equal(h.element('form-biometric-setup').style.display,'block');
 assert.equal(h.containers.get('.camera-container').style.display,'none');
 assert.equal(h.ctx.request.options.headers.Authorization,'Bearer verification');
 for(const data of [{available:false},{available:true,authorized:true}]){
  h=harness({ok:true,data});await h.ctx.loadBiometricSetup();
  assert.equal(h.element('form-biometric-setup').style.display,'none');
  assert.equal(h.containers.get('.camera-container').style.display,'');
 }
 h=harness({ok:false,status:404,data:{detail:'Not Found'}});
 assert.equal(await h.ctx.loadBiometricSetup(),true,'An old service must not silently fall back to face matching');
 assert.equal(h.element('form-biometric-setup').style.display,'block');
 assert.equal(h.element('input-biometric-setup-code').disabled,true);
 assert.equal(h.element('btn-biometric-setup').disabled,true);
 assert.match(h.element('biometric-setup-message').textContent,/RESTART_INTEGRATION_FIX/);
 h=harness({ok:false,status:401,data:{detail:'Sign in again'}});
 assert.equal(await h.ctx.loadBiometricSetup(),true);
 assert.equal(h.element('biometric-setup-message').textContent,'Sign in again');
 h=harness({ok:false,status:404,data:{detail:'Not Found'}});h.ctx.getActiveUser=()=>({email:'other@example.test'});
 assert.equal(await h.ctx.loadBiometricSetup(),false,'Other accounts keep their normal verification path');
 h=harness({ok:true,data:{success:true}});h.element('input-biometric-setup-code').value='123456';
 await h.ctx.authorizeBiometricSetup({preventDefault(){}});
 assert.equal(h.ctx.request.url,'/api/v1/face/setup/authorize');
 assert.equal(JSON.parse(h.ctx.request.options.body).session_id,'session');
 assert.equal(h.ctx.cameraRequests,1);
 assert.equal(h.element('input-biometric-setup-code').value,'');
 assert.equal(h.element('form-biometric-setup').style.display,'none');
 assert.equal(h.containers.get('.camera-container').style.display,'');
 h=harness({ok:false,data:{detail:'Invalid Authenticator code'}});h.element('input-biometric-setup-code').value='123456';
 await h.ctx.authorizeBiometricSetup({preventDefault(){}});
 assert.equal(h.ctx.cameraRequests,0);
 assert.equal(h.element('biometric-setup-message').textContent,'Invalid Authenticator code');
 assert.equal(h.element('btn-biometric-setup').disabled,false);
 h=harness({ok:true,data:{success:true}});h.element('input-biometric-setup-code').value='12';
 await h.ctx.authorizeBiometricSetup({preventDefault(){}});assert.equal(h.ctx.request,undefined);
 h=harness({ok:true,data:{}});let finish;h.ctx.fetch=()=>new Promise(resolve=>{finish=resolve;});
 const pending=h.ctx.loadBiometricSetup();h.ctx.currentSessionId='different';
 finish({ok:true,json:async()=>({available:true})});await pending;
 assert.equal(h.element('form-biometric-setup').style.display,'none');
 console.log('Biometric setup UI checks passed: account-scoped status, MFA authorization, failure, stale response and normal login.');
})().catch(err=>{console.error(err);process.exitCode=1;});
