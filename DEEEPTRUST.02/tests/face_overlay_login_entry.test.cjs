const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const root=require('node:path').resolve(__dirname,'../client')+'/';
const source=fs.readFileSync(root+'js/app_rework.js','utf8');
function fixture(){
 let draws=0,contexts=0,next=0;const frames=new Map();
 const drawing={clearRect(){},beginPath(){},rect(){},stroke(){},arc(){draws++;},fill(){}};
 const canvas={width:640,height:480,getContext(){contexts++;return drawing;}};drawing.canvas=canvas;
 const video={readyState:2,paused:false,videoWidth:640,videoHeight:480};
 const landmarks=Array.from({length:468},(_,i)=>({x:.3+(i%20)/100,y:.3+(i%15)/100}));
 const mesh={setOptions(){},onResults(fn){this.results=fn;},async send(){this.results({multiFaceLandmarks:[landmarks]});}};
 const ctx=vm.createContext({console,window:{FaceMesh:function(){return mesh;}},
  document:{getElementById:id=>id==='webcam-feed'?video:id==='faceCanvas'?canvas:null,
   createElement:()=>({width:0,height:0,getContext:()=>({drawImage(){}})})},
  requestAnimationFrame:fn=>{frames.set(++next,fn);return next;},cancelAnimationFrame:id=>frames.delete(id),
  detectionInterval:null,activeMediaStream:null,clearInterval(){},isIdentityMatched:false});
 vm.runInContext(source.slice(source.indexOf('let faceMeshInstance = null;'),source.indexOf('async function startVerificationPipeline()')),ctx);
 vm.runInContext(source.slice(source.indexOf('function stopCameraFeed()'),source.indexOf('function captureVideoFrameAsBase64()')),ctx);
 const run=()=>{const [id,fn]=frames.entries().next().value;frames.delete(id);return fn();};
 return {ctx,mesh,canvas,video,frames,run,draws:()=>draws,contexts:()=>contexts};
}
test('matching canvas dimensions still initialize drawing, on every reopening',async()=>{
 const f=fixture();
 for(let i=1;i<=4;i++){
  vm.runInContext('startFaceLandmarkOverlay()',f.ctx);await f.run();
  assert.equal(f.contexts(),i);assert.equal(f.draws(),468*i);
  vm.runInContext('stopCameraFeed()',f.ctx);assert.equal(f.frames.size,0);
 }
});
test('height-only camera changes resize landmark canvas',async()=>{
 const f=fixture();f.video.videoHeight=360;vm.runInContext('startFaceLandmarkOverlay()',f.ctx);await f.run();assert.equal(f.canvas.height,360);
});
test('late results from a stopped camera cannot draw or duplicate loops',async()=>{
 const f=fixture();let release;
 f.mesh.send=()=>new Promise(resolve=>{release=resolve;});
 vm.runInContext('startFaceLandmarkOverlay()',f.ctx);const previous=f.run();
 vm.runInContext('stopCameraFeed();startFaceLandmarkOverlay()',f.ctx);
 f.mesh.results({multiFaceLandmarks:[[{x:.5,y:.5}]]});assert.equal(f.draws(),0);
 release();await previous;assert.equal(f.frames.size,1);
});
test('failed initialization can retry without caching a broken mesh',async()=>{
 const f=fixture();f.mesh.setOptions=()=>{throw Error('not ready');};
 vm.runInContext('startFaceLandmarkOverlay()',f.ctx);await f.run();assert.equal(vm.runInContext('faceMeshInstance',f.ctx),null);
 f.mesh.setOptions=()=>{};await f.run();assert.equal(f.draws(),468);
});
test('standalone login clears saved auth once and never redirects',async()=>{
 const storage=()=>{const m=new Map();return {getItem:k=>m.get(k)||null,setItem:(k,v)=>m.set(k,v),removeItem:k=>m.delete(k)};};
 const ctx=vm.createContext({window:{},sessionStorage:storage(),localStorage:storage(),currentVerificationToken:'old',Date});
 vm.runInContext(fs.readFileSync(root+'session.js','utf8'),ctx);
 for(const store of [ctx.localStorage,ctx.sessionStorage]){store.setItem('dt_admin_token','saved');store.setItem('dt_verification_token','old-verification');}
 ctx.sessionStorage.setItem('dt_oauth_completed_access','old-access');
 vm.runInContext(source.slice(source.indexOf('let loginEntryInitialized = false;'),source.indexOf('async function initBootExperience()')),ctx);
 assert.equal(await vm.runInContext('checkExistingSession()',ctx),false);
 assert.equal(ctx.window.Session.getToken(),null);assert.equal(ctx.currentVerificationToken,null);
 assert.equal(ctx.sessionStorage.getItem('dt_oauth_params'),null);
 assert.equal(ctx.sessionStorage.getItem('dt_oauth_completed_access'),null);
 ctx.sessionStorage.setItem('dt_verification_token','new-login');
 await vm.runInContext('checkExistingSession()',ctx);
 assert.equal(ctx.sessionStorage.getItem('dt_verification_token'),'new-login');
});

test('back/forward cache restoration reloads the fresh login entry',()=>{
 let handler,reloads=0;
 const ctx=vm.createContext({window:{addEventListener:(event,fn)=>{assert.equal(event,'pageshow');handler=fn;},location:{reload(){reloads++;}}}});
 const begin=source.indexOf("window.addEventListener('pageshow'");
 const end=source.indexOf("document.addEventListener('DOMContentLoaded'",begin);
 vm.runInContext(source.slice(begin,end),ctx);
 handler({persisted:false});assert.equal(reloads,0);
 handler({persisted:true});assert.equal(reloads,1);
});
