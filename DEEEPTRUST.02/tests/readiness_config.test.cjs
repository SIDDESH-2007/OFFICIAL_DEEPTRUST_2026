const {test}=require('node:test'),assert=require('node:assert/strict');
const {validateProductionConfig}=require('../server/config/production.config');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const valid={NODE_ENV:'production',JWT_SECRET:'j'.repeat(48),AUDIT_SIGNING_KEY:'a'.repeat(48),MONGODB_URI:'mongodb+srv://fixture',MONGODB_DATABASE:'fixture',AI_SERVICE_URL:'http://127.0.0.1:8000',AUDIT_CHECKPOINT_PATH:'/persistent/checkpoint.json',FRONTEND_ORIGINS:'https://fixture.vercel.app'};
test('local configuration remains supported',()=>validateProductionConfig({}));
test('valid production configuration accepted',()=>validateProductionConfig(valid));
test('production cannot start with weak/missing/shared signing keys',()=>{for(const patch of [{JWT_SECRET:''},{JWT_SECRET:'short'},{AUDIT_SIGNING_KEY:''},{AUDIT_SIGNING_KEY:valid.JWT_SECRET}])assert.throws(()=>validateProductionConfig({...valid,...patch}));});
test('production cannot seed demo accounts or use wildcard/plaintext origins',()=>{for(const patch of [{ENABLE_DEMO_SEEDING:'true'},{FRONTEND_ORIGINS:'*'},{FRONTEND_ORIGINS:'http://example.test'},{FRONTEND_ORIGINS:'https://example.test/path'}])assert.throws(()=>validateProductionConfig({...valid,...patch}));});
test('required external resources cannot silently default to local services',()=>{for(const key of ['MONGODB_URI','MONGODB_DATABASE','AI_SERVICE_URL','AUDIT_CHECKPOINT_PATH'])assert.throws(()=>validateProductionConfig({...valid,[key]:''}));});
const source=fs.readFileSync(path.join(__dirname,'../server/routes/readiness.routes.js'),'utf8');
async function readiness({database=true,face={status:'ONLINE',mongodb_connected:true},offline=false}={}){
 let handle,result,status;
 vm.runInNewContext(source,{require:n=>n==='express'?{Router:()=>({get:(p,h)=>handle=h})}:{getDBStatus:async()=>({connected:database})},process:{env:{}},module:{exports:{}},AbortSignal,fetch:async()=>{if(offline)throw Error('offline');return{ok:true,json:async()=>face};}});
 const res={setHeader(){},status:n=>{status=n;return res;},json:r=>result=r};await handle({},res);return{status,result};
}
test('deployment readiness fails closed on dependency failure',async()=>{for(const opts of [{database:false},{face:{status:'DEGRADED',mongodb_connected:true}},{face:null},{offline:true}])assert.equal((await readiness(opts)).status,503);});
test('deployment readiness accepts database and loaded face dependencies',async()=>assert.equal((await readiness()).status,200));
