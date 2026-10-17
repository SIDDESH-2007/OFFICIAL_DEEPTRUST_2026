const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../server/routes/health.routes.js'),'utf8');
async function health(voice,mode='ok'){
 const handlers=new Map(); let body;
 const context={require:name=>name==='express'?{Router:()=>({get:(p,f)=>handlers.set(p,f)})}:{getDBStatus:async()=>({connected:true})},
  process:{env:{}},module:{exports:{}},Date,AbortSignal,
  fetch:async url=>{if(url.endsWith('/face/health'))return{ok:true,json:async()=>({})};
    if(mode==='throw')throw Error('offline');return {ok:mode!=='http',json:async()=>voice};}};
 vm.runInNewContext(source,context);
 await handlers.get('/')({}, {status:()=>({json:x=>body=x})});
 return body.services.find(x=>x.id==='voice');
}
test('loaded voice engines report ONLINE',async()=>assert.equal((await health({status:'Operational',speaker_loaded:true,replay_loaded:true,speech_loaded:true})).status,'ONLINE'));
test('uninitialized models are not falsely marked ready or unconfigured',async()=>assert.equal((await health({status:'Available / not probed'})).status,'NOT_PROBED'));
test('partial models cannot claim operational',async()=>assert.equal((await health({status:'Operational',speaker_loaded:true,replay_loaded:false,speech_loaded:true})).status,'UNAVAILABLE'));
test('offline or failed voice health never claims ready',async()=>{for(const mode of ['throw','http'])assert.equal((await health({},mode)).status,'UNAVAILABLE')});
test('malformed response fails closed',async()=>assert.equal((await health(null)).status,'UNAVAILABLE'));
