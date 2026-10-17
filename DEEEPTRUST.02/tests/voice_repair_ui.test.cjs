const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root,'client/js/app_rework.js'),'utf8');
const code = source.slice(source.indexOf('function initVoiceRecovery()'),source.indexOf('function stopAudioRecording()'));
async function run(repair,status,codeValue='123456') {
  const elements={}, calls=[];
  for (const id of ['btn-voice-recovery-alternate','voice-recovery-alternate','btn-voice-recovery-alternate-submit',
    'voice-recovery-alternate-alert','input-voice-recovery-totp','btn-start-voice']) {
    elements[id]={value:codeValue,style:{},addEventListener(name,handler){this[name]=handler;}};
  }
  const ctx=vm.createContext({voiceRepairAvailable:repair,isVoiceVerified:false,
    document:{getElementById:id=>elements[id]||null},currentSessionId:'s',
    getActiveUser:()=>({id:'u'}),voiceHeaders:()=>({Authorization:'Bearer verification-token'}),
    loadVoiceChallenge:async()=>calls.push('challenge'),switchAuthView:view=>calls.push(view),
    setTimeout:fn=>fn(),fetch:async(url,options)=>{calls.push(JSON.parse(options.body));return {ok:true,json:async()=>({success:true,status})};}});
  vm.runInContext(code,ctx);vm.runInContext('initVoiceRecovery()',ctx);
  await elements['btn-voice-recovery-alternate-submit'].click();
  return {elements,calls};
}
test('authorized repair returns to live voice capture, never directly to MFA',async()=>{
 const {calls,elements}=await run(true,'REPAIR_AUTHORIZED');
 assert.equal(calls[0].repair_voice,true);assert.deepEqual(calls.slice(1),['voice','challenge']);
 assert.equal(elements['input-voice-recovery-totp'].value,'');
 assert.equal(elements['btn-start-voice'].disabled,false);
});
test('ordinary recovery retains its existing MFA route',async()=>{
 const {calls}=await run(false,'VERIFIED');assert.equal(calls[0].repair_voice,false);assert.equal(calls[1],'mfa');
});
test('invalid Authenticator input never submits a request',async()=>{
 const {calls}=await run(true,'REPAIR_AUTHORIZED','bad');assert.deepEqual(calls,[]);
});
