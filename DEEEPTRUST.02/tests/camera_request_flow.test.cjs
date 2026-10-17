const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const path = require('path');
const root = path.resolve(__dirname,'..');
const src = fs.readFileSync(path.join(root,'client/js/app_rework.js'),'utf8');
const code = src.slice(src.indexOf('async function processCameraFrame()'), src.indexOf('async function handleDetectionResult('));
function context(matched) {
  const calls=[];
  const ctx={isProcessingFrame:false,isLivenessVerified:false,isIdentityMatched:matched,
    currentLivenessChallenge: matched ? 'HEAD_TURN_SEQUENCE':null,currentSessionId:'s',
    captureVideoFrameAsBase64:()=> 'frame',performLivenessStep:async()=>calls.push('liveness'),
    fetch:async url=>{calls.push(url);return {ok:true,json:async()=>({status:'ONE_FACE'})};},
    handleDetectionResult:async()=>calls.push('handle-detection'),document:{getElementById:()=>null}};
  vm.createContext(ctx);vm.runInContext(code,ctx);return {ctx,calls};
}
(async()=>{
  let {ctx,calls}=context(true);await ctx.processCameraFrame();
  assert.deepEqual(calls,['liveness']);assert.equal(ctx.isProcessingFrame,false);
  ({ctx,calls}=context(false));await ctx.processCameraFrame();
  assert.deepEqual(calls,['/api/v1/face/detect','handle-detection']);
  ({ctx,calls}=context(true));let finish;ctx.performLivenessStep=()=>new Promise(r=>{finish=r;calls.push('liveness');});
  const pending=ctx.processCameraFrame();await ctx.processCameraFrame();assert.deepEqual(calls,['liveness']);
  finish();await pending;assert.equal(ctx.isProcessingFrame,false);
  console.log('3 camera request routing/serialization scenarios passed');
})();
