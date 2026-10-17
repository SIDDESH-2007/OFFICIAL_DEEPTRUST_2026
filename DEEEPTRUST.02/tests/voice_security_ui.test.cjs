const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../client/js/app_rework.js'), 'utf8');
const code = source.slice(source.indexOf('let voiceChallengeId = null;'), source.indexOf('function initVoiceRecovery()'));
async function scenario(purpose, response, ok = true) {
  const elements = {};
  for (const id of ['voice-phrase-text','btn-start-voice','voice-status-badge','voice-mic-orb','voice-visualizer-container','view-voice','btn-continue-mfa','voice-enrollment-panel']) {
    elements[id] = { style: {}, textContent: '', value: '123456', previousElementSibling: {},
      classList: { add() {}, remove() {}, contains: x => x === 'active' } };
  }
  const calls = [];
  const context = vm.createContext({ console, Blob, currentVerificationToken: 'token', currentSessionId: 's',
    currentVoiceChallenge: null, isVoiceVerified: false, audioStream: null, audioContext: null, audioAnalyser: null,
    getActiveUser: () => ({id: 'u'}), document: {getElementById: id => elements[id] || null},
    switchAuthView: name => calls.push(['view', name]),
    fetch: async (url, options) => { calls.push([url, options]); return { ok: url.endsWith('/challenge') || ok,
      json: async () => url.endsWith('/challenge') ? {challenge_id:'fresh',challenge_phrase:'DeepTrust Identity Bravo Four',purpose,samples_collected:0,mfa_required:false} : response }; },
    navigator: {mediaDevices: {getUserMedia: async () => ({getTracks: () => [{stop() {}}]})}},
    window: {AudioContext: class { createAnalyser() {return {};} createMediaStreamSource() {return {connect(){}};} }},
    MediaRecorder: class {constructor() {this.state='inactive';this.mimeType='audio/webm';} start() {this.state='recording';} stop() {this.state='inactive';this.onstop();}},
    FileReader: class {readAsDataURL() {this.result='data:audio/webm;base64,bGl2ZQ==';this.onload();}},
    requestAnimationFrame: () => 1, cancelAnimationFrame() {}, setTimeout: fn => { Promise.resolve().then(fn); return 1; }, clearTimeout() {},
    stopAudioRecording() {} });
  vm.runInContext(code, context);
  await vm.runInContext('startVoiceRecordingSession()', context);
  return {context,elements,calls};
}
(async () => {
  const enrolled = await scenario('ENROLL',{success:true,status:'ENROLLED',matched:false,
    message:'Voice sample accepted. Complete Authenticator to save your profile.'});
  assert.equal(enrolled.context.isVoiceVerified,true);
  assert.equal(enrolled.elements['btn-continue-mfa'].style.display,'block');
  const submit = enrolled.calls.find(c=>c[0].endsWith('/enroll'));
  assert.equal(submit[1].headers.Authorization,'Bearer token');
  assert.equal(JSON.parse(submit[1].body).challenge_id,'fresh');
  assert.equal('mfa_code' in JSON.parse(submit[1].body),false);
  const incomplete = await scenario('ENROLL',{success:true,status:'ENROLLING'});
  assert.equal(incomplete.context.isVoiceVerified,false);
  for (const response of [{success:true}, {status:'VERIFIED',matched:false}, {status:'FAILED',success:true}]) {
    const result=await scenario('VERIFY',response);assert.equal(result.context.isVoiceVerified,false);
  }
  const verified=await scenario('VERIFY',{status:'VERIFIED',matched:true,success:true});
  assert.equal(verified.context.isVoiceVerified,true);
  assert.equal(verified.elements['btn-continue-mfa'].style.display,'block');
  const failure=await scenario('VERIFY',{detail:{code:'BACKGROUND_TOO_LOUD',message:'Background too loud.',retryable:true}},false);
  assert.equal(failure.context.isVoiceVerified,false);
  assert.equal(failure.elements['voice-status-badge'].textContent,'Background too loud.');
  console.log('7 voice UI scenarios passed: authenticated capture, one-sample enrollment to MFA, strict verification status, noise retry.');
})().catch(error=>{console.error(error);process.exitCode=1;});
