// Run with node tests/face_login_ui.test.cjs. Execute actual login functions
// against a small DOM/fetch harness; no webcam or running app is needed.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../client/js/app_rework.js'), 'utf8');
const start = source.indexOf('async function initiateLivenessChallenge()');
const end = source.indexOf('function updateCheckCard(', start);
assert(start >= 0 && end > start);
function harness(response) {
  const elements = new Map();
  const ctx = {
    currentSessionId: 'session', currentLivenessChallenge: null,
    faceVerificationEpoch: 0, faceStableCounter: 0, faceMissingCounter: 0,
    isIdentityMatched: true, isLivenessVerified: false, isLivenessChecking: false,
    lastVerifiedFrame: null, stopped: false, animated: false,
    document: {getElementById(id) {
      if (!elements.has(id)) elements.set(id, {style: {display: 'none'}, classList: {add() {}, remove() {}}, textContent: '', querySelector() {return null;}});
      return elements.get(id);
    }},
    fetch: async () => ({ok: response.ok, json: async () => response.data}),
    updateCheckCard() {}, stopCameraFeed() {ctx.stopped = true;},
    requestCameraAccess() {}, switchAuthView() {},
    window: {matchMedia: () => ({matches: false})},
    playFaceSuccessAnimation() {ctx.animated = true;},
    console: {error() {}}, setTimeout,
  };
  vm.createContext(ctx);
  vm.runInContext(source.slice(start, end), ctx);
  vm.runInContext(source.slice(source.indexOf('async function handleDetectionResult('), source.indexOf('async function performIdentityMatch(')), ctx);
  return ctx;
}
(async () => {
  let ctx = harness({ok: false, data: {detail: 'offline'}});
  await ctx.initiateLivenessChallenge();
  assert.equal(ctx.currentLivenessChallenge, null);
  assert.equal(ctx.isIdentityMatched, false);

  assert.equal(ctx.stopped, true);
  assert.equal(ctx.document.getElementById('camera-status-badge').textContent, 'offline');
  assert.equal(ctx.document.getElementById('camera-permission-box').style.display, 'flex');

  ctx = harness({ok: true, data: {}});
  let finishChallenge;
  let challengeCalls = 0;
  ctx.fetch = () => {challengeCalls++; return new Promise(resolve => {finishChallenge = resolve;});};
  const firstChallenge = ctx.initiateLivenessChallenge();
  await ctx.initiateLivenessChallenge();
  assert.equal(challengeCalls, 1, 'Concurrent requests must share one challenge');
  finishChallenge({ok: true, json: async () => ({challenge: 'PASSIVE_FACE_SCAN'})});
  await firstChallenge;
  assert.equal(ctx.currentLivenessChallenge, 'PASSIVE_FACE_SCAN');

  ctx = harness({ok: true, data: {}});
  ctx.fetch = () => new Promise(resolve => {finishChallenge = resolve;});
  const staleChallenge = ctx.initiateLivenessChallenge();
  ctx.faceVerificationEpoch++;
  ctx.currentLivenessChallenge = 'NEW_SCAN';
  finishChallenge({ok: false, json: async () => ({detail: 'expired previous scan'})});
  await staleChallenge;
  assert.equal(ctx.currentLivenessChallenge, 'NEW_SCAN');
  assert.equal(ctx.isIdentityMatched, true);
  assert.equal(ctx.stopped, false, 'Stale error must not stop a newer scan');

  ctx = harness({ok: true, data: {challenge: 'HEAD_TURN_SEQUENCE', instruction: 'Look straight'}});
  await ctx.initiateLivenessChallenge();
  assert.equal(ctx.currentLivenessChallenge, 'HEAD_TURN_SEQUENCE');

  ctx = harness({ok: true, data: {status: 'IN_PROGRESS', instruction: 'Turn your head left'}});
  ctx.currentLivenessChallenge = 'HEAD_TURN_SEQUENCE';
  await ctx.performLivenessStep('frame');
  assert.equal(ctx.document.getElementById('liveness-challenge-text').textContent, 'Turn your head left');
  assert.equal(ctx.isLivenessVerified, false);

  for (const status of ['LIVENESS_FAILED', 'LIVENESS_REQUIRED', 'PHONE_DETECTED']) {
    ctx = harness({ok: true, data: {status, message: 'Restart verification'}});
    ctx.currentLivenessChallenge = 'HEAD_TURN_SEQUENCE';
    await ctx.performLivenessStep('frame');
    assert.equal(ctx.isLivenessVerified, false);
    assert.equal(ctx.isIdentityMatched, false);
    assert.equal(ctx.stopped, true);
    assert.equal(ctx.document.getElementById('btn-continue-voice').style.display, 'none');
    assert.equal(ctx.document.getElementById('camera-permission-box').style.display, 'flex');
  }

  ctx = harness({ok: true, data: {status: 'LIVENESS_PASSED'}});
  ctx.currentLivenessChallenge = 'HEAD_TURN_SEQUENCE';
  await ctx.performLivenessStep('frame');
  assert.equal(ctx.isLivenessVerified, true);
  assert.equal(ctx.document.getElementById('btn-continue-voice').style.display, 'block');
  assert.equal(ctx.animated, true);

  ctx = harness({ok: true, data: {status: 'LIVENESS_PASSED'}});
  ctx.currentLivenessChallenge = 'HEAD_TURN_SEQUENCE';
  let resolveFetch;
  ctx.fetch = () => new Promise(resolve => {resolveFetch = resolve;});
  const pending = ctx.performLivenessStep('frame');
  await ctx.handleDetectionResult({status: 'PHONE_DETECTED', message: 'Phone detected'}, 'phone-frame');
  resolveFetch({ok: true, json: async () => ({status: 'LIVENESS_PASSED'})});
  await pending;
  assert.equal(ctx.isLivenessVerified, false);
  assert.equal(ctx.document.getElementById('btn-continue-voice').style.display, 'none');
  assert.equal(ctx.document.getElementById('camera-status-badge').textContent, 'Phone detected');

  ctx = harness({ok: true, data: {}});
  let heartbeats = 0;
  ctx.currentLivenessChallenge = 'HEAD_TURN_SEQUENCE';
  ctx.performLivenessStep = async () => {heartbeats++;};
  await ctx.handleDetectionResult({status: 'NO_FACE'}, 'frame');
  assert.equal(heartbeats, 1);
  assert.equal(ctx.document.getElementById('camera-status-badge').textContent, 'Tracking your face — hold steady');
  assert.equal(ctx.isLivenessVerified, false);

  ctx = harness({ok: true, data: {face_pipeline_version: 'previous-backend'}});
  ctx.resetFaceState = () => {};
  let cameraRequested = false;
  ctx.navigator = {mediaDevices: {getUserMedia() {cameraRequested = true;}}};
  const cameraStart = source.indexOf('async function requestCameraAccess()');
  const cameraEnd = source.indexOf('function stopCameraFeed()', cameraStart);
  vm.runInContext(source.slice(cameraStart, cameraEnd), ctx);
  await ctx.requestCameraAccess();
  assert.equal(cameraRequested, false);
  assert.match(ctx.document.getElementById('camera-status-badge').textContent, /AI backend update pending/);
  console.log('10 login UI scenarios passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
