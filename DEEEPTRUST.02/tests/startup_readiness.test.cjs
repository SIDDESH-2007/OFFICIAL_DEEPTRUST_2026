const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { waitForService } = require('../server/scripts/service_readiness');
function child() { return Object.assign(new EventEmitter(), { exitCode: null, signalCode: null }); }
test('cold startup waits for actual health instead of a fixed retry count', async () => {
    const proc = child(); let polls = 0;
    await waitForService({ child: proc, checkReady: async () => ++polls > 35, timeoutMs: 1500, pollMs: 5 });
    assert.equal(polls, 36);
    assert.equal(proc.listenerCount('error'), 0);
});
test('crashed process fails immediately even if another service answers health', async () => {
    const proc = child();
    await assert.rejects(waitForService({ child: proc, checkReady: async () => { proc.exitCode = 1; return true; }, timeoutMs: 1000 }), /exited before readiness/);
});
test('executable spawn failure shows actionable error', async () => {
    const proc = child();
    await assert.rejects(waitForService({ child: proc, checkReady: async () => { proc.emit('error', new Error('ENOENT')); return false; }, timeoutMs: 1000 }), /could not start: ENOENT/);
});
test('unhealthy service has a bounded deadline and never reports ready', async () => {
    const proc = child();
    await assert.rejects(waitForService({ child: proc, checkReady: async () => false, timeoutMs: 70, pollMs: 10 }), /did not become ready/);
});
