const { test } = require('node:test');
const assert = require('node:assert/strict');
const { allowedOrigin } = require('../server/middleware/origin-policy');
const configured = ['http://localhost:5000', 'http://localhost:5176'];
test('local and configured hospital frontends stay allowed', () => {
  for (const origin of configured) assert.equal(allowedOrigin(origin, 'localhost:5000', configured), true);
});
test('own HTTPS tunnel works but unrelated tunnels cannot read authenticated responses', () => {
  assert.equal(allowedOrigin('https://my-app.loca.lt', 'my-app.loca.lt', configured), true);
  for (const origin of ['https://attacker.loca.lt','http://my-app.loca.lt','https://my-app.loca.lt.evil.test','null']) {
    assert.equal(allowedOrigin(origin, 'my-app.loca.lt', configured), false);
  }
});
test('CLI calls without an Origin header remain supported', () => {
  assert.equal(allowedOrigin(undefined, 'localhost:5000', configured), true);
});
