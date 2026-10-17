const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const root = require('path').resolve(__dirname, '..');
const source = fs.readFileSync(root + '/client/js/app_rework.js', 'utf8');
const start = source.indexOf('async function handleResendEmailOtp');
const end = source.indexOf('async function handleEmailVerifySubmit', start);
async function check(data, ok, expected) {
  const elements = Object.fromEntries(['email-verify-status-msg', 'email-verify-error-msg', 'email-delivery-heading'].map(id => [id, {style: {}, textContent: ''}]));
  const ctx = {pendingRegisterEmail: 'test@example.com', document: {getElementById: id => elements[id]}, fetch: async () => ({ok, json: async () => data})};
  vm.createContext(ctx);
  vm.runInContext(source.slice(start, end), ctx);
  await ctx.handleResendEmailOtp();
  assert.equal(elements['email-verify-status-msg'].style.display === 'block', expected);
  assert.equal(elements['email-delivery-heading'].textContent.includes('sent'), expected);
  if (!expected) assert.equal(elements['email-verify-error-msg'].style.display, 'block');
}
(async () => {
  await check({success: true, email_sent: true}, true, true);
  await check({success: false, email_configured: false, message: 'Not configured'}, true, false);
  await check({detail: 'Delivery failed'}, false, false);
  await check({success: true}, true, false);
  console.log('4 email UI checks passed');
})();
