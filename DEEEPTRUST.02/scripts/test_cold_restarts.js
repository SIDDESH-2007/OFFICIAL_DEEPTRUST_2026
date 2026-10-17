const { spawn, execSync } = require('child_process');
const http = require('http');

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function checkHealth(url, timeoutMs = 15000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const req = http.get(url, (res) => {
        if (res.statusCode === 200) return resolve(true);
        if (Date.now() - start > timeoutMs) return reject(new Error('Timeout'));
        setTimeout(tryOnce, 500);
      });
      req.on('error', () => {
        if (Date.now() - start > timeoutMs) return reject(new Error('Timeout'));
        setTimeout(tryOnce, 500);
      });
    };
    tryOnce();
  });
}

async function runRestartTest() {
  console.log('====================================================');
  console.log('   DEEPTRUST 3X COLD RESTART VALIDATION SUITE       ');
  console.log('====================================================\n');

  // Restart 1
  console.log('--- EXECUTING COLD RESTART #1 ---');
  execSync('node server/scripts/deeptrust_launcher.js restart', { stdio: 'inherit' });
  await sleep(1500);
  await checkHealth('http://localhost:5000/api/v1/health');
  await checkHealth('http://localhost:8000/api/v1/face/health');
  console.log('[PASS] Restart #1 Health: Express Gateway & FastAPI online.');

  // Restart 2
  console.log('\n--- EXECUTING COLD RESTART #2 ---');
  execSync('node server/scripts/deeptrust_launcher.js restart', { stdio: 'inherit' });
  await sleep(1500);
  await checkHealth('http://localhost:5000/api/v1/health');
  await checkHealth('http://localhost:8000/api/v1/face/health');
  console.log('[PASS] Restart #2 Health: Express Gateway & FastAPI online.');

  // Restart 3
  console.log('\n--- EXECUTING COLD RESTART #3 ---');
  execSync('node server/scripts/deeptrust_launcher.js restart', { stdio: 'inherit' });
  await sleep(1500);
  await checkHealth('http://localhost:5000/api/v1/health');
  await checkHealth('http://localhost:8000/api/v1/face/health');
  console.log('[PASS] Restart #3 Health: Express Gateway & FastAPI online.');

  console.log('\nAll 3 Cold Restarts passed successfully!');
}

runRestartTest().catch(err => {
  console.error('Cold restart test failed:', err);
  process.exit(1);
});
