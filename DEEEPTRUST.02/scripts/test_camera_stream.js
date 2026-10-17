const { spawn } = require('child_process');
const http = require('http');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9224;

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
}

class CDPClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.id = 1;
    this.pending = new Map();
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((res, rej) => {
      this.ws.onopen = res;
      this.ws.onerror = rej;
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(msg.error);
        else resolve(msg.result);
      }
    };
  }

  send(method, params = {}) {
    const id = this.id++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    return res.result?.value;
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function testCamera() {
  console.log('Launching Chrome with fake media device & UI...');
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    'http://localhost:5000/login.html'
  ]);

  let wsUrl = '';
  for (let i = 0; i < 20; i++) {
    await sleep(300);
    try {
      const targets = await fetchJson(`http://localhost:${PORT}/json`);
      const target = targets.find(t => t.type === 'page' && t.webSocketDebuggerUrl);
      if (target) {
        wsUrl = target.webSocketDebuggerUrl;
        break;
      }
    } catch (e) {}
  }

  const cdp = new CDPClient(wsUrl);
  await cdp.connect();
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');

  await sleep(1500);

  console.log('Navigating to Face view (#view-verify)...');
  await cdp.evaluate(`
    sessionStorage.setItem('dt_intro_completed', 'true');
    const intro = document.getElementById('dt-startup-intro');
    if (intro) intro.style.display = 'none';

    // Switch view to verify
    switchAuthView('verify');
  `);

  await sleep(1000);

  // Check camera elements and stream
  const cameraState = await cdp.evaluate(`(() => {
    const video = document.getElementById('webcam-feed');
    const prompt = document.getElementById('camera-permission-box');
    const badge = document.getElementById('camera-status-badge');

    return {
      videoExists: !!video,
      videoSrcObjectAttached: !!(video && video.srcObject),
      videoPaused: video ? video.paused : null,
      videoWidth: video ? video.videoWidth : null,
      videoHeight: video ? video.videoHeight : null,
      promptDisplay: prompt ? window.getComputedStyle(prompt).display : null,
      promptHiddenClass: prompt ? prompt.classList.contains('hidden') : null,
      badgeText: badge ? badge.textContent : null,
      badgeClass: badge ? badge.className : null
    };
  })()`);

  console.log('Camera Feed Test Result:', cameraState);

  // Test camera cleanup
  console.log('Testing Camera Cleanup on view change...');
  await cdp.evaluate(`switchAuthView('login');`);
  await sleep(500);

  const cleanupState = await cdp.evaluate(`(() => {
    const video = document.getElementById('webcam-feed');
    return {
      activeMediaStreamNull: activeMediaStream === null,
      videoSrcObjectNull: video ? video.srcObject === null : null
    };
  })()`);

  console.log('Camera Cleanup Result:', cleanupState);

  cdp.close();
  chromeProc.kill();
}

testCamera().catch(console.error);
