const { spawn } = require('child_process');
const http = require('http');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9223;

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

async function testIntro() {
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    'about:blank'
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

  console.log('Navigating to fresh session...');
  await cdp.send('Page.navigate', { url: 'http://localhost:5000/login.html' });
  await sleep(400);

  // Check initial intro state
  const stateInitial = await cdp.evaluate(`(() => {
    const intro = document.getElementById('dt-startup-intro');
    const percent = document.getElementById('dt-intro-percent')?.textContent;
    const stages = document.querySelectorAll('.dt-intro-stage-item').length;
    const title = document.querySelector('.dt-intro-title')?.textContent;
    const sub = document.querySelector('.dt-intro-subtitle')?.textContent;
    return {
      visible: intro && window.getComputedStyle(intro).display !== 'none',
      percent,
      stagesCount: stages,
      title,
      sub
    };
  })()`);
  console.log('Initial Intro State:', stateInitial);

  // Wait 1 second (around ~50%)
  await sleep(1000);
  const stateMid = await cdp.evaluate(`(() => {
    const percent = document.getElementById('dt-intro-percent')?.textContent;
    const activeStages = document.querySelectorAll('.dt-intro-stage-item.active').length;
    return { percent, activeStages };
  })()`);
  console.log('Mid Intro State:', stateMid);

  // Wait for 100% and fade out (~2.8s total)
  await sleep(1800);
  const stateFinal = await cdp.evaluate(`(() => {
    const intro = document.getElementById('dt-startup-intro');
    const percent = document.getElementById('dt-intro-percent')?.textContent;
    const activeStages = document.querySelectorAll('.dt-intro-stage-item.active').length;
    const isCompletedInSession = sessionStorage.getItem('dt_intro_completed');
    const loginCardVisible = window.getComputedStyle(document.getElementById('view-login')).display !== 'none';
    const authStateUntouched = localStorage.getItem('dt_token') === null;

    return {
      introDisplay: intro ? window.getComputedStyle(intro).display : null,
      percent,
      activeStages,
      isCompletedInSession,
      loginCardVisible,
      authStateUntouched
    };
  })()`);
  console.log('Final Intro & Transition State:', stateFinal);

  cdp.close();
  chromeProc.kill();
}

testIntro().catch(console.error);
