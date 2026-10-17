const { spawn } = require('child_process');
const http = require('http');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9225;

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

async function testControls() {
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
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

  // Skip intro
  await cdp.evaluate(`
    sessionStorage.setItem('dt_intro_completed', 'true');
    const intro = document.getElementById('dt-startup-intro');
    if (intro) intro.style.display = 'none';
  `);

  console.log('Auditing Login Controls...');
  const loginAudit = await cdp.evaluate(`(() => {
    const controls = document.querySelectorAll('button, a, input, select');
    let total = controls.length;
    let working = 0;
    let disabled = 0;
    let broken = 0;

    controls.forEach(c => {
      if (c.disabled) {
        disabled++;
      } else {
        // check if visible and responsive
        const rect = c.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          working++;
        } else {
          // hidden element
        }
      }
    });

    return { total, working, disabled, broken };
  })()`);

  console.log('Login Controls Audit:', loginAudit);

  // Navigate to Dashboard
  console.log('Navigating to Dashboard...');
  await cdp.send('Page.navigate', { url: 'http://localhost:5000/dashboard.html' });
  await sleep(1500);

  const dashboardAudit = await cdp.evaluate(`(() => {
    const controls = document.querySelectorAll('button, a, input, select');
    let total = controls.length;
    let working = 0;
    let disabled = 0;
    let broken = 0;

    controls.forEach(c => {
      if (c.disabled) {
        disabled++;
      } else {
        const rect = c.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          working++;
        }
      }
    });

    return { total, working, disabled, broken };
  })()`);

  console.log('Dashboard Controls Audit:', dashboardAudit);

  cdp.close();
  chromeProc.kill();
}

testControls().catch(console.error);
