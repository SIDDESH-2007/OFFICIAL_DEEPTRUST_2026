const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9222;

const RESOLUTIONS = [
  { width: 1920, height: 1080, name: '1920x1080' },
  { width: 1536, height: 864,  name: '1536x864' },
  { width: 1440, height: 900,  name: '1440x900' },
  { width: 1366, height: 768,  name: '1366x768' },
  { width: 1280, height: 720,  name: '1280x720' }
];

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
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
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
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

  async captureScreenshot() {
    const res = await this.send('Page.captureScreenshot', { format: 'png' });
    return Buffer.from(res.data, 'base64');
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function run() {
  console.log('[1/4] Spawning headless Chrome on port ' + PORT + '...');
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-extensions',
    '--window-size=1920,1080',
    'http://localhost:5000/login.html'
  ]);

  let connected = false;
  let wsUrl = '';
  for (let i = 0; i < 30; i++) {
    await sleep(400);
    try {
      const targets = await fetchJson(`http://localhost:${PORT}/json`);
      const pageTarget = targets.find(t => t.type === 'page' && t.webSocketDebuggerUrl);
      if (pageTarget) {
        wsUrl = pageTarget.webSocketDebuggerUrl;
        connected = true;
        break;
      }
    } catch (e) {}
  }

  if (!connected) {
    console.error('Failed to connect to Chrome debugging endpoint');
    chromeProc.kill();
    process.exit(1);
  }

  console.log('[2/4] Connecting CDP WebSocket...');
  const cdp = new CDPClient(wsUrl);
  await cdp.connect();

  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('DOM.enable');

  console.log('Navigating to http://localhost:5000/login.html...');
  await cdp.send('Page.navigate', { url: 'http://localhost:5000/login.html' });
  await sleep(1500);

  // Check intro or let it complete
  console.log('Waiting for Startup Intro (0-100%)...');
  await sleep(2600);
  await cdp.evaluate(`
    sessionStorage.setItem('dt_intro_completed', 'true');
    const intro = document.getElementById('dt-startup-intro');
    if (intro) intro.style.display = 'none';
  `);

  console.log('[3/4] Testing resolutions at 100% Zoom (Browser Zoom = 100%):');
  const results = [];

  for (const res of RESOLUTIONS) {
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: res.width,
      height: res.height,
      deviceScaleFactor: 1,
      mobile: false
    });
    await sleep(350);

    const metrics = await cdp.evaluate(`(() => {
      const de = document.documentElement;
      const b = document.body;
      const hasVertScroll = de.scrollHeight > (window.innerHeight + 1);
      const hasHorizScroll = de.scrollWidth > (window.innerWidth + 1);

      // Check required elements visibility
      const logo = !!document.querySelector('.dt-brand-bar');
      const systemStatus = !!document.getElementById('system-status-indicators');
      const versionTag = document.querySelector('.dt-version-tag')?.textContent?.trim();
      const hero = !!document.querySelector('.dt-hero-content');
      const shield = !!document.querySelector('.dt-center-shield-wrap');
      const pipelineCards = document.querySelectorAll('.dt-pipeline-card').length;
      const featureCards = document.querySelectorAll('.dt-feature-card').length;
      const loginPanel = !!document.querySelector('.dt-auth-card');
      const footer = !!document.querySelector('.dt-hero-footer');
      const builtForHealthcare = document.body.innerText.includes('Built for Healthcare');

      // Check font readability
      const heroFontSize = window.getComputedStyle(document.querySelector('.dt-hero-title') || b).fontSize;

      return {
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
        scrollHeight: de.scrollHeight,
        clientHeight: de.clientHeight,
        scrollWidth: de.scrollWidth,
        clientWidth: de.clientWidth,
        hasVertScroll,
        hasHorizScroll,
        logo,
        systemStatus,
        versionTag,
        hero,
        shield,
        pipelineCards,
        featureCards,
        loginPanel,
        footer,
        builtForHealthcare,
        heroFontSize
      };
    })()`);

    const vertScroll = metrics.hasVertScroll ? 'YES' : 'NO';
    const horizScroll = metrics.hasHorizScroll ? 'YES' : 'NO';
    const clipped = (!metrics.logo || !metrics.hero || !metrics.loginPanel || !metrics.footer) ? 'YES' : 'NO';
    const readable = parseFloat(metrics.heroFontSize) >= 28 ? 'YES' : 'NO';

    results.push({
      target: res.name,
      vertScroll,
      horizScroll,
      clipped,
      readable,
      metrics
    });

    console.log(`  • ${res.name}: VertScroll: ${vertScroll} | HorizScroll: ${horizScroll} | Clipped: ${clipped} | Readable: ${readable} (scrollHeight: ${metrics.scrollHeight}px vs clientHeight: ${metrics.clientHeight}px, version: ${metrics.versionTag})`);

    // Capture screenshot
    const shot = await cdp.captureScreenshot();
    const shotPath = path.join(__dirname, `screenshot_${res.name}.png`);
    fs.writeFileSync(shotPath, shot);
  }

  console.log('[4/4] Testing Theme Switching & Contrast:');
  const lightThemeCheck = await cdp.evaluate(`(() => {
    document.documentElement.setAttribute('data-theme', 'light');
    const bg = window.getComputedStyle(document.body).backgroundColor;
    const color = window.getComputedStyle(document.body).color;
    return { bg, color, theme: document.documentElement.getAttribute('data-theme') };
  })()`);
  console.log('  • Light Theme applied:', lightThemeCheck);

  const darkThemeCheck = await cdp.evaluate(`(() => {
    const btn = document.getElementById('btn-theme-toggle');
    if (btn) btn.click();
    const bg = window.getComputedStyle(document.body).backgroundColor;
    const color = window.getComputedStyle(document.body).color;
    const brandColor = window.getComputedStyle(document.querySelector('.dt-brand-title-wrap h1') || document.body).color;
    return { bg, color, brandColor, theme: document.documentElement.getAttribute('data-theme') };
  })()`);
  console.log('  • Dark Theme applied via Toggle:', darkThemeCheck);

  // Switch back to light theme
  await cdp.evaluate(`
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.setItem('dt_theme_pref', 'light');
  `);

  console.log('\n================== SUMMARY ==================');
  console.log(JSON.stringify(results, null, 2));

  cdp.close();
  chromeProc.kill();
  process.exit(0);
}

run().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
