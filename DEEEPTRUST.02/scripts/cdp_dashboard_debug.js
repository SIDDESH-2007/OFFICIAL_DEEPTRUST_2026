const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

async function run() {
    const tokens = JSON.parse(fs.readFileSync(path.join(__dirname, '../tokens.json'), 'utf8'));
    const token = tokens.owner || tokens.healthcare;
    const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

    const chromeProc = spawn(chromePath, [
        '--headless=new',
        '--remote-debugging-port=9223',
        '--disable-gpu',
        '--no-sandbox',
        '--window-size=1440,900',
        'about:blank'
    ]);

    await new Promise(r => setTimeout(r, 1500));

    // Get version / webSocketDebuggerUrl
    const versionData = await new Promise((resolve, reject) => {
        http.get('http://127.0.0.1:9223/json/version', res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });

    const wsUrl = versionData.webSocketDebuggerUrl;
    console.log('Connected to CDP at:', wsUrl);

    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.method === 'Runtime.consoleAPICalled') {
            const args = msg.params.args.map(a => a.value).join(' ');
            console.log(`[BROWSER CONSOLE] [${msg.params.type}]`, args);
        }
        if (msg.method === 'Runtime.exceptionThrown') {
            console.error(`[BROWSER EXCEPTION]`, JSON.stringify(msg.params.exceptionDetails, null, 2));
        }
        if (msg.id && pending.has(msg.id)) {
            pending.get(msg.id)(msg);
            pending.delete(msg.id);
        }
    };

    await new Promise(resolve => ws.onopen = resolve);

    function send(method, params = {}) {
        const id = msgId++;
        return new Promise(resolve => {
            pending.set(id, resolve);
            ws.send(JSON.stringify({ id, method, params }));
        });
    }

    const target = await send('Target.createTarget', { url: 'http://localhost:5000/login.html' });
    const targetId = target.result.targetId;

    const attach = await send('Target.attachToTarget', { targetId, flatten: true });
    const sessionId = attach.result.sessionId;

    function sendSession(method, params = {}) {
        const id = msgId++;
        return new Promise(resolve => {
            pending.set(id, resolve);
            ws.send(JSON.stringify({ id, sessionId, method, params }));
        });
    }

    await sendSession('Page.enable');
    await sendSession('Runtime.enable');

    console.log('Navigating to login to set localStorage token...');
    await new Promise(r => setTimeout(r, 1000));

    await sendSession('Runtime.evaluate', {
        expression: `
            localStorage.setItem('dt_admin_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im93bmVyQGRlZXB0cnVzdC5kZW1vIiwicm9sZSI6IkRFRVBUUlVTVF9PV05FUiIsImZ1bGxfbmFtZSI6IkRlZXBUcnVzdCBPd25lciIsImlhdCI6MTc5MTA4NjY4MSwiZXhwIjoxNzkxMDkzODgxfQ.GgOr9hOopxVeFBz-kUVrDA5N8eD_i9c30ctZjSzj2f8');
            localStorage.setItem('dt_admin_token_storage', 'local');
        `
    });

    console.log('Navigating to dashboard...');
    await sendSession('Page.navigate', { url: 'http://localhost:5000/dashboard.html#admin-overview' });

    await new Promise(r => setTimeout(r, 3000));
    
    // Check if body is hidden
    const res = await sendSession('Runtime.evaluate', {
        expression: `document.documentElement.style.visibility`
    });
    console.log('document.documentElement.style.visibility:', res.result.result.value);

    const shot = await sendSession('Page.captureScreenshot', { format: 'png' });
    const imgBuffer = Buffer.from(shot.result.data, 'base64');
    const outPath = 'C:\\Users\\SIDDESHWAR BS\\.gemini\\antigravity-ide\\brain\\77a4f6a5-9750-4eaa-b343-08c3530b14da\\scratch\\dashboard_debug.png';
    fs.writeFileSync(outPath, imgBuffer);
    console.log('Saved screenshot to:', outPath);

    ws.close();
    chromeProc.kill();
    process.exit(0);
}

run().catch(err => {
    console.error('CDP Error:', err);
    process.exit(1);
});
