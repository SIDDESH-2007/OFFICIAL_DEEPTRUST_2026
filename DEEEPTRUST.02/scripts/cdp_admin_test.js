const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

async function run() {
    const tokens = JSON.parse(fs.readFileSync(path.join(__dirname, '../tokens.json'), 'utf8'));
    const token = tokens.owner;
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

    const versionData = await new Promise((resolve, reject) => {
        http.get('http://127.0.0.1:9223/json/version', res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });

    const wsUrl = versionData.webSocketDebuggerUrl;
    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
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

    await new Promise(r => setTimeout(r, 1000));

    await sendSession('Runtime.evaluate', {
        expression: `
            localStorage.setItem('dt_admin_token', '${token}');
            localStorage.setItem('dt_user_info', JSON.stringify({
                full_name: 'DeepTrust Platform Owner',
                role: 'DEEPTRUST_OWNER',
                organization_name: 'DeepTrust Security Platform'
            }));
            localStorage.setItem('dt_admin_token_storage', 'local');
        `
    });

    await sendSession('Page.navigate', { url: 'http://localhost:5000/dashboard.html' });
    await new Promise(r => setTimeout(r, 3000));

    const shot = await sendSession('Page.captureScreenshot', { format: 'png' });
    const imgBuffer = Buffer.from(shot.result.data, 'base64');
    const outPath = 'C:\\Users\\SIDDESHWAR BS\\.gemini\\antigravity-ide\\brain\\862fbeb3-ca39-4dbc-b3f5-514c079f44c3\\dashboard_admin_view.png';
    fs.writeFileSync(outPath, imgBuffer);
    console.log('Saved admin console screenshot to:', outPath);

    ws.close();
    chromeProc.kill();
    process.exit(0);
}

run().catch(err => {
    console.error('CDP Error:', err);
    process.exit(1);
});
