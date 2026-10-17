const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

async function checkUrl(url, label) {
    console.log(`\n=== Checking console for ${label} (${url}) ===`);
    const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
    const chromeProc = spawn(chromePath, [
        '--headless=new',
        '--remote-debugging-port=9224',
        '--disable-gpu',
        '--no-sandbox',
        'about:blank'
    ]);

    await new Promise(r => setTimeout(r, 1200));

    const versionData = await new Promise((resolve, reject) => {
        http.get('http://127.0.0.1:9224/json/version', res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });

    const ws = new WebSocket(versionData.webSocketDebuggerUrl);
    let msgId = 1;
    const pending = new Map();
    const errors = [];
    const logs = [];

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.method === 'Console.messageAdded') {
            const m = msg.params.message;
            if (m.level === 'error') errors.push(m.text);
            else logs.push(`[${m.level}] ${m.text}`);
        } else if (msg.method === 'Runtime.consoleAPICalled') {
            const text = msg.params.args.map(a => a.value || a.description || '').join(' ');
            if (msg.params.type === 'error') errors.push(text);
            else logs.push(`[${msg.params.type}] ${text}`);
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

    const target = await send('Target.createTarget', { url });
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

    await sendSession('Console.enable');
    await sendSession('Runtime.enable');
    await sendSession('Page.enable');

    await new Promise(r => setTimeout(r, 2000));

    console.log(`Errors count: ${errors.length}`);
    if (errors.length > 0) {
        console.error('Console errors:', errors);
    } else {
        console.log('Zero uncaught console errors.');
    }

    ws.close();
    chromeProc.kill();
    return errors.length;
}

async function run() {
    const err1 = await checkUrl('http://localhost:5000/', 'Login / Landing Page');
    const err2 = await checkUrl('http://localhost:5000/dashboard.html', 'Dashboard (Unauthenticated Redirect)');
    console.log('\nTotal console error count:', err1 + err2);
    process.exit(0);
}

run().catch(err => {
    console.error('Test error:', err);
    process.exit(1);
});
