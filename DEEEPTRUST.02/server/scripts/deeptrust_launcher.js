/**
 * deeptrust_launcher.js
 * Master process manager & health monitor for DeepTrust Security Platform
 */

const fs = require('fs');
const path = require('path');
const { spawn, exec, execSync, execFileSync } = require('child_process');
const { waitForService } = require('./service_readiness');
const http = require('http');
const net = require('net');
const os = require('os');

// Load version metadata
let VERSION = '1.0.0';
try {
    const versionFile = path.resolve(__dirname, '../../version.json');
    if (fs.existsSync(versionFile)) {
        const vd = JSON.parse(fs.readFileSync(versionFile, 'utf8'));
        VERSION = vd.version || VERSION;
    }
} catch (e) {}

// Resolve project root dynamically
let projectRoot = path.resolve(__dirname, '../../');
if (!fs.existsSync(path.join(projectRoot, 'server', 'server.js'))) {
    if (fs.existsSync(path.join(__dirname, '../DEEEPTRUST.02', 'server', 'server.js'))) {
        projectRoot = path.join(__dirname, '../DEEEPTRUST.02');
    } else if (fs.existsSync(path.join(process.cwd(), 'DEEEPTRUST.02', 'server', 'server.js'))) {
        projectRoot = path.join(process.cwd(), 'DEEEPTRUST.02');
    } else {
        projectRoot = process.cwd();
    }
}

const runtimeDir = path.join(projectRoot, '.runtime');
const logsDir = path.join(projectRoot, 'logs');
const pidsFile = path.join(runtimeDir, 'pids.json');
const hostFile = path.join(runtimeDir, 'deeptrust-host.txt');

if (!fs.existsSync(runtimeDir)) fs.mkdirSync(runtimeDir, { recursive: true });
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const action = process.argv[2] || 'start';

if (action === 'stop') {
    stopSystem();
} else if (action === 'restart') {
    stopSystem();
    setTimeout(() => {
        startSystem();
    }, 2000);
} else {
    startSystem();
}

function stopSystem() {
    console.log('\nStopping DeepTrust Platform processes...');
    let stoppedCount = 0;
    if (fs.existsSync(pidsFile)) {
        try {
            const data = JSON.parse(fs.readFileSync(pidsFile, 'utf8'));
            const pids = data.pids || [];
            for (const pid of pids) {
                try {
                    console.log(`Terminating process PID ${pid}...`);
                    execSync(`taskkill /F /T /PID ${pid}`, { stdio: 'ignore' });
                    stoppedCount++;
                } catch (e) {
                    // Process may already be closed
                }
            }
        } catch (e) {
            console.error('Error reading PID file:', e.message);
        }
        try { fs.unlinkSync(pidsFile); } catch (e) {}
    }

    try {
        // Safe check to terminate leftover node/uvicorn instances on port 5000 and 8000
        execSync(`powershell -Command "Get-NetTCPConnection -LocalPort 5000,5050,8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | Where-Object { $_ -gt 0 } | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"`, { stdio: 'ignore' });
    } catch (e) {}

    try { if (fs.existsSync(hostFile)) fs.unlinkSync(hostFile); } catch (e) {}

    console.log(`[OK] DeepTrust stopped successfully. (${stoppedCount} processes terminated)\n`);
}

async function startSystem() {
    console.log('\n============================================================');
    console.log('             DEEPTRUST SECURE STARTUP ENGINE                ');
    console.log('============================================================\n');

    // Ensure any leftover processes on ports 5000 and 8000 are cleaned up before start
    try {
        execSync(`powershell -Command "Get-NetTCPConnection -LocalPort 5000,5050,8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | Where-Object { $_ -gt 0 } | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"`, { stdio: 'ignore' });
    } catch (e) {}

    // 1. Dependency check
    console.log('[STEP 1/7] Environment Check...');
    const hasNode = checkCommand('node -v');
    const hasPython = checkCommand('python --version');
    
    if (!hasNode) {
        console.error('\nDEEPTRUST STARTUP FAILED');
        console.error('Missing: Node.js (Required to run DeepTrust API Gateway)');
        process.exit(1);
    }
    if (!hasPython) {
        console.error('\nDEEPTRUST STARTUP FAILED');
        console.error('Missing: Python (Required to run DeepTrust AI Engine)');
        process.exit(1);
    }
    console.log('  [OK] Node.js and Python verified.');

    // 2. MongoDB Check & Auto-start
    console.log('\n[STEP 2/7] Checking MongoDB Service...');
    let dbReady = await checkTcpPort(27017, '127.0.0.1');
    if (!dbReady) {
        console.log('  MongoDB not responding on 27017. Attempting to start MongoDB Windows service...');
        try {
            execSync('net start "SIDDU MongoDB"', { stdio: 'ignore' });
        } catch (e) {
            try { execSync('net start MongoDB', { stdio: 'ignore' }); } catch (e2) {}
        }
        // Re-check for up to 10 seconds
        for (let i = 0; i < 10; i++) {
            await sleep(1000);
            dbReady = await checkTcpPort(27017, '127.0.0.1');
            if (dbReady) break;
        }
    }

    if (!dbReady) {
        console.error('\nDEEPTRUST STARTUP FAILED');
        console.error('Missing: MongoDB database service is unreachable at mongodb://localhost:27017/');
        console.error('Please ensure MongoDB is installed and running.');
        process.exit(1);
    }
    console.log('  [OK] MongoDB Connected');

    // 3. Start Python FastAPI AI Backend
    console.log('\n[STEP 3/7] Starting DeepTrust AI Engine (Python FastAPI)...');
    const fastapiLogPath = path.join(logsDir, 'fastapi.log');
    const fastapiOut = fs.openSync(fastapiLogPath, 'a');
    
    // Check for Python venv
    let pythonCmd = execFileSync('python', ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8', windowsHide: true }).trim();
    const venvPaths = [
        path.join(projectRoot, 'venv', 'Scripts', 'python.exe'),
        path.join(projectRoot, '.venv', 'Scripts', 'python.exe'),
        path.join(projectRoot, 'env', 'Scripts', 'python.exe')
    ];
    for (const vp of venvPaths) {
        if (fs.existsSync(vp)) {
            pythonCmd = vp;
            break;
        }
    }

    fs.writeSync(fastapiOut, `\n[DeepTrust startup ${new Date().toISOString()}] Python: ${pythonCmd}\n`);
    const fastapiArgs = ['-u', '-m', 'uvicorn', 'server.ai_service.face_service:app', '--host', process.env.AI_BIND_HOST || '127.0.0.1', '--port', '8000'];
    const fastapiProc = spawn(pythonCmd, fastapiArgs, {
        cwd: projectRoot,
        detached: true,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', fastapiOut, fastapiOut]
    });
    fastapiProc.unref();

    console.log(`  FastAPI Engine started (PID: ${fastapiProc.pid})`);

    // Poll FastAPI readiness directly on port 8000 before starting Express
    console.log('  Waiting for FastAPI AI Engine readiness on http://127.0.0.1:8000...');
    try {
        await waitForService({
            child: fastapiProc,
            checkReady: () => checkHttpUrl('http://127.0.0.1:8000/api/v1/health'),
            timeoutMs: 90000,
            pollMs: 500,
            onProgress: seconds => console.log(`  AI models are still initializing (${seconds}s); waiting for a healthy backend...`)
        });
    } catch (error) {
        console.error(`\nDEEPTRUST STARTUP FAILED: ${error.message}`);
        console.error(`AI log: ${fastapiLogPath}`);
        try {
            const tail = fs.readFileSync(fastapiLogPath, 'utf8').split(/\r?\n/).slice(-25).join('\n');
            console.error(tail);
        } catch (_) {}
        if (fastapiProc.exitCode === null && fastapiProc.pid) fastapiProc.kill();
        process.exit(1);
    }
    console.log('  [OK] FastAPI AI Engine Ready');

    // 4. Start Node.js Express Gateway Server
    console.log('\n[STEP 4/7] Starting DeepTrust Gateway & Static Server (Node Express)...');
    const backendLogPath = path.join(logsDir, 'backend.log');
    const backendOut = fs.openSync(backendLogPath, 'a');

    const expressProc = spawn(process.execPath, ['server/server.js'], {
        cwd: projectRoot,
        detached: true,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', backendOut, backendOut]
    });
    expressProc.unref();

    console.log(`  Express Server started (PID: ${expressProc.pid})`);

    // Start Protected Healthcare Demo App (Port 5050)
    const demoAppLogPath = path.join(logsDir, 'demo_app.log');
    const demoAppOut = fs.openSync(demoAppLogPath, 'a');
    const demoAppProc = spawn(pythonCmd, ['protected_demo_app.py'], {
        cwd: projectRoot,
        detached: true,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', demoAppOut, demoAppOut]
    });
    demoAppProc.unref();
    console.log(`  Protected Healthcare Demo App started on port 5050 (PID: ${demoAppProc.pid})`);

    // Save PIDs
    const activePids = [fastapiProc.pid, expressProc.pid, demoAppProc.pid];
    fs.writeFileSync(pidsFile, JSON.stringify({ pids: activePids }, null, 2));

    // 5. Backend Health Polling
    console.log('\n[STEP 5/7] Waiting for DeepTrust Backend API Health Check...');
    let healthOk = false;
    for (let i = 0; i < 30; i++) {
        await sleep(1000);
        healthOk = await checkHttpUrl('http://localhost:5000/api/v1/health');
        if (healthOk) break;
    }

    if (!healthOk) {
        console.error('\n[FAILED] DeepTrust Backend');
        console.error(`Please inspect backend log files at:`);
        console.error(`  - ${backendLogPath}`);
        console.error(`  - ${fastapiLogPath}`);
        process.exit(1);
    }
    console.log('  [OK] Backend API Ready');

    // 6. Frontend Reachability Check
    console.log('\n[STEP 6/7] Verifying Frontend Servicing...');
    let frontendOk = false;
    for (let i = 0; i < 10; i++) {
        frontendOk = await checkHttpUrl('http://localhost:5000/');
        if (frontendOk) break;
        await sleep(500);
    }

    if (!frontendOk) {
        console.error('\n[FAILED] Frontend Servicing');
        console.error(`Please inspect backend log file at: ${backendLogPath}`);
        process.exit(1);
    }
    console.log('  [OK] Frontend Ready');

    // 7. Host Link / Tunnel Startup
    console.log('\n[STEP 7/7] Initializing Secure Public Host Tunnel...');
    const hostLogPath = path.join(logsDir, 'host.log');
    let publicHostUrl = null;

    try {
        const localtunnel = require('localtunnel');
        const tunnel = await localtunnel({ port: 5000 });
        if (tunnel && tunnel.url) {
            publicHostUrl = tunnel.url;
            fs.writeFileSync(hostFile, publicHostUrl, 'utf8');
            fs.appendFileSync(hostLogPath, `[${new Date().toISOString()}] Tunnel created: ${publicHostUrl}\n`);
            tunnel.on('close', () => {
                fs.appendFileSync(hostLogPath, `[${new Date().toISOString()}] Tunnel closed\n`);
            });
        }
    } catch (err) {
        fs.appendFileSync(hostLogPath, `[${new Date().toISOString()}] Tunnel error: ${err.message}\n`);
    }

    // Detect LAN IP
    const lanIp = getLanIpAddress();
    const localUrl = 'http://localhost:5000';
    const lanUrl = `http://${lanIp}:5000`;
    const hostUrlDisplay = publicHostUrl || 'FAILED / UNAVAILABLE (Local & LAN Active)';

    // Copy to clipboard if host URL available
    let clipboardMsg = '';
    if (publicHostUrl) {
        try {
            execSync(`echo ${publicHostUrl}| clip`, { stdio: 'ignore' });
            clipboardMsg = 'Host link copied to clipboard.';
        } catch (e) {}
    }

    // Open browser automatically
    try {
        execSync(`start "" "${localUrl}"`, { stdio: 'ignore', shell: true });
    } catch (e) {
        // Non-fatal: browser open is best-effort
    }

    // Display Final Status
    console.log('\n============================================================');
    console.log('             DEEPTRUST SECURE ACCESS PLATFORM              ');
    console.log(`                   Version ${VERSION}                      `);
    console.log('============================================================\n');
    console.log('STARTUP STATUS\n');
    console.log('  [OK] MongoDB');
    console.log('  [OK] Backend API (FastAPI)');
    console.log('  [OK] API Gateway (Express)');
    console.log('  [OK] Frontend');
    console.log(`  [${publicHostUrl ? 'OK' : 'WARN'}] Public Tunnel\n`);
    console.log('------------------------------------------------------------\n');
    console.log('DEEPTRUST IS LIVE\n');
    console.log(`  Local:       ${localUrl}`);
    console.log(`  LAN:         ${lanUrl}`);
    console.log(`  Public Host: ${publicHostUrl || 'UNAVAILABLE (Local & LAN Active)'}\n`);
    if (clipboardMsg) console.log(`  ${clipboardMsg}`);
    console.log('------------------------------------------------------------\n');
    console.log('  Backend API:    ONLINE');
    console.log('  Database:       CONNECTED');
    console.log('  Application:    READY');
    console.log('  Browser:        OPENED\n');
    console.log('Press CTRL+C or run STOP_DEEPTRUST.bat to stop DeepTrust.');
    console.log('============================================================\n');

    // Keep master launcher process alive as persistent daemon supervisor
    setInterval(() => {}, 1000 * 60 * 60);
}

function checkCommand(cmd) {
    try {
        execSync(cmd, { stdio: 'ignore' });
        return true;
    } catch (e) {
        return false;
    }
}

function checkTcpPort(port, host) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(1500);
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
        socket.connect(port, host);
    });
}

function checkHttpUrl(urlStr) {
    return new Promise((resolve) => {
        const req = http.get(urlStr, (res) => {
            if (res.statusCode >= 200 && res.statusCode < 400) {
                resolve(true);
            } else {
                resolve(false);
            }
        });
        req.on('error', () => resolve(false));
        req.setTimeout(2000, () => {
            req.destroy();
            resolve(false);
        });
    });
}

function getLanIpAddress() {
    const interfaces = os.networkInterfaces();
    let preferredIp = '127.0.0.1';
    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
            if ((net.family === 'IPv4' || net.family === 4) && !net.internal) {
                // Prefer Wi-Fi or Wireless or Ethernet over virtual adapters
                if (name.toLowerCase().includes('wi-fi') || name.toLowerCase().includes('wireless') || name.toLowerCase().includes('ethernet')) {
                    return net.address;
                }
                if (preferredIp === '127.0.0.1') preferredIp = net.address;
            }
        }
    }
    return preferredIp;
}

function sleep(ms) {
    return new Promise((res) => setTimeout(res, ms));
}
