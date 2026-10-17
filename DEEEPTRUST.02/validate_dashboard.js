const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'client/dashboard.html'), 'utf8');
const js = fs.readFileSync(path.join(__dirname, 'client/js/dashboard.js'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, 'client/css/dashboard.css'), 'utf8');

const requiredAdminViews = [
    'view-admin-overview',
    'view-admin-organizations',
    'view-admin-identity-sec',
    'view-admin-threat-investigation',
    'view-admin-risk-engine',
    'view-admin-copilot',
    'view-admin-system-health',
    'view-admin-audit-logs',
    'view-admin-integrations',
    'view-admin-settings'
];

const requiredDrawers = [
    'investigationDrawer',
    'notificationDrawer',
    'orgDetailsDrawer'
];

let allOk = true;

console.log('=== 1. CHECKING DASHBOARD.HTML SECTIONS ===');
for (const v of requiredAdminViews) {
    if (html.includes(`id="${v}"`)) {
        console.log(`PASS: Found section id="${v}"`);
    } else {
        console.error(`FAIL: Missing section id="${v}"`);
        allOk = false;
    }
}

console.log('\n=== 2. CHECKING DRAWERS ===');
for (const d of requiredDrawers) {
    if (html.includes(`id="${d}"`)) {
        console.log(`PASS: Found drawer id="${d}"`);
    } else {
        console.error(`FAIL: Missing drawer id="${d}"`);
        allOk = false;
    }
}

console.log('\n=== 3. CHECKING JS HANDLERS & ROUTING ===');
const jsFunctions = [
    'loadAdminOverview',
    'loadAdminOrganizations',
    'loadAdminIdentitySecurity',
    'loadAdminThreatInvestigation',
    'loadAdminRiskEngine',
    'loadAdminSystemHealth',
    'loadAdminIntegrations',
    'handleCopilotQuery',
    'inspectEvent',
    'inspectOrg',
    'switchView'
];

for (const fn of jsFunctions) {
    if (js.includes(fn)) {
        console.log(`PASS: Found JS function ${fn}`);
    } else {
        console.error(`FAIL: Missing JS function ${fn}`);
        allOk = false;
    }
}

console.log('\n=== 4. CHECKING CSS STYLING RULES ===');
const cssClasses = [
    '.investigation-drawer',
    '.notification-drawer',
    '.demo-badge',
    '.status-pill',
    '.factor-health-grid',
    '.sidebar-nav',
    '.kpi-grid'
];

for (const cls of cssClasses) {
    if (css.includes(cls)) {
        console.log(`PASS: Found CSS class ${cls}`);
    } else {
        console.error(`FAIL: Missing CSS class ${cls}`);
        allOk = false;
    }
}

if (allOk) {
    console.log('\n>>> ALL DASHBOARD VALIDATION CHECKS PASSED SUCCESSFULLY! <<<');
    process.exit(0);
} else {
    console.error('\n>>> VALIDATION CHECKS FAILED! <<<');
    process.exit(1);
}
