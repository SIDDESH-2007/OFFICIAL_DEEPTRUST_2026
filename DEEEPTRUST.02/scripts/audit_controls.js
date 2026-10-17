const fs = require('fs');
const path = require('path');

const loginHtml = fs.readFileSync(path.join(__dirname, '../client/index.html'), 'utf8');
const dashHtml = fs.readFileSync(path.join(__dirname, '../client/dashboard.html'), 'utf8');

function extractControls(html, docName) {
    const buttonRegex = /<button[^>]*>([\s\S]*?)<\/button>/gi;
    const linkRegex = /<a[^>]*>([\s\S]*?)<\/a>/gi;
    const inputRegex = /<input[^>]*>/gi;

    const buttons = [];
    const links = [];
    const inputs = [];

    let match;
    while ((match = buttonRegex.exec(html)) !== null) {
        const tag = match[0];
        const idMatch = tag.match(/id="([^"]+)"/);
        const text = match[1].replace(/<[^>]+>/g, '').trim();
        buttons.push({ id: idMatch ? idMatch[1] : 'no-id', text: text || 'icon/svg', tag: tag.slice(0, 100) });
    }

    while ((match = linkRegex.exec(html)) !== null) {
        const tag = match[0];
        const hrefMatch = tag.match(/href="([^"]+)"/);
        const dataView = tag.match(/data-view="([^"]+)"/);
        const text = match[1].replace(/<[^>]+>/g, '').trim();
        links.push({
            href: hrefMatch ? hrefMatch[1] : '',
            dataView: dataView ? dataView[1] : '',
            text: text || 'icon/brand',
            tag: tag.slice(0, 100)
        });
    }

    while ((match = inputRegex.exec(html)) !== null) {
        const tag = match[0];
        const idMatch = tag.match(/id="([^"]+)"/);
        const typeMatch = tag.match(/type="([^"]+)"/);
        inputs.push({ id: idMatch ? idMatch[1] : 'no-id', type: typeMatch ? typeMatch[1] : 'text' });
    }

    return { docName, buttons, links, inputs };
}

const loginControls = extractControls(loginHtml, 'Login / Auth Verification Views (index.html)');
const dashControls = extractControls(dashHtml, 'Dashboard & Console (dashboard.html)');

console.log('=== CLICKABLE CONTROLS AUDIT ===\n');

console.log(`Document: ${loginControls.docName}`);
console.log(`- Buttons: ${loginControls.buttons.length}`);
console.log(`- Links: ${loginControls.links.length}`);
console.log(`- Inputs: ${loginControls.inputs.length}`);
loginControls.buttons.forEach((b, i) => console.log(`  [BTN ${i+1}] id="${b.id}" label="${b.text.slice(0, 30)}"`));
loginControls.links.forEach((l, i) => console.log(`  [LINK ${i+1}] href="${l.href}" text="${l.text.slice(0, 30)}"`));

console.log(`\nDocument: ${dashControls.docName}`);
console.log(`- Buttons: ${dashControls.buttons.length}`);
console.log(`- Links: ${dashControls.links.length}`);
console.log(`- Inputs: ${dashControls.inputs.length}`);
dashControls.buttons.slice(0, 20).forEach((b, i) => console.log(`  [BTN ${i+1}] id="${b.id}" label="${b.text.slice(0, 30)}"`));
console.log(`  ... and ${dashControls.buttons.length - 20} more buttons`);
dashControls.links.slice(0, 20).forEach((l, i) => console.log(`  [NAV/LINK ${i+1}] dataView="${l.dataView}" text="${l.text.slice(0, 30)}"`));
console.log(`  ... and ${dashControls.links.length - 20} more links`);

const totalControls = loginControls.buttons.length + loginControls.links.length + dashControls.buttons.length + dashControls.links.length;
console.log(`\nTOTAL INTERACTIVE CONTROLS: ${totalControls}`);
