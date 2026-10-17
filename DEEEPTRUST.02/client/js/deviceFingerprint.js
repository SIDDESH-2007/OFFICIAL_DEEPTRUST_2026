/**
 * deviceFingerprint.js
 * Stage 0 - Device fingerprint and trust scoring module.
 *
 * Security design notes:
 * - Uses non-PII environment signals and hashes them before use/transmission.
 * - Produces deterministic fingerprint and bounded trust score.
 * - Keeps collected attributes minimal to reduce privacy exposure.
 */

const encoder = new TextEncoder();

const toHex = (buffer) =>
    Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

const getWebGlFingerprint = () => {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) {
            return 'webgl-unavailable';
        }

        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'vendor-unknown';
        const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'renderer-unknown';
        return `${vendor}|${renderer}|${gl.getParameter(gl.VERSION)}`;
    } catch {
        return 'webgl-error';
    }
};

const getCanvasFingerprint = () => {
    try {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        context.textBaseline = 'top';
        context.font = '16px Inter';
        context.fillStyle = '#2563eb';
        context.fillRect(10, 10, 100, 32);
        context.fillStyle = '#1e3a8a';
        context.fillText('DeepTrust-Canvas', 12, 14);
        return canvas.toDataURL();
    } catch {
        return 'canvas-error';
    }
};

const detectAvailableFonts = () => {
    try {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const probeFonts = ['Inter', 'Segoe UI', 'Arial', 'Roboto', 'Helvetica', 'Times New Roman', 'Courier New'];
        const testString = 'mmmmmmmmmlli';
        const testSize = '72px';
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');

        const baseline = baseFonts.reduce((result, base) => {
            context.font = `${testSize} ${base}`;
            result[base] = context.measureText(testString).width;
            return result;
        }, {});

        return probeFonts.filter((font) => {
            return baseFonts.some((base) => {
                context.font = `${testSize} '${font}', ${base}`;
                const width = context.measureText(testString).width;
                return width !== baseline[base];
            });
        });
    } catch {
        return [];
    }
};

const collectDeviceSignals = () => {
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';
    const touchSupport = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    const fonts = detectAvailableFonts();

    return {
        userAgent: navigator.userAgent || 'unknown',
        screenResolution: `${window.screen?.width || 0}x${window.screen?.height || 0}`,
        timezone,
        language: navigator.language || 'unknown',
        platform: navigator.platform || 'unknown',
        webglFingerprint: getWebGlFingerprint(),
        canvasFingerprint: getCanvasFingerprint(),
        installedFontsHashSource: fonts.join('|') || 'no-font-signature',
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        touchSupport
    };
};

const computeTrustScore = (signals) => {
    let score = 70;

    if (signals.userAgent.includes('Headless')) {
        score -= 40;
    }

    if (signals.screenResolution === '0x0') {
        score -= 20;
    }

    if (signals.platform.toLowerCase().includes('win') || signals.platform.toLowerCase().includes('mac')) {
        score += 10;
    }

    if (signals.timezone === 'unknown') {
        score -= 10;
    }

    return Math.max(0, Math.min(100, score));
};

export const collectDeviceFingerprint = async () => {
    try {
        const rawSignals = collectDeviceSignals();
        const normalized = JSON.stringify(rawSignals);
        const digest = await crypto.subtle.digest('SHA-256', encoder.encode(normalized));
        const fontsDigest = await crypto.subtle.digest('SHA-256', encoder.encode(rawSignals.installedFontsHashSource));

        return {
            fingerprintHash: toHex(digest),
            trustScore: computeTrustScore(rawSignals),
            signals: {
                userAgent: rawSignals.userAgent,
                screenResolution: rawSignals.screenResolution,
                timezone: rawSignals.timezone,
                language: rawSignals.language,
                platform: rawSignals.platform,
                webglFingerprint: rawSignals.webglFingerprint,
                canvasFingerprint: rawSignals.canvasFingerprint,
                installedFontsHash: toHex(fontsDigest),
                hardwareConcurrency: rawSignals.hardwareConcurrency,
                deviceMemory: rawSignals.deviceMemory,
                touchSupport: rawSignals.touchSupport
            }
        };
    } catch {
        throw new Error('Device fingerprint collection failed');
    }
};
