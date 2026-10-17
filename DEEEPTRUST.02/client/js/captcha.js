/**
 * captcha.js
 * Stage 4 - Adaptive CAPTCHA module.
 *
 * Security design notes:
 * - Only activates challenge when risk score exceeds policy threshold.
 * - Difficulty scales with assessed risk.
 * - Returns short-lived challenge token, not raw answer.
 */

let currentToken = null;
let currentAnswer = null;
let initialized = false;

const randomChars = (length) => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    return Array.from({ length }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
};

const challengeConfigByDifficulty = {
    low: { length: 4, prompt: 'Enter the challenge code' },
    medium: { length: 6, prompt: 'Enter the security challenge code' },
    high: { length: 8, prompt: 'High-risk challenge: enter the full security code' }
};

const resolveDifficulty = (riskScore) => {
    if (riskScore >= 80) {
        return 'high';
    }

    if (riskScore >= 60) {
        return 'medium';
    }

    return 'low';
};

const buildToken = () => `captcha-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

export const renderCaptcha = (containerId) => {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="captcha-box" id="captchaBox" hidden>
            <div class="captcha-title" id="captchaPrompt"></div>
            <div class="captcha-code" id="captchaCode"></div>
            <input id="captchaInput" type="text" autocomplete="off" maxlength="12" placeholder="Type code here" />
            <button type="button" id="captchaVerifyBtn">Verify Challenge</button>
            <div class="status-message" id="captchaStatus"></div>
        </div>
    `;

    const verifyButton = container.querySelector('#captchaVerifyBtn');
    verifyButton?.addEventListener('click', () => {
        const answer = container.querySelector('#captchaInput')?.value?.trim().toUpperCase();
        const status = container.querySelector('#captchaStatus');
        if (!answer || answer !== currentAnswer) {
            currentToken = null;
            if (status) {
                status.textContent = 'Challenge failed. Please retry.';
                status.className = 'status-message error';
            }
            return;
        }

        currentToken = buildToken();
        if (status) {
            status.textContent = 'Challenge verified.';
            status.className = 'status-message success';
        }
    });

    initialized = true;
};

export const requestCaptchaChallenge = ({ riskScore }) => {
    if (!initialized) {
        throw new Error('Captcha module is not initialized');
    }

    const box = document.getElementById('captchaBox');
    const prompt = document.getElementById('captchaPrompt');
    const code = document.getElementById('captchaCode');
    const input = document.getElementById('captchaInput');
    const status = document.getElementById('captchaStatus');

    if (!box || !prompt || !code || !input || !status) {
        throw new Error('Captcha UI unavailable');
    }

    const difficulty = resolveDifficulty(riskScore);
    const config = challengeConfigByDifficulty[difficulty];

    currentToken = null;
    currentAnswer = randomChars(config.length);

    prompt.textContent = config.prompt;
    code.textContent = currentAnswer;
    input.value = '';
    status.textContent = '';
    status.className = 'status-message';
    box.hidden = false;

    return { required: true, difficulty };
};

export const clearCaptcha = () => {
    currentToken = null;
    currentAnswer = null;

    const box = document.getElementById('captchaBox');
    const input = document.getElementById('captchaInput');
    const status = document.getElementById('captchaStatus');
    if (box) {
        box.hidden = true;
    }
    if (input) {
        input.value = '';
    }
    if (status) {
        status.textContent = '';
        status.className = 'status-message';
    }
};

export const getCaptchaToken = () => currentToken;
