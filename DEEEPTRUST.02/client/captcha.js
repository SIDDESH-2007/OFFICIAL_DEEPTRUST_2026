/**
 * ============================================================
 * captcha.js — Stage 3: CAPTCHA Verification
 * ============================================================
 * Responsibilities:
 *   - Render a CAPTCHA challenge (mock built-in or Google reCAPTCHA v2)
 *   - Wait for the user to solve it
 *   - Validate the token / response
 *   - Return true (human) or false (bot / unsolved)
 *
 * TWO MODES (switch via CAPTCHA_MODE constant):
 *   'mock'    → built-in math CAPTCHA, no external deps
 *   'google'  → Google reCAPTCHA v2 (needs site key in HTML)
 * ============================================================
 */

const Captcha = (() => {

  // ── Configuration ──────────────────────────────────────────

  // Change to 'google' to use Google reCAPTCHA v2
  const CAPTCHA_MODE = 'mock';

  // Your Google reCAPTCHA v2 site key (only needed in 'google' mode)
  // Get one at: https://www.google.com/recaptcha/admin/create
  const RECAPTCHA_SITE_KEY = 'YOUR_SITE_KEY_HERE';

  // ── Mock CAPTCHA (built-in math challenge) ─────────────────

  /**
   * generateMathChallenge()
   * Creates a simple arithmetic question and its answer.
   *
   * @returns {{ question: string, answer: number }}
   */
  function generateMathChallenge() {
    const a  = Math.floor(Math.random() * 9) + 1;
    const b  = Math.floor(Math.random() * 9) + 1;
    const op = ['+', '-', '×'][Math.floor(Math.random() * 3)];

    let answer;
    switch (op) {
      case '+': answer = a + b; break;
      case '-': answer = a - b; break;
      case '×': answer = a * b; break;
    }

    return { question: `${a} ${op} ${b}`, answer };
  }

  /**
   * renderMockCaptcha()
   * Builds the math-challenge UI inside a container element.
   * Returns a Promise that resolves to true/false when submitted.
   *
   * @param {HTMLElement} container
   * @returns {Promise<boolean>}
   */
  function renderMockCaptcha(container) {
    const challenge = generateMathChallenge();

    // ── Build the challenge UI ─────────────────────────────
    container.innerHTML = `
      <div id="mock-captcha" style="
        border: 1px solid var(--accent, #00ffe7);
        border-radius: 10px;
        padding: 16px 20px;
        margin-top: 12px;
        background: rgba(0,255,231,0.04);
        font-family: 'Courier New', monospace;
        text-align: center;
      ">
        <p style="margin: 0 0 10px; font-size: 13px; color: #aaa; letter-spacing: 1px;">
          🔐 SECURITY CHECK
        </p>

        <!-- Distorted-looking question rendered on canvas -->
        <canvas id="captcha-canvas" width="200" height="52"
          style="border-radius:6px; margin-bottom:10px; display:block; margin:0 auto 12px;">
        </canvas>

        <input
          id="captcha-input"
          type="number"
          placeholder="Your answer"
          autocomplete="off"
          style="
            width: 120px;
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #444;
            background: #111;
            color: #fff;
            font-size: 16px;
            text-align: center;
            outline: none;
          "
        />

        <div style="margin-top:12px; display:flex; gap:10px; justify-content:center;">
          <button id="captcha-submit" style="
            padding: 8px 20px;
            background: var(--accent, #00ffe7);
            color: #000;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 1px;
          ">VERIFY</button>

          <button id="captcha-refresh" title="New challenge" style="
            padding: 8px 12px;
            background: transparent;
            color: #aaa;
            border: 1px solid #444;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
          ">↻</button>
        </div>

        <p id="captcha-msg" style="
          margin: 10px 0 0;
          font-size: 12px;
          color: #f55;
          min-height: 16px;
        "></p>
      </div>
    `;

    // Draw the question on canvas (adds slight noise / distortion)
    drawChallengeOnCanvas(
      document.getElementById('captcha-canvas'),
      challenge.question + ' = ?'
    );

    // ── Return a Promise that resolves when user submits ───
    return new Promise((resolve) => {

      document.getElementById('captcha-submit').addEventListener('click', () => {
        const input = document.getElementById('captcha-input');
        const msg   = document.getElementById('captcha-msg');
        const val   = parseInt(input.value, 10);

        if (isNaN(val)) {
          msg.textContent = 'Please enter a number.';
          return;
        }

        if (val === challenge.answer) {
          msg.style.color  = '#0f0';
          msg.textContent  = '✓ Correct!';
          setTimeout(() => resolve(true), 600);
        } else {
          msg.style.color  = '#f55';
          msg.textContent  = '✗ Wrong answer. Try again.';
          input.value      = '';
        }
      });

      // Refresh button: re-render with a new challenge
      document.getElementById('captcha-refresh').addEventListener('click', () => {
        renderMockCaptcha(container).then(resolve);
      });

      // Allow pressing Enter to submit
      document.getElementById('captcha-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          document.getElementById('captcha-submit').click();
        }
      });
    });
  }

  /**
   * drawChallengeOnCanvas()
   * Renders the math question with slight visual noise so it
   * looks harder for simple OCR/bots to parse.
   *
   * @param {HTMLCanvasElement} canvas
   * @param {string} text
   */
  function drawChallengeOnCanvas(canvas, text) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Background
    ctx.fillStyle = '#0d0d0d';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Noise lines
    for (let i = 0; i < 8; i++) {
      ctx.strokeStyle = `rgba(0,255,231,${0.05 + Math.random() * 0.1})`;
      ctx.lineWidth   = 1;
      ctx.beginPath();
      ctx.moveTo(Math.random() * canvas.width, Math.random() * canvas.height);
      ctx.lineTo(Math.random() * canvas.width, Math.random() * canvas.height);
      ctx.stroke();
    }

    // Text (slightly tilted, coloured)
    ctx.save();
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate((Math.random() - 0.5) * 0.15); // subtle tilt
    ctx.font        = 'bold 24px "Courier New", monospace';
    ctx.fillStyle   = '#00ffe7';
    ctx.textAlign   = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, 0, 0);
    ctx.restore();
  }

  // ── Google reCAPTCHA v2 mode ───────────────────────────────

  /**
   * renderGoogleCaptcha()
   * Mounts a standard reCAPTCHA v2 widget into the container
   * and resolves true when the user completes it.
   *
   * Prerequisites in HTML:
   *   <script src="https://www.google.com/recaptcha/api.js" async defer></script>
   *
   * @param {HTMLElement} container
   * @returns {Promise<boolean>}
   */
  function renderGoogleCaptcha(container) {
    container.innerHTML = `<div id="g-recaptcha-widget" style="margin-top:12px;"></div>`;

    return new Promise((resolve) => {
      // grecaptcha is loaded by the <script> tag in HTML
      if (typeof grecaptcha === 'undefined') {
        console.error('[Captcha] Google reCAPTCHA script not loaded.');
        resolve(false);
        return;
      }

      grecaptcha.render('g-recaptcha-widget', {
        sitekey:  RECAPTCHA_SITE_KEY,
        theme:    'dark',
        callback: (token) => {
          // token is a non-empty string when the user passes the challenge
          console.log('[Captcha] reCAPTCHA token received:', token.slice(0, 20) + '…');
          resolve(!!token);
        },
        'expired-callback': () => {
          console.warn('[Captcha] reCAPTCHA expired.');
          resolve(false);
        },
      });
    });
  }

  // ── Core API ───────────────────────────────────────────────

  /**
   * verify()
   * Main entry point. Renders the appropriate CAPTCHA type and
   * returns the result.
   *
   * @param {HTMLElement} container - DOM element to render CAPTCHA into
   * @returns {Promise<boolean>} true = human verified
   */
  async function verify(container) {
    try {
      if (CAPTCHA_MODE === 'google') {
        return await renderGoogleCaptcha(container);
      }
      // Default: mock math CAPTCHA
      return await renderMockCaptcha(container);
    } catch (err) {
      console.error('[Captcha] Error during verification:', err);
      return false;
    }
  }

  // ── Public interface ───────────────────────────────────────
  return { verify };

})();
