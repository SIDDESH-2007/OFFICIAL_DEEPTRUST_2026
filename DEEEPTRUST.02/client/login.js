/**
 * ============================================================
 * login.js — Main Authentication Flow Orchestrator
 * ============================================================
 * This is the "conductor" of the whole login process.
 * It calls each verification stage in sequence and stops
 * immediately if any stage fails.
 *
 * FLOW:
 *   User submits form
 *     → Stage 1A: Face Verification      (faceAuth.js)
 *     → Stage 1B: Pattern Validation     (patternAuth.js)
 *     → Stage 2:  Mouse Behaviour Score  (mouseTracker.js)
 *     → Stage 3:  CAPTCHA                (captcha.js)
 *     → API Call                         (apiService.js)
 *     → Save Session & Redirect          (session.js)
 *
 * Dependencies (load BEFORE login.js in HTML):
 *   faceAuth.js | patternAuth.js | mouseTracker.js |
 *   captcha.js  | apiService.js  | session.js
 * ============================================================
 */

// ── Wait for DOM to be fully loaded before attaching events ──
document.addEventListener('DOMContentLoaded', () => {

  // ── DOM references ────────────────────────────────────────
  const loginForm        = document.getElementById('login-form');
  const usernameInput    = document.getElementById('username');
  const passwordInput    = document.getElementById('password');
  const loginBtn         = document.getElementById('login-btn');

  // Status display area — show messages to the user
  const statusBox        = document.getElementById('auth-status');

  // Containers where webcam preview / CAPTCHA will be injected
  const faceContainer    = document.getElementById('face-container');
  const captchaContainer = document.getElementById('captcha-container');

  // ── Guard: redirect if already logged in ─────────────────
  // If a valid session exists, skip the login page entirely
  Session.redirectIfAuthenticated('/dashboard.html');

  // ── UI Helpers ────────────────────────────────────────────

  /**
   * setStatus()
   * Updates the status box with a message and visual style.
   *
   * @param {string} message  - text to display
   * @param {'info'|'success'|'error'|'loading'} type
   */
  function setStatus(message, type = 'info') {
    if (!statusBox) return;

    const colours = {
      info:    '#aaa',
      success: '#00ff88',
      error:   '#ff4444',
      loading: '#00ffe7',
    };

    statusBox.style.color   = colours[type] || '#aaa';
    statusBox.textContent   = message;
    statusBox.style.display = message ? 'block' : 'none';
  }

  /**
   * setLoading()
   * Disables / enables the login button and shows a spinner label.
   *
   * @param {boolean} loading
   * @param {string}  [label]
   */
  function setLoading(loading, label = 'Verifying…') {
    if (!loginBtn) return;
    loginBtn.disabled    = loading;
    loginBtn.textContent = loading ? label : 'Login';
  }

  /**
   * showSection()
   * Shows or hides a DOM element.
   *
   * @param {HTMLElement|null} el
   * @param {boolean} visible
   */
  function showSection(el, visible) {
    if (!el) return;
    el.style.display = visible ? 'block' : 'none';
  }

  // ── Stage runners ─────────────────────────────────────────

  /**
   * runStage1Face()
   * Opens the webcam, shows a preview, captures and verifies the face.
   *
   * @returns {Promise<boolean>}
   */
  async function runStage1Face() {
    setStatus('Stage 1/3 — Verifying your identity…', 'loading');
    showSection(faceContainer, true);

    const result = await FaceAuth.verify(faceContainer);

    showSection(faceContainer, false);
    return result;
  }

  /**
   * runStage1Pattern()
   * Validates username and password format client-side.
   *
   * @param {string} username
   * @param {string} password
   * @returns {{ passed: boolean, errors: string[] }}
   */
  function runStage1Pattern(username, password) {
    return PatternAuth.verify({ username, password });
  }

  /**
   * runStage2Mouse()
   * Collects mouse movement for 3 seconds and returns a behaviour score.
   *
   * @returns {Promise<number>} score 0–100
   */
  async function runStage2Mouse() {
    setStatus('Stage 2/3 — Move your mouse naturally while we analyse behaviour…', 'loading');

    // Pass a countdown callback so the user sees "3… 2… 1…"
    const { human, score } = await MouseTracker.isHuman((remaining) => {
      setStatus(`Stage 2/3 — Keep moving your mouse… (${remaining}s)`, 'loading');
    });

    return { human, score };
  }

  /**
   * runStage3Captcha()
   * Renders the CAPTCHA widget and waits for the user to solve it.
   *
   * @returns {Promise<boolean>}
   */
  async function runStage3Captcha() {
    setStatus('Stage 3/3 — Complete the security check below.', 'loading');
    showSection(captchaContainer, true);

    const result = await Captcha.verify(captchaContainer);

    showSection(captchaContainer, false);
    return result;
  }

  // ── Main login handler ────────────────────────────────────

  /**
   * handleLogin()
   * Orchestrates the full authentication pipeline.
   * Called when the user submits the login form.
   *
   * @param {Event} event - form submit event
   */
  async function handleLogin(event) {
    // Prevent the default HTML form submission (page reload)
    event.preventDefault();

    // ── Collect credentials ─────────────────────────────────
    const username = (usernameInput?.value || '').trim();
    const password  = passwordInput?.value || '';

    // Basic check — fields must not be empty
    if (!username || !password) {
      setStatus('Please enter your username and password.', 'error');
      return;
    }

    // ── Lock the UI ─────────────────────────────────────────
    setLoading(true, 'Starting verification…');
    setStatus('', 'info');

    // ── Variable declarations ────────────────────────────────
    // We collect all results and send them together at the end.
    let faceVerificationResult    = false;
    let patternVerificationResult = false;
    let mouseBehaviorScore        = 0;
    let captchaResult             = false;

    try {

      // ════════════════════════════════════════════════════════
      // STAGE 1A — Pattern / Password Validation
      // (Run first because it's instant — no async needed)
      // ════════════════════════════════════════════════════════
      const patternCheck = runStage1Pattern(username, password);

      if (!patternCheck.passed) {
        // Show the first error message from the list
        setStatus(`❌ ${patternCheck.errors[0]}`, 'error');
        setLoading(false);
        return; // STOP — don't continue to other stages
      }

      patternVerificationResult = true;
      console.log('[Login] ✅ Stage 1B (Pattern) passed.');

      // ════════════════════════════════════════════════════════
      // STAGE 1B — Face Verification
      // ════════════════════════════════════════════════════════
      faceVerificationResult = await runStage1Face();

      if (!faceVerificationResult) {
        setStatus('❌ Face verification failed. Please try again.', 'error');
        setLoading(false);
        return; // STOP
      }

      console.log('[Login] ✅ Stage 1A (Face) passed.');

      // ════════════════════════════════════════════════════════
      // STAGE 2 — Mouse Behaviour Analysis
      // ════════════════════════════════════════════════════════
      const mouseResult = await runStage2Mouse();
      mouseBehaviorScore = mouseResult.score;

      if (!mouseResult.human) {
        setStatus(
          `❌ Behaviour check failed (score: ${mouseBehaviorScore}/100). Automated input detected.`,
          'error'
        );
        setLoading(false);
        return; // STOP
      }

      console.log(`[Login] ✅ Stage 2 (Mouse) passed. Score: ${mouseBehaviorScore}`);

      // ════════════════════════════════════════════════════════
      // STAGE 3 — CAPTCHA Verification
      // ════════════════════════════════════════════════════════
      captchaResult = await runStage3Captcha();

      if (!captchaResult) {
        setStatus('❌ CAPTCHA verification failed. Please complete the challenge.', 'error');
        setLoading(false);
        return; // STOP
      }

      console.log('[Login] ✅ Stage 3 (CAPTCHA) passed.');

      // ════════════════════════════════════════════════════════
      // ALL STAGES PASSED — Send to backend
      // ════════════════════════════════════════════════════════
      setStatus('All checks passed. Authenticating…', 'loading');
      setLoading(true, 'Authenticating…');

      const apiResponse = await ApiService.loginAdmin({
        username,
        password,
        faceVerificationResult,
        patternVerificationResult,
        mouseBehaviorScore,
        captchaResult,
      });

      if (!apiResponse.success) {
        setStatus(`❌ Login failed: ${apiResponse.message}`, 'error');
        setLoading(false);
        return; // STOP
      }

      // ════════════════════════════════════════════════════════
      // SUCCESS — Save session and redirect
      // ════════════════════════════════════════════════════════
      Session.save(apiResponse.token, apiResponse.user);

      setStatus('✅ Authentication successful! Redirecting…', 'success');

      // Short delay so the user sees the success message
      setTimeout(() => {
        window.location.replace('/dashboard.html');
      }, 800);

    } catch (err) {
      // Unexpected error (shouldn't happen, but always handle it)
      console.error('[Login] Unexpected error:', err);
      setStatus('An unexpected error occurred. Please try again.', 'error');
      setLoading(false);
    }
  }

  // ── Attach event listener ─────────────────────────────────
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  } else {
    // Fallback: attach to the login button directly
    loginBtn?.addEventListener('click', handleLogin);
  }

  // ── Password strength indicator (optional UX feature) ─────
  passwordInput?.addEventListener('input', () => {
    const strength = PatternAuth.getStrengthLabel(passwordInput.value);
    const indicator = document.getElementById('password-strength');
    if (!indicator) return;

    const labels = {
      'weak':        { text: 'Weak',        color: '#ff4444' },
      'medium':      { text: 'Medium',      color: '#ffaa00' },
      'strong':      { text: 'Strong',      color: '#00cc66' },
      'very-strong': { text: 'Very Strong', color: '#00ff88' },
    };

    const { text, color } = labels[strength] || labels['weak'];
    indicator.textContent = text;
    indicator.style.color = color;
  });

});
