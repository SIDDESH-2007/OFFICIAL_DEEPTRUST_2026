/**
 * ============================================================
 * patternAuth.js — Stage 1B: Pattern / Password Verification
 * ============================================================
 * Responsibilities:
 *   - Validate username + password against known rules
 *   - Optionally validate a PIN or unlock pattern
 *   - Return true (valid) or false (invalid)
 *
 * In a real system passwords are NEVER checked client-side
 * against plaintext — this module only enforces FORMAT rules
 * and passes the credentials to the backend via apiService.js.
 * ============================================================
 */

const PatternAuth = (() => {

  // ── Configuration ──────────────────────────────────────────

  const RULES = {
    minPasswordLength: 8,
    requireUppercase:  true,
    requireNumber:     true,
    requireSpecial:    true,
    minUsernameLength: 3,
  };

  // Regex helpers
  const HAS_UPPERCASE = /[A-Z]/;
  const HAS_NUMBER    = /[0-9]/;
  const HAS_SPECIAL   = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;

  // ── Validation helpers ─────────────────────────────────────

  /**
   * validateUsername()
   * Checks that the username meets basic length & format rules.
   *
   * @param {string} username
   * @returns {{ valid: boolean, reason: string }}
   */
  function validateUsername(username) {
    const trimmed = (username || '').trim();

    if (!trimmed) {
      return { valid: false, reason: 'Username is required.' };
    }
    if (trimmed.length < RULES.minUsernameLength) {
      return { valid: false, reason: `Username must be at least ${RULES.minUsernameLength} characters.` };
    }

    return { valid: true, reason: '' };
  }

  /**
   * validatePassword()
   * Enforces complexity rules on the password string.
   * These checks happen CLIENT-SIDE only for UX feedback;
   * the real auth happens on the server.
   *
   * @param {string} password
   * @returns {{ valid: boolean, reason: string }}
   */
  function validatePassword(password) {
    if (!password) {
      return { valid: false, reason: 'Password is required.' };
    }
    if (password.length < RULES.minPasswordLength) {
      return { valid: false, reason: `Password must be at least ${RULES.minPasswordLength} characters.` };
    }
    if (RULES.requireUppercase && !HAS_UPPERCASE.test(password)) {
      return { valid: false, reason: 'Password must contain at least one uppercase letter.' };
    }
    if (RULES.requireNumber && !HAS_NUMBER.test(password)) {
      return { valid: false, reason: 'Password must contain at least one number.' };
    }
    if (RULES.requireSpecial && !HAS_SPECIAL.test(password)) {
      return { valid: false, reason: 'Password must contain at least one special character (!@#$…).' };
    }

    return { valid: true, reason: '' };
  }

  /**
   * validatePin()  [optional second factor]
   * Checks a 4–6 digit numeric PIN.
   *
   * @param {string} pin
   * @returns {{ valid: boolean, reason: string }}
   */
  function validatePin(pin) {
    if (!pin) return { valid: true, reason: '' }; // PIN is optional

    const digits = /^\d{4,6}$/.test(pin);
    if (!digits) {
      return { valid: false, reason: 'PIN must be 4–6 digits.' };
    }
    return { valid: true, reason: '' };
  }

  // ── Core API ───────────────────────────────────────────────

  /**
   * verify()
   * Run all pattern/password checks and return a combined result.
   *
   * @param {object} credentials
   * @param {string} credentials.username
   * @param {string} credentials.password
   * @param {string} [credentials.pin] - optional
   * @returns {{ passed: boolean, errors: string[] }}
   */
  function verify({ username, password, pin = '' }) {
    const errors = [];

    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) errors.push(usernameCheck.reason);

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) errors.push(passwordCheck.reason);

    const pinCheck = validatePin(pin);
    if (!pinCheck.valid) errors.push(pinCheck.reason);

    const passed = errors.length === 0;

    if (passed) {
      console.log('[PatternAuth] ✅ Credentials passed format validation.');
    } else {
      console.warn('[PatternAuth] ❌ Validation failed:', errors);
    }

    return { passed, errors };
  }

  /**
   * getStrengthLabel()
   * Returns a human-readable password strength label.
   * Useful for rendering a strength meter in the UI.
   *
   * @param {string} password
   * @returns {'weak' | 'medium' | 'strong' | 'very-strong'}
   */
  function getStrengthLabel(password) {
    if (!password || password.length < 6) return 'weak';

    let score = 0;
    if (password.length >= 8)  score++;
    if (password.length >= 12) score++;
    if (HAS_UPPERCASE.test(password)) score++;
    if (HAS_NUMBER.test(password))    score++;
    if (HAS_SPECIAL.test(password))   score++;

    if (score <= 1) return 'weak';
    if (score === 2) return 'medium';
    if (score === 3) return 'strong';
    return 'very-strong';
  }

  // ── Public interface ───────────────────────────────────────
  return { verify, getStrengthLabel };

})();
