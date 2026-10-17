/**
 * ============================================================
 * apiService.js — Backend API Communication
 * ============================================================
 * Responsibilities:
 *   - POST all authentication data to /api/admin/login
 *   - Handle HTTP errors and network failures gracefully
 *   - Return a structured response object to login.js
 *
 * The backend should validate the password, issue a JWT, and
 * optionally re-verify the CAPTCHA token server-side.
 * ============================================================
 */

const ApiService = (() => {

  // ── Configuration ──────────────────────────────────────────

  // Change this to your actual backend URL in production
  const BASE_URL = '';  // e.g. 'https://api.yourdomain.com'

  const ENDPOINTS = {
    adminLogin: `${BASE_URL}/api/admin/login`,
  };

  // Request timeout (ms) — avoids hanging indefinitely
  const REQUEST_TIMEOUT_MS = 10_000;

  // ── Helpers ────────────────────────────────────────────────

  /**
   * withTimeout()
   * Wraps a fetch() Promise with a timeout so we don't wait forever.
   *
   * @param {Promise} fetchPromise
   * @param {number}  ms - milliseconds before rejection
   * @returns {Promise}
   */
  function withTimeout(fetchPromise, ms) {
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Request timed out after ${ms}ms`)), ms)
    );
    return Promise.race([fetchPromise, timeout]);
  }

  /**
   * buildHeaders()
   * Returns standard JSON request headers.
   * Add Authorization header here if hitting a pre-auth endpoint.
   *
   * @returns {Headers}
   */
  function buildHeaders() {
    return {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // CSRF hint for some servers
    };
  }

  // ── Core API ───────────────────────────────────────────────

  /**
   * loginAdmin()
   * POSTs the full authentication payload to the backend.
   *
   * Expected server response (200 OK):
   * {
   *   success: true,
   *   token:   "eyJ...",       // JWT access token
   *   user: {
   *     id:   "...",
   *     role: "admin"
   *   }
   * }
   *
   * On failure (4xx / 5xx):
   * {
   *   success: false,
   *   message: "Invalid credentials."
   * }
   *
   * @param {object} payload
   * @param {string}  payload.username
   * @param {string}  payload.password
   * @param {boolean} payload.faceVerificationResult
   * @param {boolean} payload.patternVerificationResult
   * @param {number}  payload.mouseBehaviorScore
   * @param {boolean} payload.captchaResult
   *
   * @returns {Promise<{ success: boolean, token?: string, message?: string }>}
   */
  async function loginAdmin({
    username,
    password,
    faceVerificationResult,
    patternVerificationResult,
    mouseBehaviorScore,
    captchaResult,
  }) {
    // ── Build request body ─────────────────────────────────
    const body = JSON.stringify({
      username,
      password,
      faceVerificationResult,    // boolean
      patternVerificationResult, // boolean
      mouseBehaviorScore,        // number 0–100
      captchaResult,             // boolean
      clientTimestamp: Date.now(), // helps detect replay attacks server-side
    });

    console.log('[ApiService] Sending login request…', {
      username,
      faceVerificationResult,
      patternVerificationResult,
      mouseBehaviorScore,
      captchaResult,
    });

    try {
      // ── Fire the request (with timeout guard) ─────────────
      const response = await withTimeout(
        fetch(ENDPOINTS.adminLogin, {
          method:      'POST',
          headers:     buildHeaders(),
          body,
          credentials: 'same-origin', // sends cookies for CSRF protection
        }),
        REQUEST_TIMEOUT_MS
      );

      // ── Parse JSON ─────────────────────────────────────────
      const data = await response.json();

      if (!response.ok) {
        // Server returned a 4xx or 5xx error
        const errMsg = data?.message || `Server error: HTTP ${response.status}`;
        console.error('[ApiService] Login rejected:', errMsg);
        return { success: false, message: errMsg };
      }

      console.log('[ApiService] ✅ Login accepted. Token received.');
      return data; // { success: true, token: "...", user: {...} }

    } catch (err) {
      // Network error, timeout, or JSON parse failure
      console.error('[ApiService] Network/fetch error:', err.message);
      return {
        success: false,
        message: err.message.includes('timed out')
          ? 'Server is not responding. Please try again.'
          : 'Network error. Check your connection.',
      };
    }
  }

  // ── Public interface ───────────────────────────────────────
  return { loginAdmin };

})();
