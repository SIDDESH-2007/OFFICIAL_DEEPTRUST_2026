/**
 * session.js
 * Unified Session & Token Management for DeepTrust Platform
 *
 * Distinct Token Separation:
 * - Token A (Verification / Pre-Auth Token): Used strictly during Face, Liveness, Voice, MFA verification stages.
 * - Token B (Final Access Token): Issued only after POST /api/v1/auth/finalize confirms all security factors.
 */

const SESSION_TOKEN_KEY = 'dt_admin_token';
const SESSION_EXP_KEY = 'dt_admin_token_exp';
const SESSION_STORAGE_MODE_KEY = 'dt_admin_token_storage';
const VERIFICATION_TOKEN_KEY = 'dt_verification_token';
const VERIFICATION_SESSION_KEY = 'dt_verification_session_id';
const USER_INFO_KEY = 'dt_user_info';
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 mins

const authEvents = new EventTarget();
let expiryTimerId = null;
let idleTimerId = null;

const storageProviders = {
    session: sessionStorage,
    local: localStorage
};

const getStorageMode = () => {
    const mode = localStorage.getItem(SESSION_STORAGE_MODE_KEY) || sessionStorage.getItem(SESSION_STORAGE_MODE_KEY);
    return mode === 'local' ? 'local' : 'session';
};

const getActiveStorage = () => storageProviders[getStorageMode()];

const decodeJwtPayload = (token) => {
    try {
        const payloadSegment = token.split('.')[1];
        if (!payloadSegment) return null;
        const base64 = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(
            atob(base64)
                .split('')
                .map((c) => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
                .join('')
        );
        return JSON.parse(json);
    } catch {
        return null;
    }
};

const clearStoredToken = () => {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem(SESSION_EXP_KEY);
    sessionStorage.removeItem(SESSION_STORAGE_MODE_KEY);
    sessionStorage.removeItem(USER_INFO_KEY);

    localStorage.removeItem(SESSION_TOKEN_KEY);
    localStorage.removeItem(SESSION_EXP_KEY);
    localStorage.removeItem(SESSION_STORAGE_MODE_KEY);
    localStorage.removeItem(USER_INFO_KEY);
    
    // Clear legacy/demo storage keys if present
    localStorage.removeItem('deeptrust_user');
    localStorage.removeItem('deeptrust_token');
    localStorage.removeItem('user');
    localStorage.removeItem('token');
};

export const setVerificationSession = (sessionId, verificationToken, user = null) => {
    if (sessionId) sessionStorage.setItem(VERIFICATION_SESSION_KEY, sessionId);
    if (verificationToken) sessionStorage.setItem(VERIFICATION_TOKEN_KEY, verificationToken);
    if (user) sessionStorage.setItem(USER_INFO_KEY, JSON.stringify(user));
};

export const getVerificationSession = () => {
    return {
        sessionId: sessionStorage.getItem(VERIFICATION_SESSION_KEY),
        verificationToken: sessionStorage.getItem(VERIFICATION_TOKEN_KEY),
        user: getUserInfo()
    };
};

export const clearVerificationSession = () => {
    sessionStorage.removeItem(VERIFICATION_SESSION_KEY);
    sessionStorage.removeItem(VERIFICATION_TOKEN_KEY);
};

export const setSessionToken = (token, options = {}) => {
    if (!token || typeof token !== 'string') {
        throw new Error('Invalid auth token');
    }

    const payload = decodeJwtPayload(token);
    const expMs = payload?.exp ? payload.exp * 1000 : Date.now() + 8 * 3600 * 1000;
    const persistent = Boolean(options?.persistent);
    const mode = persistent ? 'local' : 'session';
    const storage = persistent ? localStorage : sessionStorage;

    clearStoredToken();
    storage.setItem(SESSION_TOKEN_KEY, token);
    storage.setItem(SESSION_EXP_KEY, String(expMs));
    storage.setItem(SESSION_STORAGE_MODE_KEY, mode);
    localStorage.setItem(SESSION_STORAGE_MODE_KEY, mode);

    if (options?.user) {
        storage.setItem(USER_INFO_KEY, JSON.stringify(options.user));
    }

    // Clear temporary verification state now that final token is secured
    clearVerificationSession();

    authEvents.dispatchEvent(new CustomEvent('auth:login', { detail: { expMs, persistent } }));
};

export const getSessionToken = () => {
    // Check both session and local storage to handle tab duplication / persistence
    const token = sessionStorage.getItem(SESSION_TOKEN_KEY) || localStorage.getItem(SESSION_TOKEN_KEY);
    const expMs = Number(sessionStorage.getItem(SESSION_EXP_KEY) || localStorage.getItem(SESSION_EXP_KEY) || 0);

    if (!token) return null;

    if (expMs && Date.now() >= expMs) {
        clearSession('expired');
        return null;
    }

    return token;
};

export const getUserInfo = () => {
    try {
        const raw = sessionStorage.getItem(USER_INFO_KEY) || localStorage.getItem(USER_INFO_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch {
        return null;
    }
};

export const getAuthorizationHeader = () => {
    const token = getSessionToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
};

export const refreshSessionActivity = () => {
    if (getSessionToken()) {
        authEvents.dispatchEvent(new CustomEvent('auth:activity'));
    }
};

export const clearSession = (reason = 'manual-logout') => {
    clearStoredToken();
    clearVerificationSession();
    authEvents.dispatchEvent(new CustomEvent('auth:logout', { detail: { reason } }));
};

export const requireValidSession = () => {
    const token = getSessionToken();
    return Boolean(token);
};

export const onAuthEvent = (eventName, handler) => {
    authEvents.addEventListener(eventName, handler);
    return () => authEvents.removeEventListener(eventName, handler);
};

// Global Bridge for standard scripts
if (typeof window !== 'undefined') {
    window.Session = {
        save: (token, user, persistent) => setSessionToken(token, { user, persistent }),
        getToken: getSessionToken,
        getUser: getUserInfo,
        setVerification: setVerificationSession,
        getVerification: getVerificationSession,
        clear: clearSession,
        isActive: () => Boolean(getSessionToken()),
        logout: () => {
            clearSession('manual-logout');
            window.location.replace('login.html');
        }
    };
}
