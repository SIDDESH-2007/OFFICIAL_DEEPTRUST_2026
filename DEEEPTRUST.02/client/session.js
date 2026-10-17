/**
 * session.js — Global Session Bridge
 */

(function () {
    const SESSION_TOKEN_KEY = 'dt_admin_token';
    const SESSION_EXP_KEY = 'dt_admin_token_exp';
    const VERIFICATION_TOKEN_KEY = 'dt_verification_token';
    const VERIFICATION_SESSION_KEY = 'dt_verification_session_id';
    const USER_INFO_KEY = 'dt_user_info';

    function getToken() {
        const t = sessionStorage.getItem(SESSION_TOKEN_KEY) || localStorage.getItem(SESSION_TOKEN_KEY);
        const exp = Number(sessionStorage.getItem(SESSION_EXP_KEY) || localStorage.getItem(SESSION_EXP_KEY) || 0);
        if (!t) return null;
        if (exp && Date.now() >= exp) {
            clear();
            return null;
        }
        return t;
    }

    function getUser() {
        try {
            const raw = sessionStorage.getItem(USER_INFO_KEY) || localStorage.getItem(USER_INFO_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }

    function save(token, user = {}, persistent = false) {
        if (!token) return;
        let expiry = Date.now() + 8 * 3600 * 1000;
        try {
            const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
            if (Number.isFinite(payload.exp)) expiry = payload.exp * 1000;
        } catch { /* Legacy tokens retain the existing fallback lifetime. */ }
        for (const store of [sessionStorage, localStorage]) {
            for (const key of [SESSION_TOKEN_KEY, SESSION_EXP_KEY, USER_INFO_KEY, 'dt_admin_token_storage']) store.removeItem(key);
        }
        const storage = persistent ? localStorage : sessionStorage;
        storage.setItem(SESSION_TOKEN_KEY, token);
        storage.setItem(SESSION_EXP_KEY, String(expiry));
        storage.setItem('dt_admin_token_storage', persistent ? 'local' : 'session');
        localStorage.setItem('dt_admin_token_storage', persistent ? 'local' : 'session');
        if (user) storage.setItem(USER_INFO_KEY, JSON.stringify(user));
        sessionStorage.removeItem(VERIFICATION_TOKEN_KEY);
        sessionStorage.removeItem(VERIFICATION_SESSION_KEY);
    }

    function clear() {
        sessionStorage.removeItem(SESSION_TOKEN_KEY);
        sessionStorage.removeItem(SESSION_EXP_KEY);
        sessionStorage.removeItem(USER_INFO_KEY);
        sessionStorage.removeItem(VERIFICATION_TOKEN_KEY);
        sessionStorage.removeItem(VERIFICATION_SESSION_KEY);

        localStorage.removeItem(SESSION_TOKEN_KEY);
        localStorage.removeItem(SESSION_EXP_KEY);
        localStorage.removeItem(USER_INFO_KEY);
    }

    function isActive() {
        return Boolean(getToken());
    }

    function logout(loginPath = 'login.html') {
        clear();
        window.location.replace(loginPath);
    }

    window.Session = {
        save: save,
        getToken: getToken,
        getUser: getUser,
        clear: clear,
        isActive: isActive,
        logout: logout,
        setVerification: function(sessionId, verificationToken, user) {
            if (sessionId) sessionStorage.setItem(VERIFICATION_SESSION_KEY, sessionId);
            if (verificationToken) sessionStorage.setItem(VERIFICATION_TOKEN_KEY, verificationToken);
            if (user) sessionStorage.setItem(USER_INFO_KEY, JSON.stringify(user));
        },
        getVerification: function() {
            return {
                sessionId: sessionStorage.getItem(VERIFICATION_SESSION_KEY),
                verificationToken: sessionStorage.getItem(VERIFICATION_TOKEN_KEY),
                user: getUser()
            };
        }
    };
})();
