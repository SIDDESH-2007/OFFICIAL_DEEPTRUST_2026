/**
 * dashboardGuard.js
 * Dashboard route protection, profile synchronization, and secure logout handler.
 *
 * Security Lifecycle:
 * 1. Checks for FINAL ACCESS TOKEN (dt_admin_token).
 * 2. Validates session with GET /api/v1/auth/me.
 * 3. Restores user profile, organization context, and role capabilities.
 * 4. Refreshes activity and handles proactive session termination.
 */

import {
    getSessionToken,
    clearSession,
    refreshSessionActivity,
    onAuthEvent
} from './session.js?v=20261006-security1';

const redirectToLogin = () => {
    window.location.replace('login.html');
};

const updateDashboardUserUI = (user, organization) => {
    if (!user) return;

    const userNameEl = document.getElementById('userName');
    const userRoleEl = document.getElementById('userRole');
    const userAvatarEl = document.getElementById('userAvatar');

    if (userNameEl) {
        userNameEl.textContent = user.full_name || 'Administrator';
    }

    if (userRoleEl) {
        if (user.role === 'DEEPTRUST_OWNER') {
            userRoleEl.textContent = 'Platform Owner';
        } else {
            userRoleEl.textContent = 'DeepTrust Security Admin';
        }
    }

    if (userAvatarEl && user.full_name) {
        const initials = user.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
        userAvatarEl.src = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='48' height='48'%3E%3Crect width='100%25' height='100%25' fill='%231e3a8a'/%3E%3Ctext x='50%25' y='56%25' font-size='16' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='bold'%3E${initials}%3C/text%3E%3C/svg%3E`;
    }
};

const enforceDashboardAccess = async () => {
    const token = getSessionToken();
    if (!token) {
        console.warn('[Dashboard Guard] No active access token found. Redirecting to login.');
        redirectToLogin();
        return false;
    }

    try {
        const res = await fetch('/api/v1/auth/me', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (res.status === 401) {
            console.warn('[Dashboard Guard] Session token is invalid or expired.');
            clearSession('expired');
            redirectToLogin();
            return false;
        }

        if (res.ok) {
            const data = await res.json();
            if (data.user) {
                updateDashboardUserUI(data.user, data.organization);
            }
            // Show the dashboard now that auth is verified
            document.documentElement.style.visibility = '';
            document.documentElement.style.opacity = '1';
        }
    } catch (err) {
        // Network timeout / offline check: Keep local session active
        console.warn('[Dashboard Guard] Offline or local mode active. Preserving session.');
        document.documentElement.style.visibility = '';
        document.documentElement.style.opacity = '1';
    }

    return true;
};

const bindLogoutButton = () => {
    const logoutBtn = document.getElementById('logoutBtn');
    if (!logoutBtn) return;

    logoutBtn.addEventListener('click', async () => {
        const token = getSessionToken();
        try {
            if (token) {
                await fetch('/api/v1/auth/logout', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            }
        } catch (e) {}

        clearSession('manual-logout');
        redirectToLogin();
    });
};

const bindActivityRefresh = () => {
    ['click', 'keypress', 'mousemove', 'scroll'].forEach((eventName) => {
        document.addEventListener(eventName, () => {
            refreshSessionActivity();
        }, { passive: true });
    });
};

// Initialize Dashboard Guard
(async () => {
    const isAllowed = await enforceDashboardAccess();
    if (isAllowed) {
        bindLogoutButton();
        bindActivityRefresh();
    }
})();

onAuthEvent('auth:logout', () => {
    redirectToLogin();
});
