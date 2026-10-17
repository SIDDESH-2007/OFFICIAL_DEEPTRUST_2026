/**
 * ============================================================
 * dashboard_guard.js — Auth Guard for Your Existing Dashboard
 * ============================================================
 * HOW TO USE:
 *   Add these two lines to the <head> of your dashboard.html,
 *   BEFORE any other scripts:
 *
 *     <script src="js/session.js"></script>
 *     <script src="js/dashboard_guard.js"></script>
 *
 * That's it! This file will:
 *   1. Check if a valid session (JWT) exists.
 *   2. Redirect unauthenticated users to login.html immediately.
 *   3. Expose a logout() helper for your dashboard's logout button.
 *   4. Optionally show the logged-in username in your dashboard UI.
 *
 * Your existing dashboard UI is completely unchanged.
 * ============================================================
 */

// ── Immediate auth check ──────────────────────────────────────
// This runs synchronously so the dashboard never renders for
// unauthenticated users — they are redirected before seeing anything.

Session.requireAuth('/login.html'); // <-- change path if needed

// ── After DOM loads, apply user info and setup logout ─────────
document.addEventListener('DOMContentLoaded', () => {

  // 1. Show the logged-in user's name (if your dashboard has an element for it)
  //    Add  id="admin-username"  anywhere in dashboard.html to use this.
  const usernameEl = document.getElementById('admin-username');
  if (usernameEl) {
    const user = Session.getUser();
    usernameEl.textContent = user?.username || user?.id || 'Admin';
  }

  // 2. Wire up any logout buttons in your dashboard.
  //    Add  id="logout-btn"  to your logout button in dashboard.html.
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      Session.logout('/login.html');
    });
  }

  // 3. Refresh session activity on meaningful user interactions.
  //    This resets the 30-minute inactivity timer.
  ['click', 'keypress', 'scroll'].forEach(event => {
    document.addEventListener(event, () => {
      Session.refreshActivity();
    }, { passive: true });
  });

  console.log('[DashboardGuard] ✅ Authenticated session confirmed.');
  console.log('[DashboardGuard] User:', Session.getUser());

});
