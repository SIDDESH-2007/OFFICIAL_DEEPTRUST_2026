import { initAuditIntegrity } from "./auditIntegrity.js?v=20261006-security1";
import { initDashboardFeatures } from './dashboardFeatures.js?v=20261007-dashboard-fix1';
/**
 * dashboard.js
 * DeepTrust Enterprise Healthcare Security Dashboard Controller
 * =============================================================
 * - Complete Role-Conditional Architecture for Healthcare Organization & DeepTrust Admin Console
 * - 100% Real MongoDB Telemetry & Verification Pipelines
 * - Deterministic Risk Analysis, Threat Investigation & AI Security Copilot
 * - Direct URL hash routing, persistent session, zero blank pages
 */

import { getSessionToken, clearSession, getAuthorizationHeader } from './session.js?v=20261006-security1';
import { startSessionMonitor } from './sessionMonitor.js?v=20261008-interaction3';

let currentUser = null;
let currentRole = 'HOSPITAL_ADMIN';
let activeViewId = 'org-overview';
let activeEventId = null;

// Helper: Escape HTML to avoid XSS
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ── 1. AUTHENTICATION & PROFILE RESTORATION ────────────────────────────────
async function initDashboardAuth() {
    const token = getSessionToken();
    if (!token) {
        console.warn('[DeepTrust Dashboard] No active session token. Redirecting to login.');
        window.location.replace('login.html');
        return false;
    }

    try {
        const response = await fetch('/api/v1/auth/me', {
            headers: getAuthorizationHeader()
        });

        if (!response.ok) {
            console.warn('[DeepTrust Dashboard] Session verification failed. Redirecting to login.');
            clearSession();
            window.location.replace('login.html');
            return false;
        }

        const data = await response.json();
        currentUser = data.user || data;
        currentRole = currentUser.role || 'HOSPITAL_ADMIN';

        setupRoleContext();
        syncUserProfileUI();
        
        // Show dashboard shell now that auth is verified
        document.documentElement.style.visibility = '';
        document.documentElement.style.opacity = '1';
        return true;
    } catch (err) {
        console.error('[DeepTrust Dashboard] Profile fetch error:', err);
        // Show shell even on offline errors so user isn't stuck with white screen
        document.documentElement.style.visibility = '';
        document.documentElement.style.opacity = '1';
        return false;
    }
}

function setupRoleContext() {
    const orgNav = document.getElementById('orgNav');
    const deeptrustAdminNav = document.getElementById('deeptrustAdminNav');
    const portalContextLabel = document.getElementById('portalContextLabel');
    const breadcrumbOrg = document.getElementById('breadcrumbOrg');

    // Extract initial hash if available
    const hash = (window.location.hash || '').replace('#', '').trim();

    // Always enforce Platform Console regardless of role
    if (orgNav) orgNav.style.display = 'none';
    if (deeptrustAdminNav) deeptrustAdminNav.style.display = 'flex';
    if (portalContextLabel) portalContextLabel.textContent = 'SECURITY CONSOLE';
    if (breadcrumbOrg) breadcrumbOrg.textContent = 'DeepTrust Platform';

    const validAdminViews = [
        'admin-overview', 'admin-accounts', 'admin-organizations', 'admin-identity-sec',
        'admin-session-control', 'admin-threat-investigation', 'admin-risk-engine', 'admin-copilot',
        'admin-reports', 'admin-system-health', 'admin-audit-logs', 'admin-integrations',
        'admin-settings', 'admin-profile', 'admin-security'
    ];
    const targetView = validAdminViews.includes(hash) ? hash : 'admin-overview';
    switchView(targetView);
}

function syncUserProfileUI() {
    if (!currentUser) return;

    const firstName = (currentUser.full_name || 'Admin').split(' ')[0];
    const hour = new Date().getHours();
    const greetingPrefix = hour < 12 ? 'Good Morning' : hour < 18 ? 'Good Afternoon' : 'Good Evening';

    // Topbar Profile
    const topbarName = document.getElementById('topbarUserName');
    const topbarRole = document.getElementById('topbarUserRole');
    const topbarAvatar = document.getElementById('userAvatarText');

    if (topbarName) topbarName.textContent = currentUser.full_name || 'Rachel Vance';
    if (topbarRole) {
        topbarRole.textContent = (currentRole === 'DEEPTRUST_OWNER' || currentRole === 'DEEPTRUST_ADMIN')
            ? 'Platform Security Architect'
            : (currentUser.display_role || 'Hospital Security Admin');
    }
    if (topbarAvatar && currentUser.full_name) {
        const initials = currentUser.full_name
            .split(' ')
            .map(n => n[0])
            .join('')
            .substring(0, 2)
            .toUpperCase();
        topbarAvatar.textContent = initials;
    }

    // Dynamic Header Greetings
    const orgGreeting = document.getElementById('orgGreeting');
    if (orgGreeting) {
        orgGreeting.textContent = `${greetingPrefix}, ${firstName}`;
    }

    const adminGreeting = document.getElementById('adminGreeting');
    if (adminGreeting) {
        adminGreeting.textContent = `DeepTrust Security Console — ${greetingPrefix}, ${firstName}`;
    }
}

// ── 2. VIEW SWITCHING & URL HASH ROUTING ────────────────────────────────────
let pendingViewLoad = 0;

function switchView(viewId) {
    const nextSection = viewId && document.getElementById(`view-${viewId}`);
    if (!nextSection) return;
    if (activeViewId === viewId && nextSection.classList.contains('active')) return;
    activeViewId = viewId;
    document.dispatchEvent(new CustomEvent('deeptrust:view', {detail:viewId}));
    trackSecurityViewActivity(viewId);

    if (window.location.hash !== `#${viewId}`) {
        history.replaceState(null, '', `#${viewId}`);
    }

    document.querySelectorAll('.view-section.active').forEach(section => {
        if (section !== nextSection) section.classList.remove('active', 'section-enter', 'section-leave', 'section-active');
    });
    nextSection.classList.remove('section-enter', 'section-leave');
    nextSection.classList.add('active', 'section-content', 'section-active');

    const nextNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);
    document.querySelectorAll('.nav-item.active').forEach(item => {
        if (item !== nextNav) item.classList.remove('active');
    });
    if (nextNav) nextNav.classList.add('active');

    const breadcrumbSection = document.getElementById('breadcrumbSection');
    const navLabel = nextNav?.querySelector('span');
    if (breadcrumbSection && navLabel) breadcrumbSection.textContent = navLabel.textContent;

    // Keep navigation responsive even if telemetry and charts take time.
    if (pendingViewLoad) cancelAnimationFrame(pendingViewLoad);
    pendingViewLoad = requestAnimationFrame(() => {
        pendingViewLoad = requestAnimationFrame(() => {
            pendingViewLoad = 0;
            if (activeViewId !== viewId) return;
            try {
                loadViewData(viewId);
            } catch (err) {
                console.error(`[DeepTrust Navigation] Error rendering view ${viewId}:`, err);
            }
        });
    });
}

function loadViewData(viewId) {
    switch (viewId) {
        // Healthcare Organization Views
        case 'org-overview':
            loadHealthcareOverview();
            break;
        case 'org-identities':
            loadIdentities();
            break;
        case 'org-auth-activity':
            loadFullAuthActivity();
            break;
        case 'org-alerts':
            loadSecurityAlerts();
            break;
        case 'org-access-requests':
            loadAccessRequests();
            break;
        case 'org-reports':
            loadReports('today');
            break;
        case 'org-audit':
            loadAuditTrail('auditTrailTable');
            break;
        case 'org-settings':
            // Static settings forms
            break;

        // DeepTrust Admin Console Views
        case 'admin-overview':
            loadAdminOverview();
            break;
        case 'admin-accounts':
            loadAdminAccounts();
            break;
        case 'admin-organizations':
            loadAdminOrganizations();
            break;
        case 'admin-identity-sec':
            loadAdminIdentitySecurity();
            break;
        case 'admin-session-control':
            loadAdminSessionControl();
            break;
        case 'admin-threat-investigation':
            loadAdminThreatInvestigation('ALL');
            break;
        case 'admin-risk-engine':
            loadAdminRiskEngine();
            break;
        case 'admin-copilot':
            // Ready for query input
            break;
        case 'admin-reports':
            loadAdminReports();
            break;
        case 'admin-system-health':
            loadAdminSystemHealth();
            break;
        case 'admin-audit-logs':
            loadAdminAuditLogs(document.getElementById('auditIdentitySearchInput')?.value.trim() || '');
            break;
        case 'admin-integrations':
            loadAdminIntegrations();
            break;
        case 'admin-settings':
            // Platform settings
            break;
        case 'admin-profile':
            loadAdminProfile();
            break;
        case 'admin-security':
            loadAdminSecurity();
            break;
        default:
            console.warn(`[DeepTrust Dashboard] Unknown view requested: ${viewId}`);
            break;
    }
}

// ── 3. HEALTHCARE OVERVIEW TELEMETRY ─────────────────────────────────────────
async function loadHealthcareOverview() {
    try {
        const sumRes = await fetch('/api/v1/dashboard/summary', { headers: getAuthorizationHeader() });
        if (sumRes.ok) {
            const sumData = await sumRes.json();
            const totalAuthEl = document.getElementById('kpiTotalAuth');
            const verifiedEl = document.getElementById('kpiVerifiedAccess');
            const blockedEl = document.getElementById('kpiBlockedAttempts');
            const openAlertsEl = document.getElementById('kpiOpenAlerts');
            const highRiskEl = document.getElementById('kpiHighRiskSessions');

            if (totalAuthEl) totalAuthEl.textContent = sumData.total_authentications || 0;
            if (verifiedEl) verifiedEl.textContent = sumData.verified_access || 0;
            if (blockedEl) blockedEl.textContent = sumData.blocked_attempts || 0;
            if (openAlertsEl) openAlertsEl.textContent = sumData.open_alerts || 0;
            if (highRiskEl) highRiskEl.textContent = sumData.high_risk_sessions || 0;

            const sidebarAlertBadge = document.getElementById('orgSidebarAlertBadge');
            if (sidebarAlertBadge) {
                if (sumData.open_alerts > 0) {
                    sidebarAlertBadge.style.display = 'inline-block';
                    sidebarAlertBadge.textContent = sumData.open_alerts;
                } else {
                    sidebarAlertBadge.style.display = 'none';
                }
            }
        }

        loadAuthenticationTrend('24h');
        loadRiskOverview();
        loadRecentActivity();
        loadFactorHealth();
        loadNovaCareAggregateCounts();
        loadNovaCareSecurityActivity();
    } catch (err) {
        console.error('[Healthcare Overview] Telemetry fetch error:', err);
    }
}

async function loadAuthenticationTrend(range = '24h') {
    const container = document.getElementById('trendBarsArea');
    if (!container) return;

    try {
        const res = await fetch(`/api/v1/dashboard/authentication-trend?range=${range}`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const trend = data.trend || [];

            let maxVal = 1;
            trend.forEach(t => {
                const total = (t.verified || 0) + (t.failed || 0) + (t.blocked || 0);
                if (total > maxVal) maxVal = total;
            });

            container.innerHTML = trend.map(t => {
                const v = t.verified || 0;
                const f = t.failed || 0;
                const b = t.blocked || 0;
                const total = v + f + b;
                const totalHeightPct = Math.max(14, Math.round((total / maxVal) * 100));

                const vPct = total > 0 ? Math.round((v / total) * 100) : 100;
                const fPct = total > 0 ? Math.round((f / total) * 100) : 0;
                const bPct = total > 0 ? Math.round((b / total) * 100) : 0;

                return `
                    <div class="trend-bar-group">
                        <div class="bar-stack" style="height: ${totalHeightPct}%;">
                            ${b > 0 ? `<div class="bar-segment blocked" style="height: ${bPct}%;"></div>` : ''}
                            ${f > 0 ? `<div class="bar-segment failed" style="height: ${fPct}%;"></div>` : ''}
                            <div class="bar-segment verified" style="height: ${vPct}%;"></div>
                        </div>
                        <span class="bar-label">${escapeHtml(t.time)}</span>
                    </div>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Trend Chart Error]:', e);
    }
}

async function loadRiskOverview() {
    try {
        const res = await fetch('/api/v1/dashboard/risk-overview', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const d = data.distribution || { low: 1, medium: 0, high: 0, critical: 0 };

            const countLow = document.getElementById('riskCountLow');
            const countMed = document.getElementById('riskCountMed');
            const countHigh = document.getElementById('riskCountHigh');
            const countCrit = document.getElementById('riskCountCrit');

            if (countLow) countLow.textContent = d.low;
            if (countMed) countMed.textContent = d.medium;
            if (countHigh) countHigh.textContent = d.high;
            if (countCrit) countCrit.textContent = d.critical;

            const total = d.low + d.medium + d.high + d.critical;
            const bar = document.getElementById('riskBarSegments');
            if (bar && total > 0) {
                bar.innerHTML = `
                    <div class="risk-level-segment low" style="width: ${(d.low / total) * 100}%;"></div>
                    <div class="risk-level-segment medium" style="width: ${(d.medium / total) * 100}%;"></div>
                    <div class="risk-level-segment high" style="width: ${(d.high / total) * 100}%;"></div>
                    <div class="risk-level-segment critical" style="width: ${(d.critical / total) * 100}%;"></div>
                `;
            }
        }
    } catch (e) {
        console.warn('[Risk Overview Error]:', e);
    }
}

async function loadRecentActivity() {
    const tableBody = document.querySelector('#recentActivityTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/dashboard/recent-activity?limit=6', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const activities = data.activity || [];

            if (activities.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No recent authentication events recorded.</td></tr>`;
                return;
            }

            tableBody.innerHTML = activities.map(act => {
                const timeStr = act.timestamp ? new Date(act.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recent';
                const f = act.factors || {};
                const isAllow = act.decision === 'ALLOWED' || act.decision === 'ALLOW';

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
                        <td>
                            <strong>${escapeHtml(act.identity || 'Workforce Identity')}</strong>
                        </td>
                        <td style="color: var(--text-secondary);">${escapeHtml(act.role || 'Hospital Staff')}</td>
                        <td>
                            <div class="factor-check-list">
                                <span class="factor-tag ${f.credentials ? 'pass' : 'fail'}">Cred ${f.credentials ? '✓' : '✗'}</span>
                                <span class="factor-tag ${f.face ? 'pass' : 'fail'}">Face ${f.face ? '✓' : '✗'}</span>
                                <span class="factor-tag ${f.liveness ? 'pass' : 'fail'}">Live ${f.liveness ? '✓' : '✗'}</span>
                                <span class="factor-tag ${f.voice ? 'pass' : 'fail'}">Voice ${f.voice ? '✓' : '✗'}</span>
                                <span class="factor-tag ${f.mfa ? 'pass' : 'fail'}">MFA ${f.mfa ? '✓' : '✗'}</span>
                            </div>
                        </td>
                        <td>
                            <span class="status-pill ${act.risk === 'HIGH' || act.risk === 'CRITICAL' ? 'high' : 'low'}">
                                ${escapeHtml(act.risk || 'LOW')}
                            </span>
                        </td>
                        <td>
                            <span class="status-pill ${isAllow ? 'low' : 'high'}">
                                ${isAllow ? 'ALLOW' : 'BLOCK'}
                            </span>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Recent Activity Error]:', e);
    }
}

async function loadFactorHealth() {
    const grid = document.getElementById('factorHealthGrid');
    if (!grid) return;

    try {
        const res = await fetch('/api/v1/dashboard/factor-health', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const layers = data.layers || [];

            grid.innerHTML = layers.map(l => `
                <div class="factor-health-item">
                    <div class="factor-info-left">
                        <span class="status-dot ${l.status === 'Operational' ? 'pulsing' : ''}" style="${l.status !== 'Operational' ? 'background-color: var(--warning-amber);' : ''}"></span>
                        <div>
                            <div style="font-size: 0.85rem; font-weight: 600; color: #fff;">${escapeHtml(l.name)}</div>
                            <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(l.detail)}</div>
                        </div>
                    </div>
                    <span class="factor-status-badge ${l.status === 'Operational' ? '' : 'degraded'}">${escapeHtml(l.status)}</span>
                </div>
            `).join('');
        }
    } catch (e) {
        console.warn('[Factor Health Error]:', e);
    }
}

// ── 4. HEALTHCARE IDENTITIES VIEW ────────────────────────────────────────────
async function loadIdentities(search = '', role = 'ALL') {
    const tableBody = document.querySelector('#identitiesTable tbody');
    if (!tableBody) return;

    try {
        let url = '/api/v1/identities';
        const params = new URLSearchParams();
        if (search) params.append('search', search);
        if (role && role !== 'ALL') params.append('role', role);
        if (params.toString()) url += `?${params.toString()}`;

        const res = await fetch(url, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const identities = data.identities || [];

            if (identities.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 32px;">No matching clinical workforce identities found.</td></tr>`;
                return;
            }

            tableBody.innerHTML = identities.map(u => {
                const lastAuthStr = u.last_auth ? new Date(u.last_auth * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Never';
                return `
                    <tr>
                        <td><strong>${escapeHtml(u.name)}</strong></td>
                        <td style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(u.email)}</td>
                        <td><span class="status-pill low">${escapeHtml(u.display_role || u.role)}</span></td>
                        <td>${escapeHtml(u.department || 'Healthcare')}</td>
                        <td><span class="status-pill ${u.face_enrolled ? 'low' : 'pending'}">${u.face_enrolled ? 'Enrolled ✓' : 'Pending'}</span></td>
                        <td><span class="status-pill ${u.voice_enrolled ? 'low' : 'pending'}">${u.voice_enrolled ? 'Enrolled ✓' : 'Pending'}</span></td>
                        <td><span class="status-pill ${u.mfa_enabled ? 'low' : 'pending'}">${u.mfa_enabled ? 'Enabled ✓' : 'Disabled'}</span></td>
                        <td><span class="status-pill ${u.status === 'ACTIVE' ? 'low' : 'high'}">${escapeHtml(u.status || 'ACTIVE')}</span></td>
                        <td style="color: var(--text-muted); font-size: 0.8rem;">${lastAuthStr}</td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Identities Fetch Error]:', e);
    }
}

// ── 5. AUTHENTICATION ACTIVITY VIEW ────────────────────────────────────────
async function loadFullAuthActivity() {
    const tableBody = document.querySelector('#fullAuthActivityTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/dashboard/recent-activity?limit=30', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const acts = data.activity || [];

            if (acts.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 32px;">No authentication records available.</td></tr>`;
                return;
            }

            tableBody.innerHTML = acts.map(a => {
                const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Recent';
                const f = a.factors || {};
                const isAllow = a.decision === 'ALLOWED' || a.decision === 'ALLOW';

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${timeStr}</td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--primary-indigo);">${escapeHtml((a.session_id || 'SES-DEMO').substring(0, 16))}</td>
                        <td><strong>${escapeHtml(a.identity)}</strong></td>
                        <td>${escapeHtml(a.role)}</td>
                        <td>
                            <div class="factor-check-list">
                                <span class="factor-tag ${f.credentials ? 'pass' : 'fail'}">Pass</span>
                                <span class="factor-tag ${f.face ? 'pass' : 'fail'}">Face</span>
                                <span class="factor-tag ${f.voice ? 'pass' : 'fail'}">Voice</span>
                                <span class="factor-tag ${f.mfa ? 'pass' : 'fail'}">MFA</span>
                            </div>
                        </td>
                        <td><span class="status-pill ${a.risk === 'HIGH' || a.risk === 'CRITICAL' ? 'high' : 'low'}">${escapeHtml(a.risk || 'LOW')}</span></td>
                        <td><span class="status-pill ${isAllow ? 'low' : 'high'}">${isAllow ? 'ALLOW' : 'BLOCK'}</span></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Full Activity Fetch Error]:', e);
    }
}

// ── 6. SECURITY ALERTS VIEW ────────────────────────────────────────────────
async function loadSecurityAlerts(severity = 'ALL') {
    const tableBody = document.querySelector('#alertsTable tbody');
    if (!tableBody) return;

    try {
        let url = '/api/v1/security-events';
        if (severity && severity !== 'ALL') url += `?severity=${severity}`;

        const res = await fetch(url, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const events = data.events || [];

            if (events.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 32px;">No open security alerts matching criteria.</td></tr>`;
                return;
            }

            tableBody.innerHTML = events.map(evt => {
                const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recent';
                const sevClass = evt.severity === 'CRITICAL' || evt.severity === 'HIGH' ? 'high' : evt.severity === 'MEDIUM' ? 'medium' : 'low';
                const statusClass = evt.status === 'RESOLVED' ? 'low' : evt.status === 'ACKNOWLEDGED' ? 'medium' : 'high';

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
                        <td><strong>${escapeHtml(evt.identity || 'Unknown Actor')}</strong></td>
                        <td>${escapeHtml(evt.event_type || 'Security Anomaly')}</td>
                        <td>${escapeHtml(evt.factor || 'Multi-Factor')}</td>
                        <td><span class="status-pill ${sevClass}">${escapeHtml(evt.severity || 'HIGH')}</span></td>
                        <td><span class="status-pill ${statusClass}">${escapeHtml(evt.status || 'OPEN')}</span></td>
                        <td>
                            <button class="btn btn-secondary btn-sm" onclick="window.inspectEvent('${escapeHtml(evt.event_id)}')">Investigate</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Alerts Fetch Error]:', e);
    }
}

// ── 7. PRIVILEGED ACCESS REQUESTS ──────────────────────────────────────────
async function loadAccessRequests() {
    const tableBody = document.querySelector('#accessRequestsTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/access-requests', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const reqs = data.requests || [];

            if (reqs.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">No pending privileged access requests.</td></tr>`;
                return;
            }

            tableBody.innerHTML = reqs.map(r => {
                const timeStr = r.created_at ? new Date(r.created_at * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Recent';
                const isPending = r.status === 'PENDING';

                return `
                    <tr>
                        <td><strong>${escapeHtml(r.identity_name || r.user_id)}</strong></td>
                        <td>${escapeHtml(r.role || 'Clinician')}</td>
                        <td><span style="font-weight: 600; color: #fff;">${escapeHtml(r.target_resource)}</span></td>
                        <td style="color: var(--text-secondary); max-width: 220px; font-size: 0.8rem;">${escapeHtml(r.justification)}</td>
                        <td style="color: var(--text-muted); font-size: 0.8rem;">${timeStr}</td>
                        <td><span class="status-pill ${r.status === 'APPROVED' ? 'low' : r.status === 'DENIED' ? 'high' : 'pending'}">${escapeHtml(r.status)}</span></td>
                        <td>
                            ${isPending ? `
                                <div style="display: flex; gap: 6px;">
                                    <button class="btn btn-success btn-sm" onclick="window.decideAccess('${escapeHtml(r.request_id)}', 'APPROVED')">Approve</button>
                                    <button class="btn btn-secondary btn-sm" onclick="window.decideAccess('${escapeHtml(r.request_id)}', 'DENIED')">Deny</button>
                                </div>
                            ` : `<span style="font-size: 0.75rem; color: var(--text-muted);">Decided by ${escapeHtml(r.decided_by || 'Admin')}</span>`}
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Access Requests Error]:', e);
    }
}

// ── 8. COMPLIANCE & SECURITY REPORTS ───────────────────────────────────────
async function loadReports(range = 'today') {
    const grid = document.getElementById('reportMetricsGrid') || document.getElementById('reportsKpiGrid');
    if (!grid) return;

    try {
        const res = await fetch(`/api/v1/reports/summary?range=${range}`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const m = data.metrics || {};

            grid.innerHTML = `
                <div class="kpi-card">
                    <span class="kpi-title">Total Auth Attempts</span>
                    <div class="kpi-value">${m.total_attempts || 0}</div>
                    <div class="kpi-footer"><span>Zero-trust evaluated</span></div>
                </div>
                <div class="kpi-card">
                    <span class="kpi-title">Allowed Sessions</span>
                    <div class="kpi-value" style="color: var(--success-emerald);">${m.allowed_sessions || 0}</div>
                    <div class="kpi-footer"><span>Policy compliant</span></div>
                </div>
                <div class="kpi-card">
                    <span class="kpi-title">Blocked Attacks</span>
                    <div class="kpi-value" style="color: var(--danger-red);">${m.blocked_attempts || 0}</div>
                    <div class="kpi-footer"><span>Zero-trust blocked</span></div>
                </div>
                <div class="kpi-card">
                    <span class="kpi-title">Biometric Verifications</span>
                    <div class="kpi-value" style="color: var(--accent-cyan);">${(m.face_verifications || 0) + (m.voice_verifications || 0)}</div>
                    <div class="kpi-footer"><span>Face + Voice Neural</span></div>
                </div>
            `;
        }
    } catch (e) {
        console.warn('[Reports Fetch Error]:', e);
    }
}

// ── 9. AUDIT TRAIL VIEW ────────────────────────────────────────────────────
async function loadAuditTrail(targetTableId = 'auditTrailTable') {
    const tableBody = document.querySelector(`#${targetTableId} tbody`);
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/audit-logs?limit=50', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const logs = data.logs || [];

            if (logs.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 32px;">No audit logs found.</td></tr>`;
                return;
            }

            tableBody.innerHTML = logs.map(l => {
                const timeStr = l.timestamp ? new Date(l.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recent';
                const riskClass = l.risk === 'HIGH' ? 'high' : l.risk === 'MEDIUM' ? 'medium' : 'low';

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${timeStr}</td>
                        <td><strong>${escapeHtml(l.actor || l.email || l.user_id || 'System')}</strong></td>
                        <td>${escapeHtml(l.action || l.event_type)}</td>
                        <td style="color: var(--text-secondary);">${escapeHtml(l.target || l.identity || 'Workstation')}</td>
                        <td><span style="font-size: 0.8rem; color: #fff;">${escapeHtml(l.organization_name || 'NovaCare Medical Center')}</span></td>
                        <td><span class="status-pill ${riskClass}">${escapeHtml(l.result || l.risk || 'SUCCESS')}</span></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Audit Trail Error]:', e);
    }
}

// ── 10. NOTIFICATION CENTER ────────────────────────────────────────────────
let notificationSyncBusy = false;
let notificationsInitialized = false;
const seenLoginNotifications = new Set();
const notificationPageOpenedAt = Date.now() / 1000;
function showStaffLoginPopup(notification) {
    let host = document.getElementById('staff-login-popups');
    if (!host) {
        host = document.createElement('div'); host.id = 'staff-login-popups';
        host.setAttribute('aria-label', 'New hospital sign-ins');
        document.body.appendChild(host);
    }
    while (host.children.length >= 3) host.firstElementChild.remove();
    const popup = document.createElement('div'); popup.className = 'detail-box dt-staff-login-toast';
    popup.setAttribute('role', 'status');
    popup.setAttribute('aria-live', 'polite');
    popup.setAttribute('aria-atomic', 'true');
    const label = document.createElement('span'); label.className = 'dt-login-toast-label';
    label.textContent = 'Successful staff sign-in';
    const title = document.createElement('strong');
    title.textContent = notification.title || 'New hospital login';
    const message = document.createElement('p'); message.textContent = notification.message || '';
    const when = document.createElement('small');
    const timestamp = new Date(notification.timestamp || Number(notification.created_at) * 1000);
    when.textContent = Number.isFinite(timestamp.getTime()) ? timestamp.toLocaleString() : 'Just received';
    const close = document.createElement('button'); close.type = 'button';
    close.className = 'dt-login-toast-dismiss'; close.textContent = 'Dismiss';
    close.setAttribute('aria-label', 'Dismiss hospital login notification');
    let expiry;
    const pause = () => clearTimeout(expiry);
    const remove = () => { pause(); popup.remove(); };
    const resume = () => { pause(); expiry = setTimeout(remove, 12000); };
    close.addEventListener('click', remove);
    popup.addEventListener('mouseenter', pause);
    popup.addEventListener('mouseleave', resume);
    popup.addEventListener('focusin', pause);
    popup.addEventListener('focusout', resume);
    popup.append(label, title, message, when, close); host.appendChild(popup);
    resume();
}
async function syncNotifications() {
    if (notificationSyncBusy || document.hidden) return;
    notificationSyncBusy = true;
    try {
        const response = await fetch('/api/v1/notifications', {headers:getAuthorizationHeader()});
        if (!response.ok) return;
        const data = await response.json();
        const notifs = data.notifications || [];
        const count = data.unread_count || 0;
        const badge = document.getElementById('unreadNotifCount');
        if (badge) { badge.style.display = count ? 'inline-block' : 'none'; badge.textContent = count; }
        for (const n of [...notifs].reverse()) {
            const id = n.notification_id || n._id;
            if (n.type === 'HOSPITAL_STAFF_LOGIN' && !seenLoginNotifications.has(id)) {
                const created = Number(n.created_at);
                const justSignedIn = Number.isFinite(created) && created >= notificationPageOpenedAt - 15 && created <= Date.now() / 1000;
                if (!n.read && (notificationsInitialized || justSignedIn)) showStaffLoginPopup(n);
                seenLoginNotifications.add(id);
            }
        }
        notificationsInitialized = true;
        const body = document.getElementById('notifListBody');
        if (body) {
            const markup = notifs.length ? notifs.map(n => `
                <div class="detail-box" style="border-left:3px solid ${n.read ? 'var(--surface-border)' : 'var(--primary-indigo)'}">
                    <strong>${escapeHtml(n.title)}</strong>
                    <small>${escapeHtml(n.timestamp ? new Date(n.timestamp).toLocaleString() : 'Recent')}</small>
                    <p>${escapeHtml(n.message || n.summary || '')}</p>
                </div>`).join('') : '<div class="empty-state">No new notifications.</div>';
            if (body.innerHTML !== markup) body.innerHTML = markup;
        }
    } catch (error) { console.warn('[Notification Sync Error]:',error); }
    finally { notificationSyncBusy = false; }
}

// ── 11. DEEPTRUST ADMIN: OVERVIEW ──────────────────────────────────────────
async function loadAdminOverview() {
    try {
        const res = await fetch('/api/v1/admin/overview', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const orgsEl = document.getElementById('adminKpiOrgs');
            const identitiesEl = document.getElementById('adminKpiIdentities');
            const todayAuthEl = document.getElementById('adminKpiTodayAuth');
            const alertsEl = document.getElementById('adminKpiAlerts');

            if (orgsEl) orgsEl.textContent = data.organizations_protected || 1;
            if (identitiesEl) identitiesEl.textContent = data.total_identities || 0;
            if (todayAuthEl) todayAuthEl.textContent = data.active_sessions || data.total_security_events || 0;
            if (alertsEl) alertsEl.textContent = data.high_risk_events || 0;

            const adminAlertBadge = document.getElementById('adminSidebarAlertBadge');
            if (adminAlertBadge) {
                if (data.high_risk_events > 0) {
                    adminAlertBadge.style.display = 'inline-block';
                    adminAlertBadge.textContent = data.high_risk_events;
                } else {
                    adminAlertBadge.style.display = 'none';
                }
            }
        }

        // Load recent security events table
        loadAdminRecentEvents();
        // Load overview health grid
        loadAdminOverviewHealthGrid();
    } catch (e) {
        console.warn('[Admin Overview Error]:', e);
    }
}

async function loadAdminRecentEvents() {
    const tableBody = document.querySelector('#adminRecentEventsTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/security-events', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const events = data.events || [];

            if (events.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No security events recorded.</td></tr>`;
                return;
            }

            tableBody.innerHTML = events.slice(0, 5).map(evt => {
                const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent';
                const isBlocked = evt.decision === 'BLOCK';
                const isDemo = evt.is_demo === true;

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
                        <td>
                            <strong>${escapeHtml(evt.identity || 'Demo Attempt')}</strong>
                            ${isDemo ? '<span class="demo-badge">DEMO</span>' : ''}
                        </td>
                        <td>${escapeHtml(evt.event_type || 'Authentication')}</td>
                        <td><span class="status-pill ${evt.severity === 'CRITICAL' || evt.severity === 'HIGH' ? 'high' : 'low'}">${escapeHtml(evt.severity || 'LOW')}</span></td>
                        <td><span class="status-pill ${isBlocked ? 'high' : 'low'}">${isBlocked ? 'BLOCKED' : 'ALLOWED'}</span></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Admin Recent Events Error]:', e);
    }
}

async function loadAdminOverviewHealthGrid() {
    const grid = document.getElementById('adminOverviewHealthGrid');
    if (!grid) return;

    try {
        const res = await fetch('/api/v1/admin/system-health', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const engines = data.engines || {};

            const items = [
                { name: 'YuNet Face Detection', status: engines.face_yunet?.status || 'Operational', detail: 'OpenCV ONNX Engine' },
                { name: 'SFace Neural Recognizer', status: engines.face_sface?.status || 'Operational', detail: '128-d Cosine Metric' },
                { name: 'Active Temporal Liveness', status: engines.active_liveness?.status || 'Operational', detail: 'Landmark Anti-Spoof' },
                { name: 'Voice Biometrics', status: engines.voice_biometrics?.status || 'Operational', detail: 'Acoustic Frequency Match' },
                { name: 'Authenticator MFA', status: engines.authenticator_mfa?.status || 'Operational', detail: 'RFC 6238 TOTP Engine' },
                { name: 'Zero-Trust Risk Engine', status: engines.zero_trust_risk?.status || 'Operational', detail: 'Deterministic Policy' }
            ];

            grid.innerHTML = items.map(it => `
                <div class="factor-health-item">
                    <div class="factor-info-left">
                        <span class="status-dot ${it.status === 'Operational' ? 'pulsing' : ''}" style="${it.status !== 'Operational' ? 'background-color: var(--warning-amber);' : ''}"></span>
                        <div>
                            <div style="font-size: 0.82rem; font-weight: 600; color: #fff;">${escapeHtml(it.name)}</div>
                            <div style="font-size: 0.7rem; color: var(--text-muted);">${escapeHtml(it.detail)}</div>
                        </div>
                    </div>
                    <span class="factor-status-badge ${it.status === 'Operational' ? '' : 'degraded'}">${escapeHtml(it.status)}</span>
                </div>
            `).join('');
        }
    } catch (e) {
        console.warn('[Admin Overview Health Grid Error]:', e);
    }
}

// ── 12. DEEPTRUST ADMIN: ORGANIZATIONS ─────────────────────────────────────
async function loadAdminOrganizations() {
    const tableBody = document.querySelector('#adminOrgsTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/admin/organizations', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const orgs = data.organizations || [];

            if (orgs.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 32px;">No organizations found.</td></tr>`;
                return;
            }

            tableBody.innerHTML = orgs.map(org => {
                return `
                    <tr style="cursor: pointer;" onclick="window.inspectOrg('${escapeHtml(org.organization_id || org._id)}')">
                        <td><strong>${escapeHtml(org.name || 'NovaCare Medical Center')}</strong></td>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">${escapeHtml(org.domain || 'healthcare.org.internal')}</td>
                        <td>${escapeHtml(org.industry || 'Healthcare Infrastructure')}</td>
                        <td><span class="status-pill low">${escapeHtml(org.status || 'ACTIVE')}</span></td>
                        <td><span style="font-weight: 600; color: #fff;">${org.identities_count || 1}</span></td>
                        <td><span class="status-pill ${org.open_alerts_count > 0 ? 'high' : 'low'}">${org.open_alerts_count || 0}</span></td>
                        <td style="color: var(--text-muted); font-size: 0.8rem;">Active Now</td>
                        <td>
                            <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); window.inspectOrg('${escapeHtml(org.organization_id || org._id)}')">View Details</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Admin Organizations Error]:', e);
        tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load organizations. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-organizations">Retry</button></td></tr>`;
    }
}

// ── 13. DEEPTRUST ADMIN: IDENTITY SECURITY ─────────────────────────────────
async function loadAdminIdentitySecurity() {
    const tableBody = document.querySelector('#adminIdentitySecurityTable tbody');

    try {
        const res = await fetch('/api/v1/admin/identity-security', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const m = data.metrics || {};
            const identities = data.identities || [];

            const totalEl = document.getElementById('adminTotalIdentities');
            const faceEl = document.getElementById('adminFaceEnrolled');
            const voiceEl = document.getElementById('adminVoiceEnrolled');
            const mfaEl = document.getElementById('adminMfaEnabled');
            const setupEl = document.getElementById('adminRequiringSetup');

            if (totalEl) totalEl.textContent = m.total_identities || 0;
            if (faceEl) faceEl.textContent = m.face_enrolled || 0;
            if (voiceEl) voiceEl.textContent = m.voice_enrolled || 0;
            if (mfaEl) mfaEl.textContent = m.mfa_enabled || 0;
            if (setupEl) setupEl.textContent = m.requiring_setup || 0;

            if (tableBody) {
                if (identities.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 32px;">No enrolled identities found.</td></tr>`;
                    return;
                }

                tableBody.innerHTML = identities.map(u => {
                    const lastAuthStr = u.last_auth ? new Date(u.last_auth * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Never';
                    const isDemo = u.is_demo === true;

                    return `
                        <tr>
                            <td>
                                <strong>${escapeHtml(u.name)}</strong>
                                ${isDemo ? '<span class="demo-badge">DEMO</span>' : ''}
                            </td>
                            <td style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(u.email)}</td>
                            <td>${escapeHtml(u.organization_name || 'NovaCare Medical Center')}</td>
                            <td><span class="status-pill low">${escapeHtml(u.display_role || u.role)}</span></td>
                            <td><span class="status-pill ${u.face_enrolled ? 'low' : 'pending'}">${u.face_enrolled ? 'Enrolled ✓' : 'Pending'}</span></td>
                            <td><span class="status-pill ${u.voice_enrolled ? 'low' : 'pending'}">${u.voice_enrolled ? 'Enrolled ✓' : 'Pending'}</span></td>
                            <td><span class="status-pill ${u.mfa_enabled ? 'low' : 'pending'}">${u.mfa_enabled ? 'Enabled ✓' : 'Disabled'}</span></td>
                            <td><span class="status-pill ${u.status === 'ACTIVE' ? 'low' : 'high'}">${escapeHtml(u.status || 'ACTIVE')}</span></td>
                            <td style="color: var(--text-muted); font-size: 0.8rem;">${lastAuthStr}</td>
                        </tr>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        console.warn('[Admin Identity Security Error]:', e);
        if (tableBody) {
            tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load identity security telemetry. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-identity-sec">Retry</button></td></tr>`;
        }
    }
}

// ── 14. DEEPTRUST ADMIN: THREAT INVESTIGATION ──────────────────────────────
async function loadAdminThreatInvestigation(severity = 'ALL') {
    const tableBody = document.querySelector('#adminThreatsTable tbody');
    if (!tableBody) return;

    try {
        let url = '/api/v1/security-events';
        if (severity && severity !== 'ALL') url += `?severity=${severity}`;

        const res = await fetch(url, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const events = data.events || [];

            if (events.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 32px;">No threat incidents recorded.</td></tr>`;
                return;
            }

            tableBody.innerHTML = events.map(evt => {
                const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recent';
                const sevClass = evt.severity === 'CRITICAL' || evt.severity === 'HIGH' ? 'high' : evt.severity === 'MEDIUM' ? 'medium' : 'low';
                const statusClass = evt.status === 'RESOLVED' ? 'low' : evt.status === 'ACKNOWLEDGED' ? 'medium' : 'high';
                const isDemo = evt.is_demo === true;

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
                        <td>
                            <strong>${escapeHtml(evt.identity || 'Unknown Identity')}</strong>
                            ${isDemo ? '<span class="demo-badge">DEMO</span>' : ''}
                        </td>
                        <td>${escapeHtml(evt.event_type || 'Security Violation')}</td>
                        <td>${escapeHtml(evt.factor || 'Multi-Signal')}</td>
                        <td><span style="font-family: var(--font-mono); font-weight: 700; color: ${evt.risk_score > 70 ? 'var(--danger-red)' : 'var(--success-emerald)'};">${evt.risk_score || 0}/100</span></td>
                        <td><span class="status-pill ${sevClass}">${escapeHtml(evt.severity || 'HIGH')}</span></td>
                        <td><span class="status-pill ${statusClass}">${escapeHtml(evt.status || 'OPEN')}</span></td>
                        <td>
                            <button class="btn btn-secondary btn-sm" onclick="window.inspectEvent('${escapeHtml(evt.event_id)}')">Investigate</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Admin Threats Error]:', e);
        tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load threat events. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-threat-investigation">Retry</button></td></tr>`;
    }
}

// ── 15. DEEPTRUST ADMIN: RISK ENGINE ───────────────────────────────────────
async function loadAdminRiskEngine() {
    const tableBody = document.querySelector('#adminRiskTable tbody');

    try {
        const res = await fetch('/api/v1/admin/risk-evaluations', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const m = data.metrics || {};
            const evals = data.evaluations || [];

            const allowedEl = document.getElementById('riskAllowedCount');
            const stepUpEl = document.getElementById('riskStepUpCount');
            const blockedEl = document.getElementById('riskBlockedCount');

            if (allowedEl) allowedEl.textContent = m.allowed || 0;
            if (stepUpEl) stepUpEl.textContent = m.step_up || 0;
            if (blockedEl) blockedEl.textContent = m.blocked || 0;

            if (tableBody) {
                if (evals.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 32px;">No risk evaluations recorded.</td></tr>`;
                    return;
                }

                tableBody.innerHTML = evals.map(ev => {
                    const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recent';
                    const isAllow = ev.decision === 'ALLOW' || ev.decision === 'ALLOWED';
                    const isStepUp = ev.decision === 'STEP_UP';
                    const decisionClass = isAllow ? 'low' : isStepUp ? 'medium' : 'high';
                    const isDemo = ev.is_demo === true;
                    const reasons = ev.reason_codes || [];

                    return `
                        <tr>
                            <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
                            <td>
                                <strong>${escapeHtml(ev.user_id || 'Identity')}</strong>
                                ${isDemo ? '<span class="demo-badge">DEMO</span>' : ''}
                            </td>
                            <td><span style="font-family: var(--font-mono); font-weight: 700; color: ${ev.risk_score > 70 ? 'var(--danger-red)' : 'var(--success-emerald)'};">${ev.risk_score || 0}/100</span></td>
                            <td><span class="status-pill ${ev.risk_level === 'CRITICAL' || ev.risk_level === 'HIGH' ? 'high' : 'low'}">${escapeHtml(ev.risk_level || 'LOW')}</span></td>
                            <td><span class="status-pill ${decisionClass}">${escapeHtml(ev.decision || 'ALLOW')}</span></td>
                            <td>
                                <div class="factor-check-list">
                                    ${reasons.map(r => `<span class="factor-tag ${isAllow ? 'pass' : 'fail'}">${escapeHtml(r)}</span>`).join('')}
                                </div>
                            </td>
                        </tr>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        console.warn('[Admin Risk Engine Error]:', e);
        if (tableBody) {
            tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load risk evaluations. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-risk-engine">Retry</button></td></tr>`;
        }
    }
}

// ── 16. DEEPTRUST ADMIN: SYSTEM HEALTH ─────────────────────────────────────
async function loadAdminSystemHealth() {
    const grid = document.getElementById('adminSystemHealthGrid');

    try {
        const res = await fetch('/api/v1/admin/system-health', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const infra = data.infrastructure || {};
            const engines = data.engines || {};

            const isAllHealthy = infra.mongodb_database?.status === 'Operational' && infra.api_server?.status === 'Operational';

            // Update topbar health badge & sidebar indicator
            const topbarHealth = document.getElementById('topbarHealthText');
            const sidebarStatus = document.getElementById('sidebarStatusText');
            if (topbarHealth) topbarHealth.textContent = isAllHealthy ? 'System Operational' : 'System Degraded';
            if (sidebarStatus) sidebarStatus.textContent = isAllHealthy ? 'System Operational' : 'System Degraded';

            if (grid) {
                const items = [
                    { name: 'API Server Gateway', status: infra.api_server?.status || 'Unknown', detail: 'Port 8000 (FastAPI 0.110)' },
                    { name: 'MongoDB Database', status: infra.mongodb_database?.status || 'Unknown', detail: '127.0.0.1:27017 (Cluster US-East)' },
                    { name: 'YuNet Face Detection Engine', status: engines.face_yunet?.status || 'Unknown', detail: 'OpenCV ONNX Runtime' },
                    { name: 'SFace Neural Feature Recognizer', status: engines.face_sface?.status || 'Unknown', detail: '128-d Cosine Vector Space' },
                    { name: 'Passive Liveness', status: engines.active_liveness?.status || 'Unknown', detail: 'MiniFASNet anti-spoof ensemble' },
                    { name: 'Voice Acoustic Biometrics', status: engines.voice_biometrics?.status || 'Unknown', detail: engines.voice_biometrics?.mode || 'Voice readiness not checked' },
                    { name: 'Authenticator MFA (RFC 6238)', status: engines.authenticator_mfa?.status || 'Unknown', detail: engines.authenticator_mfa?.mode || 'TOTP readiness not checked' },
                    { name: 'Zero-Trust Policy Engine', status: engines.zero_trust_risk?.status || 'Unknown', detail: 'Deterministic Risk Evaluation' }
                ];

                grid.innerHTML = items.map(it => `
                    <div class="factor-health-item">
                        <div class="factor-info-left">
                            <span class="status-dot ${it.status === 'Operational' ? 'pulsing' : ''}" style="${it.status !== 'Operational' ? 'background-color: var(--warning-amber);' : ''}"></span>
                            <div>
                                <div style="font-size: 0.85rem; font-weight: 600; color: #fff;">${escapeHtml(it.name)}</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(it.detail)}</div>
                            </div>
                        </div>
                        <span class="factor-status-badge ${it.status === 'Operational' ? '' : 'degraded'}">${escapeHtml(it.status)}</span>
                    </div>
                `).join('');
            }
        }
    } catch (e) {
        console.warn('[Admin System Health Error]:', e);
    }
}

// ── 17. DEEPTRUST ADMIN: INTEGRATIONS ──────────────────────────────────────
async function loadAdminIntegrations() {
    const tableBody = document.querySelector('#adminIntegrationsTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/admin/integrations', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const integrations = data.integrations || [];

            if (integrations.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 32px;">No integrations configured.</td></tr>`;
                return;
            }

            tableBody.innerHTML = integrations.map(item => {
                const isConn = item.connected === true;
                const statusPillClass = isConn ? 'low' : item.status === 'Not Configured' ? 'pending' : 'high';

                return `
                    <tr>
                        <td><strong>${escapeHtml(item.name)}</strong></td>
                        <td><span class="status-pill low">${escapeHtml(item.type)}</span></td>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">${escapeHtml(item.endpoint)}</td>
                        <td><span class="status-pill ${statusPillClass}">${escapeHtml(item.status)}</span></td>
                        <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(item.detail)}</td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[Admin Integrations Error]:', e);
        tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load integrations. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-integrations">Retry</button></td></tr>`;
    }
}

// ── 18. AI SECURITY COPILOT QUERY HANDLER ──────────────────────────────────
async function handleCopilotQuery(queryText) {
    if (!queryText || !queryText.trim()) return;

    const chatBox = document.getElementById('copilotChatBox');
    const evidenceList = document.getElementById('copilotEvidenceList');
    const recList = document.getElementById('copilotRecList');
    const input = document.getElementById('copilotInput');

    if (input) input.value = '';

    // Append User message
    if (chatBox) {
        const userMsg = document.createElement('div');
        userMsg.className = 'copilot-message user';
        userMsg.textContent = queryText;
        chatBox.appendChild(userMsg);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    // Append Loading Indicator
    const agentMsg = document.createElement('div');
    agentMsg.className = 'copilot-message agent';
    agentMsg.innerHTML = `<div class="copilot-message-title">DeepTrust Security Copilot</div><p>Analyzing MongoDB telemetry and correlating verification signals...</p>`;
    if (chatBox) {
        chatBox.appendChild(agentMsg);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    try {
        const res = await fetch('/api/v1/ai/query', {
            method: 'POST',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query: queryText })
        });

        if (res.ok) {
            const data = await res.json();
            agentMsg.innerHTML = `
                <div class="copilot-message-title">${escapeHtml(data.title || 'Security Copilot Analysis')}</div>
                <p style="margin-bottom: 8px;">${escapeHtml(data.analysis)}</p>
                <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(data.disclaimer)}</div>
            `;

            if (evidenceList && data.evidence) {
                evidenceList.innerHTML = data.evidence.map(ev => `<div class="evidence-item">${escapeHtml(ev)}</div>`).join('');
            }

            if (recList && data.recommendations) {
                recList.innerHTML = data.recommendations.map(r => `
                    <div class="recommendation-item">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--primary-indigo); flex-shrink: 0;"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
                        <span>${escapeHtml(r)}</span>
                    </div>
                `).join('');
            }
        } else {
            agentMsg.innerHTML = `<div class="copilot-message-title">DeepTrust Security Copilot</div><p>Unable to perform telemetry analysis at this time. Please retry.</p>`;
        }
    } catch (e) {
        agentMsg.innerHTML = `<div class="copilot-message-title">DeepTrust Security Copilot</div><p>Error connecting to Security Copilot service.</p>`;
    }

    if (chatBox) chatBox.scrollTop = chatBox.scrollHeight;
}

// ── 19. RIGHT INVESTIGATION DRAWER & ACTIONS ───────────────────────────────
window.inspectEvent = async function (eventId) {
    if (!eventId) return;
    activeEventId = eventId;

    const drawer = document.getElementById('investigationDrawer');
    const backdrop = document.getElementById('drawerBackdrop');
    if (!drawer || !backdrop) return;

    drawer.classList.add('open');
    backdrop.classList.add('open');

    try {
        const res = await fetch(`/api/v1/admin/dashboard/features/alerts/${encodeURIComponent(eventId)}`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const evt = data.event || {};
            document.dispatchEvent(new CustomEvent('deeptrust:alert',{detail:evt}));

            const idEl = document.getElementById('drawerEventId');
            const sevEl = document.getElementById('drawerEventSeverity');
            const identEl = document.getElementById('drawerEventIdentity');
            const decEl = document.getElementById('drawerEventDecision');
            const descEl = document.getElementById('drawerEventDesc');
            const reasonBox = document.getElementById('drawerReasonTags');
            const timelineBox = document.getElementById('drawerAuditTimeline');

            if (idEl) idEl.textContent = evt.event_id || eventId;
            if (sevEl) sevEl.textContent = evt.severity || 'HIGH';
            if (identEl) identEl.textContent = evt.identity || 'Unknown Identity';
            if (decEl) decEl.textContent = evt.decision || 'Not recorded';
            if (descEl) descEl.textContent = evt.description || evt.event_type || 'Recorded security event';

            if (reasonBox) {
                const reasons = evt.reason_codes || [];
                reasonBox.innerHTML = reasons.map(r => `<span class="factor-tag fail">${escapeHtml(r)}</span>`).join('');
            }

            if (timelineBox) {
                const timeline = evt.audit_timeline || [];
                if (timeline.length === 0) {
                    timelineBox.innerHTML = `<div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-title">${escapeHtml(evt.event_type || 'Event Logged')}</div><div class="timeline-time">${evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'Recent'}</div></div>`;
                } else {
                    timelineBox.innerHTML = timeline.map(t => `
                        <div class="timeline-item">
                            <div class="timeline-dot"></div>
                            <div class="timeline-title">${escapeHtml(t.action || t.event_type)}</div>
                            <div class="timeline-time">${t.timestamp ? new Date(t.timestamp).toLocaleString() : 'Recent'}</div>
                        </div>
                    `).join('');
                }
            }
        }
    } catch (e) {
        console.warn('[Investigation Drawer Fetch Error]:', e);
    }
};

window.inspectOrg = async function(orgId) {
    const drawer=document.getElementById('orgDetailsDrawer'),body=document.getElementById('orgDrawerBody');
    if(!drawer || !body)return;
    drawer.classList.add('open');document.getElementById('drawerBackdrop')?.classList.add('open');body.textContent='Loading hospital details…';
    try {
        const response=await fetch('/api/v1/admin/dashboard/features/overview?organization_id='+encodeURIComponent(orgId),{headers:getAuthorizationHeader()});
        if(!response.ok)throw Error('Unable to load this hospital');
        const data=await response.json(),org=data.organizations.find(o=>o.organization_id===orgId);
        if(!org)throw Error('Hospital not found in your scope');
        document.getElementById('orgDrawerTitle').textContent=org.name;
        body.innerHTML='<div class="detail-grid">'+Object.entries({Hospital:org.name,Users:org.users,'Active sessions':org.active_sessions,'Pending accounts':org.pending_accounts,'Pending approvals':org.pending_requests,'Open alerts':org.open_alerts,...org.roles}).map(([key,value])=>'<div class="detail-box"><span class="detail-box-label">'+escapeHtml(key)+'</span><span class="detail-box-value">'+escapeHtml(String(value))+'</span></div>').join('')+'</div>';
    }catch(error){body.textContent=error.message;}
};

window.decideAccess = async function (requestId, decision) {
    try {
        const response = await fetch(`/api/v1/access-requests/${requestId}/decision`, {
            method: 'POST',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ decision })
        });
        if(!response.ok){const error=await response.json().catch(()=>({}));throw Error(error.detail || 'Approval action failed');}
        loadAccessRequests();
    } catch (e) {
        console.warn('[Decide Access Error]:', e); alert(e.message);
    }
};

function closeDrawers() {
    document.querySelectorAll('.investigation-drawer, .notification-drawer').forEach(d => d.classList.remove('open'));
    const backdrop = document.getElementById('drawerBackdrop');
    if (backdrop) backdrop.classList.remove('open');
}

// ── 20. DEEPTRUST ADMIN: ACCOUNT MANAGEMENT ────────────────────────────────
let currentPendingMfaUserId = null;
let currentRemoveAccountId = null;

function formatAccountCreatedAt(value) {
    if (value === null || value === undefined || value === '') return 'Recent';
    // The accounts API returns Unix seconds; retain compatibility with
    // millisecond timestamps and ISO dates from older account records.
    const numeric = typeof value === 'number' || /^\d+(?:\.\d+)?$/.test(String(value).trim());
    const timestamp = numeric ? Number(value) : value;
    const date = new Date(numeric && Math.abs(timestamp) < 1e12 ? timestamp * 1000 : timestamp);
    return Number.isNaN(date.getTime()) ? 'Recent' : date.toLocaleDateString([], { dateStyle: 'short' });
}

async function loadAdminAccounts() {
    const tableBody = document.querySelector('#adminAccountsTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/admin/accounts', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const accounts = data.accounts || [];

            // Update KPI cards
            const totalAccountsEl = document.getElementById('kpiTotalAccounts');
            const dtAdminsEl = document.getElementById('kpiDeeptrustAdmins');
            const hcAdminsEl = document.getElementById('kpiHealthcareAdmins');
            const activeAccEl = document.getElementById('kpiActiveAccounts');
            const disabledAccEl = document.getElementById('kpiDisabledAccounts');

            const dtCount = accounts.filter(a => a.account_type === 'DEEPTRUST_ADMIN').length;
            const hcCount = accounts.filter(a => a.account_type === 'HEALTHCARE_ADMIN').length;
            const activeCount = accounts.filter(a => a.status === 'active').length;
            const disabledCount = accounts.filter(a => a.status !== 'active').length;

            if (totalAccountsEl) totalAccountsEl.textContent = accounts.length;
            if (dtAdminsEl) dtAdminsEl.textContent = dtCount;
            if (hcAdminsEl) hcAdminsEl.textContent = hcCount;
            if (activeAccEl) activeAccEl.textContent = activeCount;
            if (disabledAccEl) disabledAccEl.textContent = disabledCount;

            if (accounts.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 32px;">No administrator accounts found.</td></tr>`;
                return;
            }

            tableBody.innerHTML = accounts.map(acc => {
                const createdStr = formatAccountCreatedAt(acc.created_at);
                const lastLoginStr = acc.last_login_at ? new Date(acc.last_login_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Never';
                const isDt = acc.account_type === 'DEEPTRUST_ADMIN';
                const isActive = acc.status === 'active';
                const isSelf = currentUser && (currentUser.id === acc.id || currentUser.email === acc.email);

                return `
                    <tr>
                        <td><strong>${escapeHtml(acc.full_name)}</strong></td>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">${escapeHtml(acc.email)}</td>
                        <td><span class="status-pill ${isDt ? 'info' : 'low'}">${isDt ? 'DeepTrust Admin' : 'Healthcare Admin'}</span></td>
                        <td>${escapeHtml(acc.organization_name || acc.organization || (isDt ? 'DeepTrust' : 'NovaCare Medical Center'))}</td>
                        <td><span class="factor-tag pass">${escapeHtml(acc.role)}</span></td>
                        <td><span class="status-pill ${acc.mfa_enabled ? 'verified' : 'pending'}">${acc.mfa_enabled ? 'Enrolled ✓' : 'Pending 2FA'}</span></td>
                        <td><span class="status-pill ${isActive ? 'active' : 'block'}">${isActive ? 'Active' : 'Disabled'}</span></td>
                        <td style="color: var(--text-muted); font-size: 0.78rem;">${lastLoginStr}</td>
                        <td style="color: var(--text-muted); font-size: 0.78rem;">${createdStr}</td>
                        <td>
                            <div style="display: flex; gap: 4px; align-items: center;">
                                ${isActive 
                                    ? `<button class="btn btn-secondary btn-sm btn-action-disable" data-id="${escapeHtml(acc.id)}" ${isSelf ? 'disabled title="Cannot disable own active account"' : ''}>Disable</button>` 
                                    : `<button class="btn btn-success btn-sm btn-action-enable" data-id="${escapeHtml(acc.id)}">Enable</button>`
                                }
                                <button class="btn btn-secondary btn-sm btn-action-reset-mfa" data-id="${escapeHtml(acc.id)}" title="Reset Google Authenticator">Reset 2FA</button>
                                <button class="btn btn-danger btn-sm btn-action-remove" data-id="${escapeHtml(acc.id)}" data-email="${escapeHtml(acc.email)}" ${isSelf ? 'disabled title="Cannot remove own active account"' : ''}>Remove</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');

            // Attach dynamic action buttons
            tableBody.querySelectorAll('.btn-action-disable').forEach(b => {
                b.addEventListener('click', (e) => {
                    e.stopPropagation();
                    handleAccountDisable(b.getAttribute('data-id'));
                });
            });
            tableBody.querySelectorAll('.btn-action-enable').forEach(b => {
                b.addEventListener('click', (e) => {
                    e.stopPropagation();
                    handleAccountEnable(b.getAttribute('data-id'));
                });
            });
            tableBody.querySelectorAll('.btn-action-reset-mfa').forEach(b => {
                b.addEventListener('click', (e) => {
                    e.stopPropagation();
                    handleAccountMfaReset(b.getAttribute('data-id'));
                });
            });
            tableBody.querySelectorAll('.btn-action-remove').forEach(b => {
                b.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openRemoveAccountModal(b.getAttribute('data-id'), b.getAttribute('data-email'));
                });
            });
        }
    } catch (e) {
        console.warn('[Admin Accounts Load Error]:', e);
        tableBody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--danger-red); padding: 32px;">Unable to load accounts. <button class="btn btn-secondary btn-sm" data-dashboard-retry="admin-accounts">Retry</button></td></tr>`;
    }
}

function openCreateAccountModal() {
    const modal = document.getElementById('createAccountModal');
    const form = document.getElementById('formCreateAccount');
    if (form) form.reset();
    resetPasswordStrengthUI('modalPassStrengthFill', 'modalPassStrengthText', 'modalPassReqs', 'mreq-');

    // Default to Healthcare Admin
    const typeSelect = document.getElementById('modalAccType');
    const orgSelect = document.getElementById('modalAccOrg');
    const roleSelect = document.getElementById('modalAccRole');
    if (typeSelect) typeSelect.value = 'HEALTHCARE_ADMIN';
    if (orgSelect) {
        orgSelect.innerHTML = `<option value="NovaCare Medical Center" selected>Healthcare Organization</option>`;
    }
    if (roleSelect) {
        roleSelect.innerHTML = `
            <option value="HOSPITAL_ADMIN" selected>Hospital Administrator</option>
            <option value="SECURITY_ANALYST">Security Analyst</option>
            <option value="ADMIN">System Administrator</option>
        `;
    }

    if (modal) modal.classList.add('open');
}

function closeCreateAccountModal() {
    const modal = document.getElementById('createAccountModal');
    if (modal) modal.classList.remove('open');
}

function resetPasswordStrengthUI(fillId, textId, reqsId, prefix) {
    const fill = document.getElementById(fillId);
    const text = document.getElementById(textId);
    if (fill) {
        fill.style.width = '0%';
        fill.style.backgroundColor = 'var(--surface-border)';
    }
    if (text) text.textContent = 'Strength: None';

    const items = ['len', 'upper', 'lower', 'num', 'sym'];
    items.forEach(k => {
        const el = document.getElementById(`${prefix}${k}`);
        if (el) el.className = 'pass-req-item invalid';
    });
}

function updatePasswordStrength(pwd, fillId, textId, prefix) {
    const fill = document.getElementById(fillId);
    const text = document.getElementById(textId);

    const hasLen = pwd.length >= 8;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNum = /[0-9]/.test(pwd);
    const hasSym = /[^A-Za-z0-9]/.test(pwd);

    const setReq = (k, valid) => {
        const el = document.getElementById(`${prefix}${k}`);
        if (el) el.className = `pass-req-item ${valid ? 'valid' : 'invalid'}`;
    };

    setReq('len', hasLen);
    setReq('upper', hasUpper);
    setReq('lower', hasLower);
    setReq('num', hasNum);
    setReq('sym', hasSym);

    let score = 0;
    if (hasLen) score++;
    if (hasUpper) score++;
    if (hasLower) score++;
    if (hasNum) score++;
    if (hasSym) score++;

    const percent = Math.min(100, score * 20);
    if (fill) {
        fill.style.width = `${percent}%`;
        if (score <= 2) fill.style.backgroundColor = 'var(--danger-red)';
        else if (score <= 4) fill.style.backgroundColor = 'var(--warning-amber)';
        else fill.style.backgroundColor = 'var(--success-emerald)';
    }

    if (text) {
        if (score <= 2) text.textContent = 'Strength: Weak';
        else if (score <= 4) text.textContent = 'Strength: Moderate';
        else text.textContent = 'Strength: Strong ✓';
    }

    return score === 5;
}

async function handleCreateAccountSubmit(e) {
    e.preventDefault();
    const fullName = document.getElementById('modalAccFullName')?.value.trim();
    const email = document.getElementById('modalAccEmail')?.value.trim().toLowerCase();
    const accountType = document.getElementById('modalAccType')?.value;
    const organization = document.getElementById('modalAccOrg')?.value;
    const role = document.getElementById('modalAccRole')?.value;
    const password = document.getElementById('modalAccPassword')?.value;
    const confirmPassword = document.getElementById('modalAccConfirmPassword')?.value;

    if (!fullName || !email || !password) {
        alert('Please complete all required fields.');
        return;
    }

    if (password !== confirmPassword) {
        alert('Passwords do not match. Please verify.');
        return;
    }

    if (!updatePasswordStrength(password, 'modalPassStrengthFill', 'modalPassStrengthText', 'mreq-')) {
        alert('Password does not satisfy all complexity requirements (8+ chars, uppercase, lowercase, number, special character).');
        return;
    }

    const submitBtn = document.getElementById('btnSubmitCreateAccount');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating Account & Generating 2FA Secret...';
    }

    try {
        const res = await fetch('/api/v1/admin/accounts', {
            method: 'POST',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                full_name: fullName,
                email: email,
                account_type: accountType,
                organization: organization,
                role: role,
                password: password
            })
        });

        const data = await res.json();

        if (res.ok && data.success) {
            closeCreateAccountModal();

            // Open QR Enrollment modal immediately
            const mfaSetup = data.mfa_setup;
            const newUser = data.user;
            currentPendingMfaUserId = newUser.id || newUser._id || email;

            const qrModal = document.getElementById('qrEnrollmentModal');
            const qrImg = document.getElementById('qrCodeImg');
            const secretDisplay = document.getElementById('qrSecretKeyDisplay');

            if (qrImg && mfaSetup.qr_base64) {
                qrImg.src = mfaSetup.qr_base64;
            }
            if (secretDisplay && mfaSetup.secret) {
                secretDisplay.textContent = mfaSetup.secret;
            }

            // Clear TOTP input boxes
            document.querySelectorAll('#enrollmentOtpContainer .totp-input-digit').forEach(b => b.value = '');

            if (qrModal) qrModal.classList.add('open');
            loadAdminAccounts();
        } else {
            alert(data.detail || 'Failed to create account. Ensure email is unique and formatted correctly.');
        }
    } catch (err) {
        console.error('Account creation error:', err);
        alert('Network error communicating with DeepTrust security backend.');
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<span>Create & Proceed to 2FA Setup</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;
        }
    }
}

async function handleConfirmTotpSubmit(e) {
    e.preventDefault();
    const boxes = document.querySelectorAll('#enrollmentOtpContainer .totp-input-digit');
    let code = '';
    boxes.forEach(b => code += b.value.trim());

    if (code.length < 6) {
        alert('Please enter all 6 digits of the authenticator code.');
        return;
    }

    const verifyBtn = document.getElementById('btnVerifyAndEnableMfa');
    if (verifyBtn) {
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Verifying TOTP Code...';
    }

    try {
        const res = await fetch('/api/v1/mfa/totp/confirm', {
            method: 'POST',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: currentPendingMfaUserId,
                totp_code: code
            })
        });

        const data = await res.json();

        if (res.ok && data.success) {
            const qrModal = document.getElementById('qrEnrollmentModal');
            if (qrModal) qrModal.classList.remove('open');
            alert('Google Authenticator 2FA verified & enabled successfully!');
            loadAdminAccounts();
            if (activeViewId === 'admin-security') {
                loadAdminSecurity();
            }
        } else {
            alert(data.detail || 'Invalid authentication code. Please enter the current code from Google Authenticator.');
        }
    } catch (err) {
        console.error('TOTP confirm error:', err);
        alert('Network error verifying authentication code.');
    } finally {
        if (verifyBtn) {
            verifyBtn.disabled = false;
            verifyBtn.innerHTML = `<span>Verify & Enable 2FA</span>`;
        }
    }
}

async function handleAccountDisable(id) {
    if (!confirm('Disable this administrator account? All active sessions will be terminated immediately.')) return;
    try {
        const res = await fetch(`/api/v1/admin/accounts/${id}/disable`, {
            method: 'POST',
            headers: getAuthorizationHeader()
        });
        if (res.ok) {
            loadAdminAccounts();
        } else {
            const data = await res.json();
            alert(data.detail || 'Failed to disable account.');
        }
    } catch (e) {
        console.warn('Disable error:', e);
    }
}

async function handleAccountEnable(id) {
    try {
        const res = await fetch(`/api/v1/admin/accounts/${id}/enable`, {
            method: 'POST',
            headers: getAuthorizationHeader()
        });
        if (res.ok) {
            loadAdminAccounts();
        } else {
            const data = await res.json();
            alert(data.detail || 'Failed to enable account.');
        }
    } catch (e) {
        console.warn('Enable error:', e);
    }
}

async function handleAccountMfaReset(id) {
    if (!confirm('Reset Google Authenticator for this account? The previous secret will be invalidated.')) return;
    try {
        const res = await fetch(`/api/v1/admin/accounts/${id}/mfa-reset`, {
            method: 'POST',
            headers: getAuthorizationHeader()
        });
        const data = await res.json();
        if (res.ok && data.success) {
            currentPendingMfaUserId = id;
            const qrModal = document.getElementById('qrEnrollmentModal');
            const qrImg = document.getElementById('qrCodeImg');
            const secretDisplay = document.getElementById('qrSecretKeyDisplay');

            if (qrImg && data.qr_base64) qrImg.src = data.qr_base64;
            if (secretDisplay && data.secret) secretDisplay.textContent = data.secret;
            document.querySelectorAll('#enrollmentOtpContainer .totp-input-digit').forEach(b => b.value = '');

            if (qrModal) qrModal.classList.add('open');
            loadAdminAccounts();
        } else {
            alert(data.detail || 'Failed to reset MFA.');
        }
    } catch (e) {
        console.warn('MFA Reset error:', e);
    }
}

function openRemoveAccountModal(id, email) {
    currentRemoveAccountId = id;
    const modal = document.getElementById('removeAccountModal');
    const emailTarget = document.getElementById('removeAccountEmailTarget');
    const confirmInput = document.getElementById('removeConfirmInput');
    const executeBtn = document.getElementById('btnExecuteRemoveAccount');

    if (emailTarget) emailTarget.textContent = email;
    if (confirmInput) confirmInput.value = '';
    if (executeBtn) executeBtn.disabled = true;

    if (modal) modal.classList.add('open');
}

function closeRemoveAccountModal() {
    const modal = document.getElementById('removeAccountModal');
    if (modal) modal.classList.remove('open');
}

async function handleExecuteRemoveAccount() {
    if (!currentRemoveAccountId) return;
    const executeBtn = document.getElementById('btnExecuteRemoveAccount');
    if (executeBtn) {
        executeBtn.disabled = true;
        executeBtn.textContent = 'Removing Account...';
    }

    try {
        const res = await fetch(`/api/v1/admin/accounts/${currentRemoveAccountId}`, {
            method: 'DELETE',
            headers: getAuthorizationHeader()
        });

        const data = await res.json();
        if (res.ok && data.success) {
            closeRemoveAccountModal();
            loadAdminAccounts();
        } else {
            alert(data.detail || 'Failed to remove account.');
        }
    } catch (e) {
        console.warn('Remove account error:', e);
        alert('Network error removing account.');
    } finally {
        if (executeBtn) {
            executeBtn.disabled = false;
            executeBtn.textContent = 'Remove Account';
        }
    }
}

// ── 21. DEEPTRUST ADMIN: PROFILE & SECURITY SETTINGS ───────────────────────
async function loadAdminProfile() {
    try {
        const res = await fetch('/api/v1/auth/me', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const u = data.user || data;

            const nameInput = document.getElementById('profileInputName');
            const emailInput = document.getElementById('profileInputEmail');
            const roleInput = document.getElementById('profileInputRole');
            const orgInput = document.getElementById('profileInputOrg');
            const createdInput = document.getElementById('profileInputCreated');
            const lastLoginInput = document.getElementById('profileInputLastLogin');

            const cardName = document.getElementById('profileCardName');
            const cardRole = document.getElementById('profileCardRole');
            const cardEmail = document.getElementById('profileCardEmail');
            const cardOrg = document.getElementById('profileCardOrg');
            const avatar = document.getElementById('profileLargeAvatar');

            if (nameInput) nameInput.value = u.full_name || '';
            if (emailInput) emailInput.value = u.email || '';
            if (roleInput) roleInput.value = u.role || 'ADMIN';
            if (orgInput) orgInput.value = u.organization_name || u.organization || 'DeepTrust';
            if (createdInput) createdInput.value = u.created_at ? new Date(u.created_at).toLocaleString() : 'System Initial';
            if (lastLoginInput) lastLoginInput.value = u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Active Now';

            if (cardName) cardName.textContent = u.full_name || 'Administrator';
            if (cardRole) cardRole.textContent = u.role || 'ADMIN';
            if (cardEmail) cardEmail.textContent = u.email || '';
            if (cardOrg) cardOrg.textContent = u.organization_name || u.organization || 'DeepTrust';

            if (avatar && u.full_name) {
                const initials = u.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
                avatar.textContent = initials;
            }
        }
    } catch (e) {
        console.warn('Profile load error:', e);
    }
}

async function handleProfileUpdate(e) {
    e.preventDefault();
    const fullName = document.getElementById('profileInputName')?.value.trim();
    if (!fullName) {
        alert('Full Name cannot be empty.');
        return;
    }

    const btn = document.getElementById('btnSaveProfile');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Saving Changes...';
    }

    try {
        const res = await fetch('/api/v1/profile', {
            method: 'PATCH',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ full_name: fullName })
        });

        const data = await res.json();
        if (res.ok && data.success) {
            currentUser.full_name = fullName;
            syncUserProfileUI();
            loadAdminProfile();
            alert('Profile name updated successfully.');
        } else {
            alert(data.detail || 'Failed to update profile.');
        }
    } catch (err) {
        console.error('Profile update error:', err);
        alert('Network error updating profile.');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Save Profile Changes';
        }
    }
}

async function loadAdminSecurity() {
    // 1. Reset password form
    const form = document.getElementById('formChangePassword');
    if (form) form.reset();
    resetPasswordStrengthUI('pwdStrengthFill', 'pwdStrengthText', 'pwdReqList', 'req-');

    // 2. Load active sessions
    const tableBody = document.querySelector('#activeSessionsTable tbody');
    if (!tableBody) return;

    try {
        const activeRes = await fetch('/api/v1/admin/sessions/active', { headers: getAuthorizationHeader() });
        const mobRes = await fetch('/api/v1/admin/mobile-sessions', { headers: getAuthorizationHeader() });

        let activeSessions = [];
        if (activeRes.ok) {
            const data = await activeRes.json();
            activeSessions = data.sessions || [];
        }

        let mobileSessions = [];
        if (mobRes.ok) {
            const mobData = await mobRes.json();
            mobileSessions = mobData.sessions || [];
        }

        const allSessions = [
            ...activeSessions,
            ...mobileSessions.map(m => ({
                id: m.session_id,
                session_id: m.session_id,
                user_name: m.admin_name || m.admin_email,
                email: m.admin_email,
                organization: 'DeepTrust Platform',
                login_at: m.created_at ? new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent',
                last_activity: m.last_active ? new Date(m.last_active).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Active',
                logout_at: '--',
                duration_formatted: 'Live Pairing',
                status: m.status,
                location_context: { city: 'LAN Hotspot', region: 'Local Network', status: 'EXPECTED' },
                behavior_summary: { interaction_velocity: 'NORMAL', status: 'NORMAL' },
                is_mobile: true
            }))
        ];

        if (allSessions.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No active sessions registered.</td></tr>`;
            return;
        }

        tableBody.innerHTML = allSessions.map(s => {
            const isMobile = s.is_mobile === true;
            const statusClass = s.status === 'ACTIVE' ? 'active' : (s.status === 'LOGGED_OUT' ? 'block' : 'warning');
            const locStr = s.location_context ? `${s.location_context.city}, ${s.location_context.region}` : 'Chennai, Tamil Nadu';
            const behaviorStr = s.behavior_summary ? s.behavior_summary.interaction_velocity || 'NORMAL' : 'NORMAL';

            return `
                <tr>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            ${s.has_photo ? `<img src="${s.photo_url}" style="width: 26px; height: 26px; border-radius: 50%; object-fit: cover; border: 1px solid var(--accent-blue);" onerror="this.style.display='none'">` : ''}
                            <div>
                                <div style="font-weight: 600; font-size: 0.82rem; color: #fff;">${escapeHtml(s.user_name || s.email)}</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(s.email)}</div>
                            </div>
                        </div>
                    </td>
                    <td style="font-size: 0.76rem; color: var(--text-secondary);">${escapeHtml(s.organization || 'NovaCare Medical Center')}</td>
                    <td style="font-size: 0.76rem; color: var(--text-muted);">
                        <div>Login: ${escapeHtml(s.login_at)}</div>
                        <div style="font-size: 0.72rem; color: var(--accent-cyan);">Duration: ${escapeHtml(s.duration_formatted)}</div>
                    </td>
                    <td style="font-size: 0.76rem; color: var(--text-muted);">
                        <div>${escapeHtml(locStr)}</div>
                        <div style="font-size: 0.70rem; color: var(--success-green); font-weight: 600;">Location: ${escapeHtml(s.location_context?.status || 'EXPECTED')}</div>
                    </td>
                    <td style="font-size: 0.76rem; color: var(--text-muted);">
                        <div>Velocity: ${escapeHtml(behaviorStr)}</div>
                        <div style="font-size: 0.70rem; color: var(--accent-cyan); font-weight: 600;">Status: ${escapeHtml(s.behavior_summary?.status || 'NORMAL')}</div>
                    </td>
                    <td>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            <span class="status-pill ${statusClass}">${escapeHtml(s.status || 'ACTIVE')}</span>
                            ${isMobile ? `<button class="btn btn-sm btn-danger" onclick="revokeMobileSession('${escapeHtml(s.session_id)}')">REVOKE</button>` : `<button class="btn btn-sm btn-secondary" onclick="viewSecurityContext('${escapeHtml(s.session_id)}')">View Security Context</button>`}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.warn('Sessions load error:', e);
    }
}

window.viewSecurityContext = async function(sessionId) {
    const modal = document.getElementById('securityContextModal');
    const modalBody = document.getElementById('securityContextModalBody');
    if (!modal || !modalBody) return;

    modal.classList.add('active');
    modalBody.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 20px;">Loading security context...</p>';

    try {
        const res = await fetch(`/api/v1/admin/sessions/${sessionId}`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const ctx = data.security_context;
            modalBody.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 14px; font-size: 0.82rem;">
                    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
                        <h4 style="color: var(--accent-blue); margin-bottom: 6px; font-size: 0.85rem;">IDENTITY</h4>
                        <div><strong>Name:</strong> ${escapeHtml(ctx.identity.full_name)}</div>
                        <div><strong>Email:</strong> ${escapeHtml(ctx.identity.email)}</div>
                        <div><strong>Role:</strong> ${escapeHtml(ctx.identity.role)}</div>
                        <div><strong>Organization:</strong> ${escapeHtml(ctx.identity.organization)}</div>
                    </div>

                    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
                        <h4 style="color: var(--accent-cyan); margin-bottom: 6px; font-size: 0.85rem;">SESSION TIMELINE</h4>
                        <div><strong>Login Time:</strong> ${escapeHtml(ctx.session.login_at)}</div>
                        <div><strong>Last Activity:</strong> ${escapeHtml(ctx.session.last_activity)}</div>
                        <div><strong>Logout Time:</strong> ${escapeHtml(ctx.session.logout_at || 'Active')}</div>
                        <div><strong>Active Duration:</strong> ${escapeHtml(ctx.session.duration_formatted)}</div>
                        <div><strong>Status:</strong> <span class="status-pill active">${escapeHtml(ctx.session.status)}</span></div>
                    </div>

                    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
                        <h4 style="color: var(--success-green); margin-bottom: 6px; font-size: 0.85rem;">LOCATION & NETWORK</h4>
                        <div><strong>Approximate Location:</strong> ${escapeHtml(ctx.location.city)}, ${escapeHtml(ctx.location.region)} (${escapeHtml(ctx.location.country)})</div>
                        <div><strong>Location Source:</strong> ${escapeHtml(ctx.location.source)}</div>
                        <div><strong>Location Evaluation:</strong> <strong style="color: var(--success-green);">${escapeHtml(ctx.location.status)}</strong></div>
                    </div>

                    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
                        <h4 style="color: var(--warning-yellow); margin-bottom: 6px; font-size: 0.85rem;">BEHAVIORAL INTERACTION</h4>
                        <div><strong>Pointer Interaction Velocity:</strong> ${escapeHtml(ctx.behavior.interaction_velocity || 'NORMAL')}</div>
                        <div><strong>Behavioral Baseline Status:</strong> <strong style="color: var(--success-green);">${escapeHtml(ctx.behavior.status)}</strong></div>
                    </div>
                </div>
            `;
        } else {
            modalBody.innerHTML = '<p style="color: var(--danger-red); text-align: center; padding: 20px;">Failed to load security context details.</p>';
        }
    } catch (e) {
        modalBody.innerHTML = '<p style="color: var(--danger-red); text-align: center; padding: 20px;">Network error loading security context.</p>';
    }
};

document.addEventListener('click', (e) => {
    if (e.target.id === 'btnCloseSecurityContextModal' || e.target.id === 'btnDismissSecurityContextModal') {
        const modal = document.getElementById('securityContextModal');
        if (modal) modal.classList.remove('active');
    }
});

window.revokeMobileSession = async function(sessionId) {
    if (!confirm(`Revoke Mobile Monitor Session ${sessionId}?`)) return;
    try {
        const res = await fetch('/api/v1/admin/mobile-sessions/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthorizationHeader()
            },
            body: JSON.stringify({ session_id: sessionId })
        });
        if (res.ok) {
            alert(`Mobile Session ${sessionId} revoked successfully.`);
            loadSecurityProfileTab();
        } else {
            alert('Failed to revoke mobile session.');
        }
    } catch(e) {
        alert('Network error revoking mobile session.');
    }
};

async function handleChangePassword(e) {
    e.preventDefault();
    const currentPass = document.getElementById('pwdCurrent')?.value;
    const newPass = document.getElementById('pwdNew')?.value;
    const confirmPass = document.getElementById('pwdConfirm')?.value;

    if (!currentPass || !newPass || !confirmPass) {
        alert('Please fill out all password fields.');
        return;
    }

    if (newPass !== confirmPass) {
        alert('New passwords do not match. Please verify.');
        return;
    }

    if (!updatePasswordStrength(newPass, 'pwdStrengthFill', 'pwdStrengthText', 'req-')) {
        alert('New password does not satisfy all complexity requirements.');
        return;
    }

    const btn = document.getElementById('btnSubmitChangePassword');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Updating Password...';
    }

    try {
        const res = await fetch('/api/v1/profile/change-password', {
            method: 'POST',
            headers: {
                ...getAuthorizationHeader(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_password: currentPass,
                new_password: newPass,
                confirm_password: confirmPass
            })
        });

        const data = await res.json();
        if (res.ok && data.success) {
            alert('Password updated successfully! Other active sessions have been revoked.');
            document.getElementById('formChangePassword')?.reset();
            resetPasswordStrengthUI('pwdStrengthFill', 'pwdStrengthText', 'pwdReqList', 'req-');
            loadAdminSecurity();
        } else {
            alert(data.detail || 'Password update failed. Please check your current password.');
        }
    } catch (err) {
        console.error('Password change error:', err);
        alert('Network error updating password.');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Update Password';
        }
    }
}

async function handleRevokeOtherSessions() {
    if (!confirm('Sign out of all other active browser sessions?')) return;
    try {
        const res = await fetch('/api/v1/profile/sessions/revoke-others', {
            method: 'POST',
            headers: getAuthorizationHeader()
        });
        const data = await res.json();
        if (res.ok && data.success) {
            alert('Other active sessions revoked successfully.');
            loadAdminSecurity();
        } else {
            alert(data.detail || 'Failed to revoke sessions.');
        }
    } catch (e) {
        console.warn('Revoke sessions error:', e);
    }
}

async function handleResetMyMfa() {
    if (!confirm('Reset your Google Authenticator 2FA? This will invalidate your current TOTP secret.')) return;
    try {
        const res = await fetch('/api/v1/mfa/totp/setup', {
            method: 'POST',
            headers: getAuthorizationHeader()
        });
        const data = await res.json();
        if (res.ok && data.success) {
            currentPendingMfaUserId = currentUser.id || currentUser._id;
            const qrModal = document.getElementById('qrEnrollmentModal');
            const qrImg = document.getElementById('qrCodeImg');
            const secretDisplay = document.getElementById('qrSecretKeyDisplay');

            if (qrImg && data.qr_base64) qrImg.src = data.qr_base64;
            if (secretDisplay && data.secret) secretDisplay.textContent = data.secret;
            document.querySelectorAll('#enrollmentOtpContainer .totp-input-digit').forEach(b => b.value = '');

            if (qrModal) qrModal.classList.add('open');
        } else {
            alert(data.detail || 'Failed to generate new MFA secret.');
        }
    } catch (e) {
        console.warn('MFA Setup error:', e);
    }
}

// ── 22. DEEPTRUST ADMIN: MONTHLY SECURITY REPORT ───────────────────────────
let monthlyReportRequest = 0;
async function loadAdminReports(year, month) {
    const requestId = ++monthlyReportRequest;
    const loadingMeta = document.getElementById('reportGeneratedMeta');
    if (loadingMeta) loadingMeta.textContent = 'Loading selected reporting period…';
    const selMonth = month || document.getElementById('reportMonthSelect')?.value || 9;
    const selYear = year || document.getElementById('reportYearSelect')?.value || 2026;

    try {
        const res = await fetch(`/api/v1/admin/reports/monthly?year=${selYear}&month=${selMonth}`, {
            headers: getAuthorizationHeader()
        });

        if (!res.ok) throw new Error("Monthly report unavailable; retry after checking database access.");
        if (res.ok) {
            const data = await res.json();
            if (requestId !== monthlyReportRequest) return;
            const m = data.metrics || {};

            const periodEl = document.getElementById('reportPeriodTitle');
            const genMetaEl = document.getElementById('reportGeneratedMeta');

            if (periodEl) {
                const monthNames = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
                periodEl.textContent = `Reporting Period: ${monthNames[parseInt(selMonth)]} ${selYear} • Scope: All Organizations`;
            }
            if (genMetaEl) {
                genMetaEl.textContent = `MongoDB • ${m.demo_records_excluded || 0} marked demo records excluded • ${m.legacy_access_allowed || 0} legacy access events kept separate • ${new Date(m.generated_at).toLocaleString()}`;
            }

            const totalLoginsEl = document.getElementById('repTotalLogins');
            const successLoginsEl = document.getElementById('repSuccessLogins');
            const blockedLoginsEl = document.getElementById('repBlockedLogins');
            const highRiskEl = document.getElementById('repHighRisk');
            const faceFailEl = document.getElementById('repFaceFailures');
            const livenessFailEl = document.getElementById('repLivenessFailures');
            const voiceFailEl = document.getElementById('repVoiceFailures');
            const mfaSuccessEl = document.getElementById('repMfaSuccess');

            if (totalLoginsEl) totalLoginsEl.textContent = m.total_login_attempts || 0;
            if (successLoginsEl) successLoginsEl.textContent = m.successful_authentications || 0;
            if (blockedLoginsEl) blockedLoginsEl.textContent = m.blocked_attempts || 0;
            if (highRiskEl) highRiskEl.textContent = m.high_risk_events || 0;
            if (faceFailEl) faceFailEl.textContent = m.face_verification_failures || 0;
            if (livenessFailEl) livenessFailEl.textContent = m.liveness_failures || 0;
            if (voiceFailEl) voiceFailEl.textContent = m.voice_verification_failures || 0;
            if (mfaSuccessEl) mfaSuccessEl.textContent = m.mfa_success || 0;

            const orgTableBody = document.querySelector('#reportOrgSummaryTable tbody');
            if (orgTableBody) {
                const orgs = m.organizations || [];
                if (orgs.length === 0) {
                    orgTableBody.innerHTML = `<tr><td colspan="5">No organization events recorded for this month.</td></tr>`;
                } else {
                    orgTableBody.innerHTML = orgs.map(o => `
                        <tr>
                            <td><strong>${escapeHtml(o.name || 'Unassigned organization')}</strong></td>
                            <td>${o.auth_count || 0}</td>
                            <td><span class="status-pill verified">${o.successful_access || 0}</span></td>
                            <td><span class="status-pill ${o.blocked_access > 0 ? 'block' : 'low'}">${o.blocked_access || 0}</span></td>
                            <td><span class="status-pill ${o.security_events > 0 ? 'high' : 'low'}">${o.security_events || 0}</span></td>
                        </tr>
                    `).join('');
                }
            }
        }
    } catch (e) {
        if (requestId !== monthlyReportRequest) return;
        console.warn('Monthly report load error:', e);
        const meta=document.getElementById('reportGeneratedMeta');
        if(meta) meta.textContent='Report unavailable. Displayed counts are not current.';
    }
}

async function handleDownloadMonthlyPdf() {
    const selMonth = document.getElementById('reportMonthSelect')?.value || 9;
    const selYear = document.getElementById('reportYearSelect')?.value || 2026;
    const btn = document.getElementById('btnDownloadMonthlyPdf');

    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Generating PDF from MongoDB...';
    }

    try {
        const res = await fetch(`/api/v1/admin/reports/monthly?year=${selYear}&month=${selMonth}&download=true`, {
            headers: getAuthorizationHeader()
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `DeepTrust_Security_Report_${selYear}_${String(selMonth).padStart(2, '0')}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const err = await res.json();
            alert(err.detail || 'Failed to generate PDF report.');
        }
    } catch (e) {
        console.error('PDF download error:', e);
        alert('Network error downloading PDF report.');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg><span>Download PDF</span>`;
        }
    }
}

// ── 23. EVENT LISTENERS & INITIALIZATION ───────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    const isAuthed = await initDashboardAuth();
    if (!isAuthed) return;
    initAuditIntegrity({headers:getAuthorizationHeader});
    initDashboardFeatures({headers:getAuthorizationHeader, escapeHtml, openSession:openSessionDetailsDrawer});
    document.dispatchEvent(new CustomEvent("deeptrust:view",{detail:activeViewId}));
    const stopSessionMonitor = startSessionMonitor({getAuthorizationHeader, onUnauthorized: () => {clearSession('revoked'); window.location.replace('login.html');}});
    window.addEventListener('pagehide', stopSessionMonitor, {once: true});
    setInterval(tickSessionDurations, 1000);
    let sessionRefreshCount = 0;
    setInterval(() => {
        if (document.hidden) return;
        sessionRefreshCount++;
        if (activeViewId === 'admin-session-control') loadAdminSessionControl();
        const drawer = document.getElementById('sessionDetailsDrawer');
        if (openSessionDrawerId && drawer?.classList.contains('open') && sessionRefreshCount % 5 === 0) openSessionDetailsDrawer(openSessionDrawerId);
        if (activeViewId === 'admin-audit-logs' && currentAuditSessionId && sessionRefreshCount % 5 === 0) openSessionAuditTimeline(currentAuditIdentityId,currentAuditSessionId);
    }, 1000);

    // Sidebar collapse toggle
    const sidebar = document.getElementById('appSidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });
    }

    // Navigation links
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const view = btn.getAttribute('data-view');
            if (view) switchView(view);
        });
    });

    // Listen to browser hash changes (back/forward buttons)
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '').trim();
        if (hash && hash !== activeViewId) {
            switchView(hash);
        }
    });

    // Profile dropdown
    const userChip = document.getElementById('userChipBtn');
    const profileDropdown = document.getElementById('profileDropdown');
    if (userChip && profileDropdown) {
        userChip.addEventListener('click', (e) => {
            e.stopPropagation();
            profileDropdown.classList.toggle('open');
        });

        document.addEventListener('click', () => {
            profileDropdown.classList.remove('open');
        });
    }

    // Profile dropdown navigation items
    const dropdownProfileBtn = document.getElementById('dropdownProfileBtn');
    if (dropdownProfileBtn) {
        dropdownProfileBtn.addEventListener('click', () => {
            if (profileDropdown) profileDropdown.classList.remove('open');
            switchView('admin-profile');
        });
    }

    const dropdownSettingsBtn = document.getElementById('dropdownSettingsBtn');
    if (dropdownSettingsBtn) {
        dropdownSettingsBtn.addEventListener('click', () => {
            if (profileDropdown) profileDropdown.classList.remove('open');
            switchView('admin-security');
        });
    }

    // Account Management Modal triggers
    const btnOpenCreateAccount = document.getElementById('btnOpenCreateAccountModal');
    if (btnOpenCreateAccount) {
        btnOpenCreateAccount.addEventListener('click', openCreateAccountModal);
    }

    const btnCloseCreate = document.getElementById('btnCloseCreateModal');
    const btnCancelCreate = document.getElementById('btnCancelCreateModal');
    if (btnCloseCreate) btnCloseCreate.addEventListener('click', closeCreateAccountModal);
    if (btnCancelCreate) btnCancelCreate.addEventListener('click', closeCreateAccountModal);

    const btnCloseQr = document.getElementById('btnCloseQrModal');
    if (btnCloseQr) {
        btnCloseQr.addEventListener('click', () => {
            document.getElementById('qrEnrollmentModal')?.classList.remove('open');
        });
    }

    const btnCloseRemove = document.getElementById('btnCloseRemoveModal');
    const btnCancelRemove = document.getElementById('btnCancelRemoveModal');
    if (btnCloseRemove) btnCloseRemove.addEventListener('click', closeRemoveAccountModal);
    if (btnCancelRemove) btnCancelRemove.addEventListener('click', closeRemoveAccountModal);

    // Dynamic Account Type switch in Create Modal
    const accTypeSelect = document.getElementById('modalAccType');
    if (accTypeSelect) {
        accTypeSelect.addEventListener('change', () => {
            const orgSelect = document.getElementById('modalAccOrg');
            const roleSelect = document.getElementById('modalAccRole');
            if (accTypeSelect.value === 'DEEPTRUST_ADMIN') {
                if (orgSelect) {
                    orgSelect.innerHTML = `<option value="DeepTrust" selected>DeepTrust</option>`;
                }
                if (roleSelect) {
                    roleSelect.innerHTML = `
                        <option value="DEEPTRUST_ADMIN" selected>DeepTrust Admin</option>
                        <option value="ADMIN">System Administrator</option>
                        <option value="SECURITY_ANALYST">Security Analyst</option>
                    `;
                }
            } else {
                if (orgSelect) {
                    orgSelect.innerHTML = `<option value="NovaCare Medical Center" selected>Healthcare Organization</option>`;
                }
                if (roleSelect) {
                    roleSelect.innerHTML = `
                        <option value="HOSPITAL_ADMIN" selected>Hospital Administrator</option>
                        <option value="SECURITY_ANALYST">Security Analyst</option>
                        <option value="ADMIN">System Administrator</option>
                    `;
                }
            }
        });
    }

    // Password strength meter in Create Modal
    const createPassInput = document.getElementById('modalAccPassword');
    if (createPassInput) {
        createPassInput.addEventListener('input', () => {
            updatePasswordStrength(createPassInput.value, 'modalPassStrengthFill', 'modalPassStrengthText', 'mreq-');
        });
    }

    // Toggle password visibility in Create Modal
    const btnToggleCreatePass = document.getElementById('btnToggleCreatePass');
    if (btnToggleCreatePass && createPassInput) {
        btnToggleCreatePass.addEventListener('click', () => {
            if (createPassInput.type === 'password') {
                createPassInput.type = 'text';
                btnToggleCreatePass.textContent = 'Hide Password';
            } else {
                createPassInput.type = 'password';
                btnToggleCreatePass.textContent = 'Show Password';
            }
        });
    }

    // Remove confirmation input listener
    const removeConfirmInput = document.getElementById('removeConfirmInput');
    const btnExecuteRemove = document.getElementById('btnExecuteRemoveAccount');
    if (removeConfirmInput && btnExecuteRemove) {
        removeConfirmInput.addEventListener('input', () => {
            btnExecuteRemove.disabled = (removeConfirmInput.value.trim() !== 'REMOVE');
        });
        btnExecuteRemove.addEventListener('click', handleExecuteRemoveAccount);
    }

    // Create Account Form submit
    const formCreateAccount = document.getElementById('formCreateAccount');
    if (formCreateAccount) {
        formCreateAccount.addEventListener('submit', handleCreateAccountSubmit);
    }

    // TOTP confirmation inputs handling
    const otpBoxes = document.querySelectorAll('#enrollmentOtpContainer .totp-input-digit');
    otpBoxes.forEach((box, index) => {
        box.addEventListener('input', () => {
            const val = box.value.trim();
            if (val.length >= 1) {
                box.value = val[0];
                if (index < otpBoxes.length - 1) otpBoxes[index + 1].focus();
            }
        });
        box.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !box.value && index > 0) {
                otpBoxes[index - 1].focus();
            }
        });
        box.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
            if (/^\d{6}$/.test(pasteData)) {
                pasteData.split('').forEach((char, i) => {
                    if (otpBoxes[i]) otpBoxes[i].value = char;
                });
                otpBoxes[otpBoxes.length - 1].focus();
            }
        });
    });

    const formConfirmTotp = document.getElementById('formConfirmTotp');
    if (formConfirmTotp) {
        formConfirmTotp.addEventListener('submit', handleConfirmTotpSubmit);
    }

    // Refresh Accounts Button
    const btnRefreshAcc = document.getElementById('btnRefreshAccounts');
    if (btnRefreshAcc) {
        btnRefreshAcc.addEventListener('click', loadAdminAccounts);
    }

    // Profile update form
    const formAdminProfile = document.getElementById('formAdminProfile');
    if (formAdminProfile) {
        formAdminProfile.addEventListener('submit', handleProfileUpdate);
    }

    // Change Password form & strength meter
    const newPassInput = document.getElementById('pwdNew');
    if (newPassInput) {
        newPassInput.addEventListener('input', () => {
            updatePasswordStrength(newPassInput.value, 'pwdStrengthFill', 'pwdStrengthText', 'req-');
        });
    }
    const formChangePassword = document.getElementById('formChangePassword');
    if (formChangePassword) {
        formChangePassword.addEventListener('submit', handleChangePassword);
    }

    // Sign out other sessions
    const btnSignOutOthers = document.getElementById('btnSignOutOtherSessions');
    if (btnSignOutOthers) {
        btnSignOutOthers.addEventListener('click', handleRevokeOtherSessions);
    }

    // Reset personal MFA
    const btnResetMyMfa = document.getElementById('btnResetMyMfa');
    if (btnResetMyMfa) {
        btnResetMyMfa.addEventListener('click', handleResetMyMfa);
    }

    // Monthly Reports triggers
    const btnGenReport = document.getElementById('btnGenerateReport');
    if (btnGenReport) {
        btnGenReport.addEventListener('click', () => {
            loadAdminReports();
        });
    }

    const monthSelect = document.getElementById('reportMonthSelect');
    const yearSelect = document.getElementById('reportYearSelect');
    if (monthSelect) monthSelect.addEventListener('change', () => loadAdminReports());
    if (yearSelect) yearSelect.addEventListener('change', () => loadAdminReports());

    const btnDownloadPdf = document.getElementById('btnDownloadMonthlyPdf');
    if (btnDownloadPdf) {
        btnDownloadPdf.addEventListener('click', handleDownloadMonthlyPdf);
    }

    // Logout actions
    const logoutBtn = document.getElementById('dropdownLogoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            const token = getSessionToken();
            if (token) {
                try {
                    await fetch('/api/v1/auth/logout', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                } catch (e) {
                    console.error('[Dashboard] Backend logout failed:', e);
                }
            }
            clearSession();
            window.location.replace('login.html');
        });
    }

    // Refresh buttons
    const refreshBtn = document.getElementById('refreshOverviewBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadHealthcareOverview();
            syncNotifications();
        });
    }

    // Notification drawer
    const notifBtn = document.getElementById('notifyDrawerBtn');
    const notifDrawer = document.getElementById('notificationDrawer');
    const notifClose = document.getElementById('notifCloseBtn');
    const markAllRead = document.getElementById('markAllNotifsReadBtn');

    if (notifBtn && notifDrawer) {
        notifBtn.addEventListener('click', () => {
            notifDrawer.classList.add('open');
            const backdrop = document.getElementById('drawerBackdrop');
            if (backdrop) backdrop.classList.add('open');
        });
    }

    if (notifClose) notifClose.addEventListener('click', closeDrawers);
    const drawerCloseBtn = document.getElementById('drawerCloseBtn');
    if (drawerCloseBtn) drawerCloseBtn.addEventListener('click', closeDrawers);
    const orgDrawerCloseBtn = document.getElementById('orgDrawerCloseBtn');
    if (orgDrawerCloseBtn) orgDrawerCloseBtn.addEventListener('click', closeDrawers);
    const orgDrawerCloseFooterBtn = document.getElementById('orgDrawerCloseFooterBtn');
    if (orgDrawerCloseFooterBtn) orgDrawerCloseFooterBtn.addEventListener('click', closeDrawers);

    const backdrop = document.getElementById('drawerBackdrop');
    if (backdrop) backdrop.addEventListener('click', closeDrawers);

    if (markAllRead) {
        markAllRead.addEventListener('click', async () => {
            await fetch('/api/v1/notifications/read-all', { method: 'POST', headers: getAuthorizationHeader() });
            syncNotifications();
        });
    }

    // Investigation drawer actions (Acknowledge / Resolve)
    const ackBtn = document.getElementById('drawerAcknowledgeBtn');
    const resolveBtn = document.getElementById('drawerResolveBtn');

    if (ackBtn) {
        ackBtn.addEventListener('click', async () => {
            if (!activeEventId) return;
            await fetch(`/api/v1/security-events/${activeEventId}/action`, {
                method: 'POST',
                headers: { ...getAuthorizationHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'ACKNOWLEDGE', notes: `Acknowledged by ${currentUser.full_name}` })
            });
            closeDrawers();
            loadSecurityAlerts();
            loadAdminThreatInvestigation('ALL');
        });
    }

    if (resolveBtn) {
        resolveBtn.addEventListener('click', async () => {
            if (!activeEventId) return;
            await fetch(`/api/v1/security-events/${activeEventId}/action`, {
                method: 'POST',
                headers: { ...getAuthorizationHeader(), 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'RESOLVE', notes: `Incident mitigated by ${currentUser.full_name}` })
            });
            closeDrawers();
            loadSecurityAlerts();
            loadAdminThreatInvestigation('ALL');
        });
    }

    // Threat Severity Filter Buttons in DeepTrust Admin
    document.querySelectorAll('#adminThreatSeverityFilter .filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#adminThreatSeverityFilter .filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadAdminThreatInvestigation(btn.getAttribute('data-filter'));
        });
    });

    // Trend Range Filters in Healthcare
    document.querySelectorAll('#trendTimeFilter .filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#trendTimeFilter .filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadAuthenticationTrend(btn.getAttribute('data-range'));
        });
    });

    // Identity Role Filters & Search in Healthcare
    document.querySelectorAll('#identityRoleFilter .filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#identityRoleFilter .filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const searchVal = document.getElementById('identitySearchInput')?.value || '';
            loadIdentities(searchVal, btn.getAttribute('data-role'));
        });
    });

    const identSearchInput = document.getElementById('identitySearchInput');
    if (identSearchInput) {
        identSearchInput.addEventListener('input', (e) => {
            const activeRole = document.querySelector('#identityRoleFilter .filter-btn.active')?.getAttribute('data-role') || 'ALL';
            loadIdentities(e.target.value, activeRole);
        });
    }

    // AI Copilot Form & Chips
    const copilotForm = document.getElementById('copilotForm');
    if (copilotForm) {
        copilotForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const query = document.getElementById('copilotInput')?.value;
            handleCopilotQuery(query);
        });
    }

    document.querySelectorAll('.copilot-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const q = chip.getAttribute('data-query');
            handleCopilotQuery(q);
        });
    });

    // Shortcut: View full log in Healthcare
    const viewAllBtn = document.getElementById('viewAllActivityBtn');
    if (viewAllBtn) {
        viewAllBtn.addEventListener('click', () => {
            switchView('org-auth-activity');
        });
    }

    // Global Search Input Keyboard Handler
    const globalSearch = document.getElementById('globalSearchInput');
    if (globalSearch) {
        globalSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const term = globalSearch.value.trim().toLowerCase();
                if (!term) return;

                if (currentRole.startsWith('DEEPTRUST')) {
                    if (term.includes('threat') || term.includes('event') || term.includes('alert')) {
                        switchView('admin-threat-investigation');
                    } else if (term.includes('org') || term.includes('healthcare')) {
                        switchView('admin-organizations');
                    } else if (term.includes('risk')) {
                        switchView('admin-risk-engine');
                    } else if (term.includes('health')) {
                        switchView('admin-system-health');
                    } else {
                        switchView('admin-identity-sec');
                    }
                } else {
                    if (term.includes('alert')) {
                        switchView('org-alerts');
                    } else if (term.includes('audit')) {
                        switchView('org-audit');
                    } else {
                        switchView('org-identities');
                    }
                }
            }
        });
    }

    // Command Palette / Quick Navigation (Ctrl+K or Cmd+K)
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            if (globalSearch) {
                globalSearch.focus();
                globalSearch.select();
            }
        }
    });

    // Session Control UI Listeners
    const scRefreshBtn = document.getElementById('scRefreshBtn');
    if (scRefreshBtn) {
        scRefreshBtn.addEventListener('click', () => loadAdminSessionControl());
    }

    const scSearchInput = document.getElementById('scSearchInput');
    if (scSearchInput) {
        scSearchInput.addEventListener('input', (e) => {
            const val = e.target.value.toLowerCase().trim();
            document.querySelectorAll('#adminSessionControlTable tbody tr').forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(val) ? '' : 'none';
            });
        });
    }

    // Per-Identity Audit UI Listeners
    const auditRefreshBtn = document.getElementById('auditIdentitiesRefreshBtn');
    if (auditRefreshBtn) {
        auditRefreshBtn.addEventListener('click', () => {
            const query = document.getElementById('auditIdentitySearchInput')?.value || '';
            loadAdminAuditLogs(query);
        });
    }

    let auditSearchTimeout = null;
    const auditSearchInput = document.getElementById('auditIdentitySearchInput');
    if (auditSearchInput) {
        auditSearchInput.addEventListener('input', (e) => {
            clearTimeout(auditSearchTimeout);
            auditSearchTimeout = setTimeout(() => {
                loadAdminAuditLogs(e.target.value.trim());
            }, 300);
        });
    }

    const auditBackToIdentitiesBtn = document.getElementById('auditBackToIdentitiesBtn');
    if (auditBackToIdentitiesBtn) {
        auditBackToIdentitiesBtn.addEventListener('click', () => {
            const identitiesLevel = document.getElementById('auditLevelIdentities');
            const detailLevel = document.getElementById('auditLevelIdentityDetail');
            const timelineLevel = document.getElementById('auditLevelSessionTimeline');
            if (identitiesLevel) identitiesLevel.style.display = 'block';
            if (detailLevel) detailLevel.style.display = 'none';
            if (timelineLevel) timelineLevel.style.display = 'none';
        });
    }

    const auditBackToSessionsBtn = document.getElementById('auditBackToSessionsBtn');
    if (auditBackToSessionsBtn) {
        auditBackToSessionsBtn.addEventListener('click', () => {
            const identitiesLevel = document.getElementById('auditLevelIdentities');
            const detailLevel = document.getElementById('auditLevelIdentityDetail');
            const timelineLevel = document.getElementById('auditLevelSessionTimeline');
            if (identitiesLevel) identitiesLevel.style.display = 'none';
            if (detailLevel) detailLevel.style.display = 'block';
            if (timelineLevel) timelineLevel.style.display = 'none';
        });
    }

    const sessionDrawerCloseBtn = document.getElementById('sessionDrawerCloseBtn');
    if (sessionDrawerCloseBtn) {
        sessionDrawerCloseBtn.addEventListener('click', () => {
            document.getElementById('sessionDetailsDrawer')?.classList.remove('open');
            document.getElementById('drawerBackdrop')?.classList.remove('open');
        });
    }

    const auditSessionStatusFilter = document.getElementById('auditSessionStatusFilter');
    if (auditSessionStatusFilter) {
        auditSessionStatusFilter.addEventListener('change', (e) => {
            const filterVal = e.target.value;
            document.querySelectorAll('#auditIdentitySessionsTable tbody tr').forEach(row => {
                if (filterVal === 'ALL') {
                    row.style.display = '';
                } else {
                    const text = row.textContent;
                    row.style.display = text.includes(filterVal) ? '' : 'none';
                }
            });
        });
    }

    // Initial Notifications Sync
    syncNotifications();

    // Live staff sign-in monitoring: one request per second while visible.
    setInterval(() => {
        syncNotifications();
    }, 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) syncNotifications(); });
});



/* ── NOVACARE PRIVACY-PRESERVING TELEMETRY & SECURITY ACTIVITY ───────── */
async function loadNovaCareAggregateCounts() {
    try {
        const res = await fetch('/api/v1/telemetry/aggregate-counts?organization_id=HEALTHCARE_ORG_1', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const c = data.counts || {};

            const elPatients = document.getElementById('countPatients');
            const elAppts = document.getElementById('countAppointments');
            const elRx = document.getElementById('countPrescriptions');
            const elLab = document.getElementById('countLabRecords');
            const elIns = document.getElementById('countInsurance');
            const elBill = document.getElementById('countBilling');
            const elAvailBeds = document.getElementById('countAvailBeds');
            const elOccBeds = document.getElementById('countOccupiedBeds');

            if (elPatients) elPatients.textContent = c.patients !== undefined ? c.patients : 'Unavailable';
            if (elAppts) elAppts.textContent = c.appointments !== undefined ? c.appointments : 'Unavailable';
            if (elRx) elRx.textContent = c.prescriptions !== undefined ? c.prescriptions : 'Unavailable';
            if (elLab) elLab.textContent = c.lab_records !== undefined ? c.lab_records : 'Unavailable';
            if (elIns) elIns.textContent = c.insurance_records !== undefined ? c.insurance_records : 'Unavailable';
            if (elBill) elBill.textContent = c.billing_transactions !== undefined ? c.billing_transactions : 'Unavailable';
            if (elAvailBeds) elAvailBeds.textContent = c.available_beds !== undefined ? c.available_beds : 'Unavailable';
            if (elOccBeds) elOccBeds.textContent = c.occupied_beds !== undefined ? c.occupied_beds : 'Unavailable';
        }
    } catch (e) {
        console.warn('[NovaCare Counts Fetch Error]:', e);
    }
}

async function loadNovaCareSecurityActivity() {
    const tableBody = document.querySelector('#novaCareActivityTable tbody');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/v1/telemetry/activity?limit=15', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const items = data.activity || [];

            if (items.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No NovaCare activity recorded yet.</td></tr>`;
                return;
            }

            tableBody.innerHTML = items.map(it => {
                const isBlocked = it.decision === 'BLOCK';
                const isStepUp = it.decision === 'STEP_UP';
                const decisionClass = isBlocked ? 'block' : (isStepUp ? 'high' : 'verified');
                const riskClass = it.risk_level === 'CRITICAL' || it.risk_level === 'HIGH' ? 'high' : (it.risk_level === 'MEDIUM' ? 'warning' : 'low');

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(it.timestamp || 'Recent')}</td>
                        <td><strong>${escapeHtml(it.role || 'Staff')}</strong></td>
                        <td><span class="status-pill low">${escapeHtml(it.action || 'READ')}</span></td>
                        <td><strong style="color: var(--primary-indigo);">${escapeHtml(it.resource_type || 'PATIENT_RECORD')}</strong></td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(it.resource_reference || 'REF-SAFE')}</td>
                        <td><span class="status-pill ${riskClass}">${it.risk_score} / ${escapeHtml(it.risk_level)}</span></td>
                        <td><span class="status-pill ${decisionClass}">${escapeHtml(it.decision)}</span></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.warn('[NovaCare Activity Fetch Error]:', e);
    }
}

// ── SESSION CONTROL IMPLEMENTATION ──────────────────────────────────────────

let sessionControlBusy = false;
let sessionTableSignature = null;
let openSessionDrawerId = null;
function sessionLocalTime(value) {
    if (!value) return 'Not recorded';
    const date = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? 'Not recorded' : date.toLocaleString();
}
function sessionDurationNode(s) {
    return `<span data-live-duration="${Number(s.duration_seconds) || 0}" data-duration-captured="${Date.now()}" data-duration-running="${s.duration_running === true}">${escapeHtml(s.duration_formatted || '00:00:00')}</span>`;
}
function tickSessionDurations() {
    if (document.hidden) return;
    document.querySelectorAll('.view-section.active [data-live-duration], .investigation-drawer.open [data-live-duration]').forEach(el => {
        const seconds = Number(el.dataset.liveDuration) + (el.dataset.durationRunning === 'true' ? Math.floor((Date.now()-Number(el.dataset.durationCaptured))/1000) : 0);
        const value = Math.max(0, seconds);
        const formatted = [Math.floor(value/3600),Math.floor(value/60)%60,value%60].map(n=>String(n).padStart(2,'0')).join(':');
        if (el.textContent !== formatted) el.textContent = formatted;
    });
}

async function loadAdminSessionControl() {
    const tableBody = document.querySelector('#adminSessionControlTable tbody');
    if (!tableBody || sessionControlBusy) return;
    sessionControlBusy = true;

    try {
        const res = await fetch('/api/v1/admin/sessions/control', { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const summary = data.summary || {};
            const sessions = data.sessions || [];
            const monitorStatus=document.getElementById('scMonitorStatus');
            const monitorUpdated=document.getElementById('scMonitorUpdated');
            const monitorAlerts=document.getElementById('scInteractionAlerts');
            if(monitorStatus)monitorStatus.textContent='Live session monitoring';
            if(monitorUpdated)monitorUpdated.textContent='Updated '+new Date().toLocaleTimeString();
            if(monitorAlerts)monitorAlerts.textContent='Interaction alerts: '+(summary.interaction_alerts || 0);


            const scActive = document.getElementById('scKpiActive');
            const scHighRisk = document.getElementById('scKpiHighRisk');
            const scStepUp = document.getElementById('scKpiStepUp');
            const scBlocked = document.getElementById('scKpiBlocked');
            const scTrustedDev = document.getElementById('scKpiTrustedDev');
            const scUntrustedDev = document.getElementById('scKpiUntrustedDev');
            const badge = document.getElementById('adminActiveSessionsBadge');

            if (scActive) scActive.textContent = summary.active_sessions || 0;
            if (scHighRisk) scHighRisk.textContent = summary.high_risk || 0;
            if (scStepUp) scStepUp.textContent = summary.step_up_required || 0;
            if (scBlocked) scBlocked.textContent = summary.blocked || 0;
            if (scTrustedDev) scTrustedDev.textContent = summary.trusted_devices || 0;
            if (scUntrustedDev) scUntrustedDev.textContent = summary.untrusted_devices || 0;

            if (badge) {
                if (summary.active_sessions > 0) {
                    badge.textContent = summary.active_sessions;
                    badge.style.display = 'inline-block';
                } else {
                    badge.style.display = 'none';
                }
            }

            if (sessions.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="13" style="text-align: center; color: var(--text-muted); padding: 32px;">No sessions recorded yet.</td></tr>`;
                return;
            }

            const nextSignature = JSON.stringify(sessions.map(s => [s.session_id,s.status,s.risk_level,s.risk_score,s.behavior_summary,s.last_activity_iso,s.ip_masked,s.device_formatted,s.device_trust,s.connection_status,s.current_view]));
            if (nextSignature === sessionTableSignature) return;
            sessionTableSignature = nextSignature;
            tableBody.innerHTML = sessions.map(s => {
                const isTrusted = s.device_trust === 'TRUSTED';
                const trustPill = isTrusted 
                    ? `<span class="status-pill low">TRUSTED</span>` 
                    : (s.device_trust === 'UNTRUSTED' ? `<span class="status-pill warning">UNTRUSTED</span>` : `<span class="status-pill">UNKNOWN</span>`);
                
                const netClass = (s.network_status === 'KNOWN' || s.network_status === 'LOCAL' || s.network_status === 'PRIVATE NETWORK') ? 'low' : (s.network_status === 'CHANGED' ? 'warning' : 'medium');
                const netPill = `<span class="status-pill ${netClass}">${escapeHtml(s.network_status || 'UNKNOWN')}</span>`;

                const riskClass = (s.risk_level === 'CRITICAL' || s.risk_level === 'HIGH') ? 'high' : (s.risk_level === 'MEDIUM' ? 'warning' : 'low');
                const riskPill = `<span class="status-pill ${riskClass}">${s.risk_score} ${escapeHtml(s.risk_level)}</span>`;

                const statusClass = s.status === 'ACTIVE' ? 'verified' : (s.status === 'BLOCKED' ? 'block' : 'warning');
                const statusPill = `<span class="status-pill ${statusClass}">${escapeHtml(s.status)}</span>`;

                return `
                    <tr data-session-id="${escapeHtml(s.session_id)}" data-identity-id="${escapeHtml(s.identity_id)}">
                        <td>
                            <button class="session-email-link btn-session-detail" data-session-id="${escapeHtml(s.session_id)}">${escapeHtml(s.email)}</button>
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(s.session_id)}</div>
                        </td>
                        <td>${escapeHtml(s.role || 'User')}</td>
                        <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(s.organization_name || 'NovaCare Medical Center')}</td>
                        <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(s.application || 'Staff Portal')}</td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(sessionLocalTime(s.login_time_iso))}</td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--accent-cyan);">${sessionDurationNode(s)}</td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(s.ip_masked || 'Unavailable')}</td>
                        <td>${netPill}</td>
                        <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(s.device_formatted || 'Desktop Browser')}</td>
                        <td>${trustPill}</td>
                        <td>${riskPill}<div class="session-monitor-subtext">${escapeHtml(s.behavior_summary?.status || 'INSUFFICIENT_DATA')}</div><div class="session-monitor-subtext">Mouse / scroll / swipe: ${escapeHtml(s.behavior_summary?.automation_assessment || 'INSUFFICIENT_DATA')}</div></td>
                        <td>${statusPill}<div class="session-monitor-subtext">${escapeHtml(s.current_view || 'Not recorded')} · ${escapeHtml(s.connection_status || 'UNKNOWN')}</div></td>
                        <td style="text-align: right; white-space: nowrap;">
                            <button class="btn btn-secondary btn-sm btn-session-detail" data-session-id="${escapeHtml(s.session_id)}" style="padding: 4px 8px; font-size: 0.76rem; margin-right: 4px;">View Details</button>
                            <button class="btn btn-secondary btn-sm btn-session-audit" data-identity-id="${escapeHtml(s.identity_id)}" data-session-id="${escapeHtml(s.session_id)}" style="padding: 4px 8px; font-size: 0.76rem;">View Audit</button>
                        </td>
                    </tr>
                `;
            }).join('');

            tableBody.querySelectorAll('.btn-session-detail').forEach(btn => {
                btn.addEventListener('click', () => {
                    const sid = btn.getAttribute('data-session-id');
                    openSessionDetailsDrawer(sid);
                });
            });

            tableBody.querySelectorAll('.btn-session-audit').forEach(btn => {
                btn.addEventListener('click', () => {
                    const iid = btn.getAttribute('data-identity-id');
                    const sid = btn.getAttribute('data-session-id');
                    switchView('admin-audit-logs');
                    openSessionAuditTimeline(iid, sid);
                });
            });
        } else {
            const status=document.getElementById('scMonitorStatus');
            if(status)status.textContent='Refresh failed — showing last recorded data';
            if(res.status===401){clearSession('expired');window.location.replace('login.html');}
        }
    } catch (e) {
        const status=document.getElementById('scMonitorStatus');
        if(status)status.textContent='Connection interrupted — showing last recorded data';
        console.warn('[Session Control Fetch Error]:', e);
    } finally { sessionControlBusy = false; }
}


function renderInteractionSummary(behavior) {
    const number=(key,digits=0)=>Number.isFinite(Number(behavior[key])) ? Number(behavior[key]).toFixed(digits) : 'Not recorded';
    const reasons={CLIENT_AUTOMATION_INDICATOR:'Browser automation or synthetic-event indicator',UNUSUAL_EVENT_RATE:'Unusually high click or pointer event rate',UNUSUAL_POINTER_SPEED:'Unusually high pointer speed',REPETITIVE_POINTER_PATTERN:'Repeated straight paths with uniform speed and timing',UNUSUAL_SCROLL_SWIPE_RATE:'Unusually frequent scroll or swipe activity',NO_POINTER_SAMPLES:'Not enough interaction samples',NO_TELEMETRY:'No measured activity received',TELEMETRY_STALE:'No recent activity summary received'};
    const labels=(behavior.reason_codes||[]).map(code=>reasons[code]||code);
    return `<strong>${escapeHtml(behavior.status||'INSUFFICIENT_DATA')}</strong>
        <p>${escapeHtml(behavior.assessment||'Waiting for measured interaction data')}</p>
        <div class="session-monitor-subtext">Data: ${escapeHtml(behavior.freshness||'NOT_MEASURED')}${behavior.last_measured_status ? ` · Last measured status: ${escapeHtml(behavior.last_measured_status)}` : ''}</div>
        <p><strong>Automation indicators:</strong> ${escapeHtml(behavior.automation_assessment||'INSUFFICIENT_DATA')}</p>
        <div class="session-monitor-subtext">Pointer samples: ${number('sample_count')} · Speed: ${number('average_velocity',1)} px/s · Clicks: ${number('click_rate',2)}/s</div>
        <div class="session-monitor-subtext">Scroll events: ${number('scroll_events')} · Wheel events: ${number('wheel_events')} · Touch swipes: ${number('swipe_count')}</div>
        <div class="session-monitor-subtext">Trusted events: ${number('trusted_events')} · Synthetic events: ${number('synthetic_events')} · WebDriver: ${behavior.webdriver===true?'Detected':behavior.webdriver===false?'Not reported':'Not recorded'}</div>
        <p>${escapeHtml(labels.join('; ')||'No unusual indicators in this measured window')}</p>
        <div class="session-monitor-subtext">Last measured: ${escapeHtml(behavior.updated_at_iso?sessionLocalTime(behavior.updated_at_iso):'Not recorded')} · Window: ${number('window_seconds',1)} seconds</div>
        <p class="session-monitor-subtext">Signals update every 15 seconds for this email and session. Mouse patterns support investigation; they cannot prove that AI controls the device. No typed text or pointer coordinates are stored.</p>`;
}

async function openSessionDetailsDrawer(sessionId) {
    if (!sessionId) return;
    openSessionDrawerId = sessionId;
    const drawer = document.getElementById('sessionDetailsDrawer');
    const backdrop = document.getElementById('drawerBackdrop');
    if (!drawer) return;

    try {
        const res = await fetch(`/api/v1/admin/sessions/detail/${sessionId}`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const s = data.session || {};
            document.dispatchEvent(new CustomEvent('deeptrust:session',{detail:s}));
            const net = data.network_context || {};
            const dev = data.device_context || {};
            const sec = data.security || {};
            const assur = data.assurance || {};

            const elEmail = document.getElementById('sdIdentityEmail');
            const elRole = document.getElementById('sdIdentityRole');
            const elOrg = document.getElementById('sdOrgName');
            const elApp = document.getElementById('sdAppName');
            const elSid = document.getElementById('sdSessionId');
            const elStatus = document.getElementById('sdSessionStatus');
            const elLogin = document.getElementById('sdLoginTime');
            const elLast = document.getElementById('sdLastActivity');

            if (elEmail) elEmail.textContent = s.email || '--';
            if (elRole) elRole.textContent = s.role || '--';
            if (elOrg) elOrg.textContent = s.organization_name || s.organization || '--';
            if (elApp) elApp.textContent = s.application || 'NovaCare Staff Portal';
            if (elSid) elSid.textContent = s.session_id || '--';
            if (elStatus) elStatus.innerHTML = `<span class="status-pill ${s.status === 'ACTIVE' ? 'verified' : 'warning'}">${escapeHtml(s.status || 'ACTIVE')}</span>`;
            if (elLogin) elLogin.textContent = sessionLocalTime(s.login_time_iso);
            if (elLast) elLast.textContent = sessionLocalTime(s.last_activity_iso);

            const elIp = document.getElementById('sdIpAddress');
            const elNet = document.getElementById('sdNetworkStatus');
            const elFirst = document.getElementById('sdFirstSeen');
            const elChanged = document.getElementById('sdNetworkChanged');

            if (elIp) elIp.textContent = net.ip_masked || 'Unavailable';
            if (elNet) elNet.innerHTML = `<span class="status-pill ${(net.network_status === 'KNOWN' || net.network_status === 'LOCAL' || net.network_status === 'PRIVATE NETWORK') ? 'low' : 'warning'}">${escapeHtml(net.network_status || 'UNKNOWN')}</span>`;
            if (elFirst) elFirst.textContent = net.first_seen ? new Date(net.first_seen).toLocaleDateString() : 'Not recorded';
            if (elChanged) elChanged.textContent = net.network_changed ? 'YES' : 'NO';

            const elBrowser = document.getElementById('sdBrowser');
            const elOs = document.getElementById('sdOs');
            const elCat = document.getElementById('sdDeviceCategory');
            const elTrust = document.getElementById('sdDeviceTrust');

            if (elBrowser) elBrowser.textContent = dev.browser || 'Chrome';
            if (elOs) elOs.textContent = dev.os || 'Windows';
            if (elCat) elCat.textContent = dev.category || 'DESKTOP';
            if (elTrust) elTrust.innerHTML = `<span class="status-pill ${dev.device_trust === 'TRUSTED' ? 'low' : 'warning'}">${escapeHtml(dev.device_trust || 'UNKNOWN')}</span>`;

            const elCreds = document.getElementById('sdAssuranceCreds');
            const elFace = document.getElementById('sdAssuranceFace');
            const elLive = document.getElementById('sdAssuranceLiveness');
            const elVoice = document.getElementById('sdAssuranceVoice');
            const elMfa = document.getElementById('sdAssuranceMfa');
            const elFinal = document.getElementById('sdAssuranceFinal');

            if (elCreds) elCreds.textContent = assur.credentials || 'NOT_RECORDED';
            if (elFace) elFace.textContent = assur.face || 'NOT_RECORDED';
            if (elLive) elLive.textContent = assur.liveness || 'NOT_RECORDED';
            if (elVoice) elVoice.textContent = assur.voice || 'NOT_RECORDED';
            if (elMfa) elMfa.textContent = assur.mfa || 'VERIFIED';
            if (elFinal) elFinal.textContent = assur.final_access || 'GRANTED';

            const duration = document.getElementById('sdDuration');
            if (duration) duration.innerHTML = sessionDurationNode(s);
            const logout = document.getElementById('sdLogoutTime');
            if (logout) logout.textContent = s.logout_time_iso ? sessionLocalTime(s.logout_time_iso) : (s.duration_running ? 'Session running' : 'Not recorded');
            const behavior = data.behavior || s.behavior_summary || {};
            const behaviorEl = document.getElementById('sdBehavior');
            if (behaviorEl) {
                behaviorEl.innerHTML = renderInteractionSummary(behavior);
            }
            const currentView = document.getElementById('sdCurrentView');
            if (currentView) currentView.textContent = s.current_view || 'Not recorded';
            const elRisk = document.getElementById('sdRiskScore');
            const elLevel = document.getElementById('sdRiskLevel');

            if (elRisk) elRisk.textContent = sec.risk_score !== undefined ? `${sec.risk_score} / 100` : '--';
            if (elLevel) elLevel.innerHTML = `<span class="status-pill ${sec.risk_level === 'HIGH' ? 'high' : 'low'}">${escapeHtml(sec.risk_level || 'LOW')}</span>`;

            const auditBtn = document.getElementById('sessionDrawerViewAuditBtn');
            if (auditBtn) {
                auditBtn.onclick = () => {
                    drawer.classList.remove('open');
                    if (backdrop) backdrop.classList.remove('open');
                    switchView('admin-audit-logs');
                    openSessionAuditTimeline(s.identity_id, s.session_id);
                };
            }

            const revokeBtn = document.getElementById('sessionDrawerRevokeBtn');
            if (revokeBtn) {
                if (!s.duration_running) {
                    revokeBtn.disabled = true;
                    revokeBtn.style.opacity = '0.5';
                    revokeBtn.textContent = 'Session Inactive';
                } else {
                    revokeBtn.disabled = false;
                    revokeBtn.style.opacity = '1';
                    revokeBtn.textContent = 'Revoke Session';
                    revokeBtn.onclick = async () => {
                        if (confirm(`Are you sure you want to revoke active session ${s.session_id}? This will immediately invalidate the session.`)) {
                            await revokeAdminSession(s.session_id);
                            drawer.classList.remove('open');
                            if (backdrop) backdrop.classList.remove('open');
                        }
                    };
                }
            }

            drawer.classList.add('open');
            if (backdrop) backdrop.classList.add('open');
        }
    } catch (e) {
        console.warn('[Session Detail Fetch Error]:', e);
    }
}

async function revokeAdminSession(sessionId) {
    try {
        const res = await fetch(`/api/v1/admin/sessions/${sessionId}/revoke`, {
            method: 'POST',
            headers: { ...getAuthorizationHeader(), 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'Admin console manual revocation' })
        });
        if (res.ok) {
            loadAdminSessionControl();
        } else {
            alert('Failed to revoke session.');
        }
    } catch (e) {
        console.warn('[Session Revoke Error]:', e);
    }
}

// ── PER-IDENTITY AUDIT LOGS IMPLEMENTATION ──────────────────────────────────
let currentAuditIdentityId = null;
let currentAuditSessionId = null;

async function loadAdminAuditLogs(searchQuery = '') {
    const identitiesLevel = document.getElementById('auditLevelIdentities');
    const detailLevel = document.getElementById('auditLevelIdentityDetail');
    const timelineLevel = document.getElementById('auditLevelSessionTimeline');

    if (identitiesLevel) identitiesLevel.style.display = 'block';
    if (detailLevel) detailLevel.style.display = 'none';
    if (timelineLevel) timelineLevel.style.display = 'none';

    const listContainer = document.getElementById('auditIdentitiesList');
    if (!listContainer) return;

    try {
        const url = `/api/v1/admin/audit/identities?search=${encodeURIComponent(searchQuery)}`;
        const res = await fetch(url, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const identities = data.identities || [];

            if (identities.length === 0) {
                listContainer.innerHTML = `<div class="card" style="text-align: center; color: var(--text-muted); padding: 40px;">No enrolled identities found matching criteria.</div>`;
                return;
            }

            listContainer.innerHTML = identities.map(idnt => {
                const initials = (idnt.full_name || 'U').split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
                const lastLoginStr = idnt.last_login_formatted || (idnt.last_login ? new Date(idnt.last_login).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Never');
                const lastActStr = idnt.last_activity_formatted || (idnt.last_activity ? new Date(idnt.last_activity).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'None');

                return `
                    <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
                            <div style="display: flex; gap: 14px; align-items: center;">
                                <div style="width: 44px; height: 44px; border-radius: 50%; background: var(--surface-border); display: flex; align-items: center; justify-content: center; font-weight: 700; color: var(--accent-cyan); font-size: 1rem;">
                                    ${initials}
                                </div>
                                <div>
                                    <div style="display: flex; gap: 8px; align-items: center;">
                                        <strong style="font-size: 0.95rem; color: #fff;">${escapeHtml(idnt.email)}</strong>
                                        <span class="status-pill low">${escapeHtml(idnt.role || 'Staff')}</span>
                                    </div>
                                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 2px;">
                                        ${escapeHtml(idnt.full_name || '')} • ${escapeHtml(idnt.organization_name || 'NovaCare Medical Center')} • <span style="font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(idnt.identity_id)}</span>
                                    </div>
                                </div>
                            </div>
                            <div>
                                <button class="btn btn-secondary btn-view-identity-audit" data-identity-id="${escapeHtml(idnt.identity_id)}" style="padding: 7px 16px; font-size: 0.82rem;">
                                    View Audit
                                </button>
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; background: var(--bg-primary); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--surface-border);">
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Total Sessions</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: #fff; margin-top: 2px;">${idnt.total_sessions || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Successful Logins</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: var(--success-emerald); margin-top: 2px;">${idnt.successful_logins || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Failed Auth</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: ${(idnt.failed_auth > 0 ? 'var(--danger-red)' : 'var(--text-secondary)')}; margin-top: 2px;">${idnt.failed_auth || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Trusted Devices</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: var(--accent-cyan); margin-top: 2px;">${idnt.trusted_devices_count || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Untrusted Devs</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: ${(idnt.untrusted_devices_count > 0 ? 'var(--warning-amber)' : 'var(--text-secondary)')}; margin-top: 2px;">${idnt.untrusted_devices_count || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Known Networks</div>
                                <div style="font-size: 1.05rem; font-weight: 700; color: #fff; margin-top: 2px;">${idnt.known_networks_count || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Last Login</div>
                                <div style="font-size: 0.82rem; font-family: var(--font-mono); color: var(--text-secondary); margin-top: 4px;">${escapeHtml(lastLoginStr)}</div>
                            </div>
                            <div>
                                <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Last Activity</div>
                                <div style="font-size: 0.82rem; font-family: var(--font-mono); color: var(--text-secondary); margin-top: 4px;">${escapeHtml(lastActStr)}</div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

            listContainer.querySelectorAll('.btn-view-identity-audit').forEach(btn => {
                btn.addEventListener('click', () => {
                    const idntId = btn.getAttribute('data-identity-id');
                    openIdentityAuditView(idntId);
                });
            });
        }
    } catch (e) {
        console.warn('[Audit Identities Fetch Error]:', e);
    }
}

async function openIdentityAuditView(identityId) {
    if (!identityId) return;
    currentAuditIdentityId = identityId;

    const identitiesLevel = document.getElementById('auditLevelIdentities');
    const detailLevel = document.getElementById('auditLevelIdentityDetail');
    const timelineLevel = document.getElementById('auditLevelSessionTimeline');

    if (identitiesLevel) identitiesLevel.style.display = 'none';
    if (detailLevel) detailLevel.style.display = 'block';
    if (timelineLevel) timelineLevel.style.display = 'none';

    try {
        const res = await fetch(`/api/v1/admin/audit/identity/${identityId}/sessions`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const idnt = data.identity || {};
            const summary = data.summary || {};
            const sessions = data.sessions || [];
            const recentCtx = data.recent_connections || [];

            const summaryCard = document.getElementById('auditIdentitySummaryCard');
            if (summaryCard) {
                summaryCard.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; margin-bottom: 14px;">
                        <div>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <h2 style="font-size: 1.15rem; font-weight: 700; color: #fff; margin: 0;">${escapeHtml(idnt.email)}</h2>
                                <span class="status-pill low">${escapeHtml(idnt.role || 'Staff')}</span>
                            </div>
                            <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 4px;">
                                ${escapeHtml(idnt.full_name || '')} • ${escapeHtml(idnt.organization_name || 'NovaCare Medical Center')} • Identity ID: <span style="font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(idnt.identity_id)}</span>
                            </div>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; background: var(--bg-primary); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--surface-border);">
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Total Sessions</div><div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${summary.total_sessions || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Successful Logins</div><div style="font-size: 1.1rem; font-weight: 700; color: var(--success-emerald);">${summary.successful_logins || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Failed Auth</div><div style="font-size: 1.1rem; font-weight: 700; color: ${(summary.failed_auth > 0 ? 'var(--danger-red)' : 'var(--text-secondary)')};">${summary.failed_auth || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Trusted Devices</div><div style="font-size: 1.1rem; font-weight: 700; color: var(--accent-cyan);">${summary.trusted_devices_count || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Untrusted Devs</div><div style="font-size: 1.1rem; font-weight: 700; color: ${(summary.untrusted_devices_count > 0 ? 'var(--warning-amber)' : 'var(--text-secondary)')};">${summary.untrusted_devices_count || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Known Networks</div><div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${summary.known_networks_count || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Blocked Actions</div><div style="font-size: 1.1rem; font-weight: 700; color: ${(summary.blocked_actions > 0 ? 'var(--danger-red)' : 'var(--text-secondary)')};">${summary.blocked_actions || 0}</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">High Risk Events</div><div style="font-size: 1.1rem; font-weight: 700; color: ${(summary.high_risk_events > 0 ? 'var(--danger-red)' : 'var(--text-secondary)')};">${summary.high_risk_events || 0}</div></div>
                    </div>
                `;
            }

            const recentContainer = document.getElementById('auditIdentityRecentContext');
            if (recentContainer) {
                if (recentCtx.length === 0) {
                    recentContainer.innerHTML = `<div style="grid-column: 1/-1; color: var(--text-muted); font-size: 0.8rem;">No connection baseline established yet.</div>`;
                } else {
                    recentContainer.innerHTML = recentCtx.map(c => `
                        <div style="background: var(--bg-primary); padding: 10px 12px; border-radius: var(--radius-sm); border: 1px solid var(--surface-border); font-size: 0.8rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-family: var(--font-mono); color: #fff; font-weight: 600;">${escapeHtml(c.ip_address)}</span>
                                <span class="status-pill low">${escapeHtml(c.network_status || 'KNOWN')}</span>
                            </div>
                            <div style="color: var(--text-secondary); margin-top: 4px; font-size: 0.75rem;">${escapeHtml(c.device || 'Desktop')} • <span class="status-pill ${c.device_trust === 'TRUSTED' ? 'low' : 'warning'}" style="padding: 1px 4px; font-size: 0.68rem;">${escapeHtml(c.device_trust || 'UNKNOWN')}</span></div>
                            <div style="color: var(--text-muted); font-size: 0.7rem; margin-top: 4px;">Last: ${c.last_seen ? new Date(c.last_seen).toLocaleDateString() : 'Recent'}</div>
                        </div>
                    `).join('');
                }
            }

            renderIdentitySessionsTable(sessions, identityId);
        }
    } catch (e) {
        console.warn('[Identity Sessions Fetch Error]:', e);
    }
}

function renderIdentitySessionsTable(sessions, identityId) {
    const tableBody = document.querySelector('#auditIdentitySessionsTable tbody');
    if (!tableBody) return;

    if (sessions.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 32px;">No historical sessions recorded for this identity.</td></tr>`;
        return;
    }

    tableBody.innerHTML = sessions.map(s => {
        const trustPill = `<span class="status-pill ${s.device_trust === 'TRUSTED' ? 'low' : 'warning'}">${escapeHtml(s.device_trust || 'UNKNOWN')}</span>`;
        const netPill = `<span class="status-pill ${(s.network_status === 'KNOWN' || s.network_status === 'LOCAL' || s.network_status === 'PRIVATE NETWORK') ? 'low' : 'warning'}">${escapeHtml(s.network_status || 'UNKNOWN')}</span>`;
        const riskPill = `<span class="status-pill ${s.risk_level === 'HIGH' ? 'high' : 'low'}">${s.risk_score || 0} ${escapeHtml(s.risk_level || 'LOW')}</span>`;
        const statusPill = `<span class="status-pill ${s.status === 'ACTIVE' ? 'verified' : (s.status === 'BLOCKED' ? 'block' : 'warning')}">${escapeHtml(s.status)}</span>`;

        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan); font-weight: 600;">${escapeHtml(s.session_id)}</td>
                <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(s.login_time_formatted || 'Recent')}</td>
                <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-secondary);">${sessionDurationNode(s)}</td>
                <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(s.device_formatted || 'Chrome • Windows')}</td>
                <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(s.ip_address_display || s.ip_address)}</td>
                <td>${netPill}</td>
                <td>${trustPill}</td>
                <td>${riskPill}</td>
                <td>${statusPill}</td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm btn-session-timeline" data-identity-id="${escapeHtml(identityId)}" data-session-id="${escapeHtml(s.session_id)}" style="padding: 4px 10px; font-size: 0.76rem;">View Timeline</button>
                </td>
            </tr>
        `;
    }).join('');

    tableBody.querySelectorAll('.btn-session-timeline').forEach(btn => {
        btn.addEventListener('click', () => {
            const iid = btn.getAttribute('data-identity-id');
            const sid = btn.getAttribute('data-session-id');
            openSessionAuditTimeline(iid, sid);
        });
    });
}

async function openSessionAuditTimeline(identityId, sessionId) {
    if (!identityId || !sessionId) return;
    currentAuditIdentityId = identityId;
    currentAuditSessionId = sessionId;

    const identitiesLevel = document.getElementById('auditLevelIdentities');
    const detailLevel = document.getElementById('auditLevelIdentityDetail');
    const timelineLevel = document.getElementById('auditLevelSessionTimeline');

    if (identitiesLevel) identitiesLevel.style.display = 'none';
    if (detailLevel) detailLevel.style.display = 'none';
    if (timelineLevel) timelineLevel.style.display = 'block';

    try {
        const res = await fetch(`/api/v1/admin/audit/identity/${identityId}/session/${sessionId}/timeline`, { headers: getAuthorizationHeader() });
        if (res.ok) {
            const data = await res.json();
            const s = data.session_info || data.session || {};
            const authTimeline = data.authentication_timeline || [];
            const actTimeline = data.activity_timeline || [];

            const activeLink = document.getElementById('auditViewActiveSessionLink');
            if (activeLink) {
                if (s.status === 'ACTIVE') {
                    activeLink.style.display = 'inline-flex';
                    activeLink.onclick = () => {
                        switchView('admin-session-control');
                    };
                } else {
                    activeLink.style.display = 'none';
                }
            }

            const headerCard = document.getElementById('auditSessionHeaderCard');
            if (headerCard) {
                headerCard.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 14px; margin-bottom: 14px;">
                        <div>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <h2 style="font-size: 1.1rem; font-weight: 700; color: #fff; margin: 0;">${escapeHtml(s.email)}</h2>
                                <span class="status-pill low">${escapeHtml(s.role || 'Staff')}</span>
                                <span class="status-pill ${s.status === 'ACTIVE' ? 'verified' : 'warning'}">${escapeHtml(s.status)}</span>
                            </div>
                            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px;">
                                Session ID: <strong style="font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(s.session_id)}</strong> • Identity ID: <span style="font-family: var(--font-mono);">${escapeHtml(identityId)}</span>
                            </div>
                        </div>
                        <div>
                            <span class="status-pill ${s.risk_level === 'HIGH' ? 'high' : 'low'}" style="font-size: 0.82rem; padding: 4px 10px;">Risk Score: ${s.risk_score || 0} (${escapeHtml(s.risk_level || 'LOW')})</span>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; background: var(--bg-primary); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--surface-border); font-size: 0.8rem;">
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Login Time</div>
                            <div style="font-family: var(--font-mono); color: #fff; margin-top: 2px;">${escapeHtml(sessionLocalTime(s.login_time_iso))}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Logout Time</div>
                            <div style="font-family: var(--font-mono); color: var(--text-secondary); margin-top: 2px;">${escapeHtml(s.logout_time_iso ? sessionLocalTime(s.logout_time_iso) : (s.duration_running ? 'Session running' : 'Not recorded'))}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Duration</div>
                            <div style="font-family: var(--font-mono); color: var(--accent-cyan); margin-top: 2px;">${sessionDurationNode(s)}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">IP Address</div>
                            <div style="font-family: var(--font-mono); color: #fff; margin-top: 2px;">${escapeHtml(s.ip_masked || 'Unavailable')}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Network Status</div>
                            <div style="margin-top: 2px;"><span class="status-pill ${(s.network_status === 'KNOWN' || s.network_status === 'LOCAL' || s.network_status === 'PRIVATE NETWORK') ? 'low' : 'warning'}">${escapeHtml(s.network_status || 'UNKNOWN')}</span></div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Device</div>
                            <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(s.device_formatted || 'Desktop Browser')}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Device Trust</div>
                            <div style="margin-top: 2px;"><span class="status-pill ${s.device_trust === 'TRUSTED' ? 'low' : 'warning'}">${escapeHtml(s.device_trust || 'UNKNOWN')}</span></div>
                        </div>
                    </div>
                `;
            }

            const authList = document.getElementById('auditAuthTimelineList');
            if (authList) {
                if (authTimeline.length === 0) {
                    authList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 24px; font-size: 0.8rem;">No authentication stage logs recorded for this session.</div>`;
                } else {
                    authList.innerHTML = authTimeline.map(ev => {
                        const timeStr = ev.timestamp ? sessionLocalTime(ev.timestamp) : 'Time not recorded';
                        const isSuccess = ev.decision === 'ALLOW' || ev.result === 'SUCCESS' || ev.result === 'ALLOW';
                        const badgeColor = isSuccess ? 'var(--success-emerald)' : (['DENY','BLOCK','FAILED'].includes(ev.decision) ? 'var(--danger-red)' : 'var(--text-muted)');
                        const decText = isSuccess ? 'ALLOW' : (ev.decision || ev.result || 'RECORDED');

                        return `
                            <div class="timeline-entry" style="padding-bottom: 16px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-family: var(--font-mono); font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(timeStr)}</span>
                                    <span style="font-size: 0.72rem; font-weight: 700; color: ${badgeColor};">${escapeHtml(decText)}</span>
                                </div>
                                <div style="font-size: 0.84rem; font-weight: 600; color: #fff; margin-top: 3px;">
                                    ${escapeHtml(ev.action || ev.event_type)}
                                </div>
                                ${ev.details ? `<div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(typeof ev.details === 'string' ? ev.details : JSON.stringify(ev.details))}</div>` : ''}
                            </div>
                        `;
                    }).join('');
                }
            }

            const actList = document.getElementById('auditActivityTimelineList');
            const actCount = document.getElementById('auditActivityEventCount');
            if (actCount) actCount.textContent = `${actTimeline.length} Events`;
            if (actList) {
                if (actTimeline.length === 0) {
                    actList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 24px; font-size: 0.8rem;">No post-login activity recorded for this session yet.</div>`;
                } else {
                    actList.innerHTML = actTimeline.map(ev => {
                        const timeStr = ev.timestamp ? sessionLocalTime(ev.timestamp) : 'Time not recorded';
                        return `
                            <div class="timeline-entry" style="padding-bottom: 16px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-family: var(--font-mono); font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(timeStr)}</span>
                                    <span style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(ev.resource || 'SYSTEM')}</span>
                                </div>
                                <div style="font-size: 0.84rem; font-weight: 600; color: var(--accent-cyan); margin-top: 3px;">
                                    ${escapeHtml(ev.action || ev.event_type)}
                                </div><div class="session-monitor-subtext">${escapeHtml(ev.details || '')}</div>
                            </div>
                        `;
                    }).join('');
                }
            }
        }
    } catch (e) {
        console.warn('[Session Timeline Fetch Error]:', e);
    }
}

function trackSecurityViewActivity(viewId) {
    if (!viewId) return;
    fetch('/api/v1/session/activity', {
        method: 'POST',
        headers: { ...getAuthorizationHeader(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: 'VIEW_SECTION', has_activity: true, details: { resource: viewId } })
    }).catch(() => {});
}

// Dynamic error rows use module-scoped loaders, including after repeated failures.
document.addEventListener('click', event => {
    const button = event.target.closest?.('[data-dashboard-retry]');
    if (!button || button.disabled) return;
    const viewId = button.dataset.dashboardRetry;
    const allowed = ['admin-organizations', 'admin-identity-sec', 'admin-threat-investigation',
        'admin-risk-engine', 'admin-integrations', 'admin-accounts'];
    if (allowed.includes(viewId)) loadViewData(viewId);
});
