/**
 * middleware/auth.middleware.js
 * Zero-Trust Authentication, Session Lifecycle & RBAC Authorization Middleware
 */

const TokenService = require('../services/token.service');
const { getDbInstance } = require('../config/db.config');

const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: "Unauthorized: Missing or invalid authorization token" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = TokenService.verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
        }

        // Zero-Trust: Strict token type isolation (Pre-auth tokens cannot access protected APIs)
        if (decoded.token_type !== 'ACCESS') {
            return res.status(403).json({ success: false, message: "Forbidden: Pre-auth verification token cannot access protected application APIs" });
        }

        const db = getDbInstance();
        if (!db) return res.status(503).json({ success: false, message: "Authentication store unavailable" });
        let sess, dbUser, policy;
        try {
            if (!decoded.session_id || !decoded.sub || !decoded.email) {
                return res.status(401).json({ success: false, message: "Unauthorized: Incomplete access token" });
            }
            sess = await db.collection('auth_sessions').findOne({
                $or: [{ _id: decoded.session_id }, { session_id: decoded.session_id }]
            });
            if (!sess || sess.revoked || !['ACTIVE', 'IDLE'].includes(sess.status) ||
                String(sess.identity_id || sess.user_id || '') !== String(decoded.sub) ||
                String(sess.email || '').toLowerCase() !== decoded.email.toLowerCase()) {
                return res.status(401).json({ success: false, message: "Unauthorized: Session is missing, ended or belongs to another account" });
            }
            policy = await db.collection('security_policies').findOne({ organization_id: sess.organization_id }) || {};
            const seconds = value => value instanceof Date ? value.getTime() / 1000 : Number(value || 0);
            const login = seconds(sess.login_at || sess.created_at);
            const last = seconds(sess.last_activity_at || sess.login_at || sess.created_at);
            const idle = Math.max(60, Math.min(86400, Number(policy.session_idle_timeout) || 1800));
            const absolute = Math.max(60, Math.min(86400, Number(policy.session_absolute_timeout) || 28800));
            const deadline = Math.min(last + idle, login + absolute, seconds(sess.expires_at) || login + absolute);
            if (!Number.isFinite(deadline) || Date.now() / 1000 >= deadline) {
                return res.status(401).json({ success: false, message: "Unauthorized: Session expired" });
            }
            const email = decoded.email.toLowerCase();
            for (const collection of ['users', 'deeptrust_admins', 'healthcare_admins']) {
                dbUser = await db.collection(collection).findOne({ email_normalized: email });
                if (dbUser) break;
            }
        } catch (_) {
            return res.status(503).json({ success: false, message: "Authentication store unavailable" });
        }
        if (!dbUser || String(dbUser._id) !== String(decoded.sub)) {
            return res.status(401).json({ success: false, message: "Unauthorized: User account not found" });
        }
        if (dbUser.organization_id !== sess.organization_id) {
            return res.status(401).json({ success: false, message: 'Unauthorized: Session organisation changed' });
        }
        const status = String(dbUser.status || 'ACTIVE').toUpperCase();
        if (status === 'PENDING_EMAIL_VERIFICATION') {
            return res.status(403).json({ success: false, code: 'EMAIL_VERIFICATION_REQUIRED', message: "Forbidden: Email verification pending" });
        }
        if (['PENDING_MFA_SETUP', 'PENDING_SECURITY_ENROLLMENT'].includes(status)) {
            return res.status(403).json({ success: false, code: 'MFA_SETUP_REQUIRED', message: "Forbidden: Security enrollment pending" });
        }
        if (status !== 'ACTIVE' || !dbUser.role || !dbUser.organization_id) {
            return res.status(403).json({ success: false, message: "Forbidden: Account is not authorised" });
        }
        req.user = {
            userId: String(dbUser._id), email: dbUser.email, role: dbUser.role,
            organization_id: dbUser.organization_id, organization_name: dbUser.organization_name,
            status, session_id: decoded.session_id
        };

        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
    }
};

/**
 * RBAC Role Restriction Middleware
 */
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(401).json({ success: false, message: "Unauthorized: Identity not verified" });
        }
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ success: false, message: "Forbidden: Insufficient privileges for this role" });
        }
        next();
    };
};

const requireAdmin = requireRole('DEEPTRUST_OWNER', 'DEEPTRUST_ADMIN', 'OWNER', 'ADMIN');
const requireOwner = requireRole('DEEPTRUST_OWNER', 'OWNER');

/**
 * Auditor Read-Only Guard Middleware (Denies mutation operations for Auditor role)
 */
const requireNonAuditor = (req, res, next) => {
    if (req.user && req.user.role === 'AUDITOR' && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        return res.status(403).json({ success: false, message: "Forbidden: Auditor role is strictly read-only" });
    }
    next();
};

/**
 * Organization Isolation Guard Middleware
 */
const requireOrgScope = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    // DeepTrust platform administrators have platform-wide access
    if (['DEEPTRUST_OWNER', 'DEEPTRUST_ADMIN', 'OWNER', 'ADMIN'].includes(req.user.role)) {
        return next();
    }
    const requestedOrg = req.params.org_id || req.params.organization_id || req.query.organization_id || (req.body && req.body.organization_id);
    if (requestedOrg && requestedOrg !== req.user.organization_id) {
        return res.status(403).json({ success: false, message: "Forbidden: Cross-organization access denied" });
    }
    next();
};

module.exports = {
    authMiddleware,
    requireRole,
    requireAdmin,
    requireOwner,
    requireNonAuditor,
    requireOrgScope
};


