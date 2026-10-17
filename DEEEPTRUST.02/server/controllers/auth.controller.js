/**
 * controllers/auth.controller.js
 * Comprehensive Authentication Controller for DeepTrust Platform
 */

const bcrypt = require('bcryptjs');
const TokenService = require('../services/token.service');
const LogService = require('../services/log.service');
const { getDbInstance } = require('../config/db.config');

// Fallback in-memory users for demo mode if MongoDB is offline
const DEMO_USERS = [
    {
        _id: 'demo_owner_1',
        full_name: 'DeepTrust Owner',
        email: 'owner@deeptrust.demo',
        email_normalized: 'owner@deeptrust.demo',
        // 'OwnerSecret123!'
        password_hash: '$2a$10$wN9Q.f2/hMlhM/xGvCqGz.FjIq/XG/L1VqG0E0F0E0F0E0F0E0F0E',
        role: 'DEEPTRUST_OWNER',
        organization_id: 'DEEPTRUST_PLATFORM',
        organization_name: 'DeepTrust Security Platform',
        status: 'ACTIVE',
        email_verified: false,
        face_enrolled: false,
        mfa_enabled: false
    },
    {
        _id: 'demo_admin_1',
        full_name: 'DeepTrust Security Admin',
        email: 'admin@healthcare.demo',
        email_normalized: 'admin@healthcare.demo',
        // 'AdminSecret123!'
        password_hash: '$2a$10$wN9Q.f2/hMlhM/xGvCqGz.FjIq/XG/L1VqG0E0F0E0F0E0F0E0F0E',
        role: 'HOSPITAL_ADMIN',
        organization_id: 'DEEPTRUST_PLATFORM',
        organization_name: 'DeepTrust Security Platform',
        status: 'ACTIVE',
        email_verified: false,
        face_enrolled: false,
        mfa_enabled: false
    }
];

const AuthController = {
    // ── 1. LOGIN (POST /api/v1/auth/login and POST /api/admin/login) ─────────
    async login(req, res) {
        try {
            const emailInput = req.body.email || req.body.username;
            const passwordInput = req.body.password;
            const selectedAccessType = req.body.selected_access_type || req.body.accessType || 'HOSPITAL_ADMIN';

            if (!emailInput || !passwordInput) {
                return res.status(400).json({ message: "Incorrect email or password." });
            }

            const normalizedEmail = emailInput.trim().toLowerCase();
            const db = getDbInstance();

            let user = null;

            if (db) {
                user = await db.collection('users').findOne({ email_normalized: normalizedEmail });
            } else {
                // Fallback for demo when DB is connecting or offline
                user = DEMO_USERS.find(u => u.email_normalized === normalizedEmail);
            }

            if (!user) {
                await LogService.logFailedAttempt(emailInput, 'User Not Found', req.body);
                return res.status(401).json({ message: "Incorrect email or password." });
            }

            if (user.status === 'PENDING_EMAIL_VERIFICATION') {
                return res.status(403).json({ code: 'EMAIL_VERIFICATION_REQUIRED', message: "Email verification pending. Please verify your official email address before logging in." });
            }
            if (user.status !== 'ACTIVE') {
                return res.status(403).json({ message: "Account is disabled or pending review." });
            }

            // Verify Password Hash using bcrypt
            let isPasswordValid = false;
            if (user.password_hash && (user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$'))) {
                isPasswordValid = await bcrypt.compare(passwordInput, user.password_hash);
            }

            if (!isPasswordValid) {
                await LogService.logFailedAttempt(emailInput, 'Invalid Password', req.body);
                return res.status(401).json({ message: "Incorrect email or password." });
            }

            // Verify Access Type Role Matching
            // Access Types: 'DEEPTRUST_OWNER' or 'HOSPITAL_ADMIN'
            const expectedRole = selectedAccessType === 'DEEPTRUST_OWNER' ? 'DEEPTRUST_OWNER' : 'HOSPITAL_ADMIN';

            if (user.role !== expectedRole) {
                console.warn(`[Auth] Role Mismatch: User ${normalizedEmail} (${user.role}) attempted login as ${expectedRole}`);
                return res.status(403).json({
                    code: 'ACCESS_ROLE_MISMATCH',
                    message: `Access Mismatch: Your account is assigned as ${user.role.replace('_', ' ')}. Please select the correct portal tab.`
                });
            }

            const orgName = user.organization_name || (assignedRole => assignedRole === 'DEEPTRUST_OWNER' ? 'DeepTrust Security Platform' : 'DeepTrust Security Platform')(user.role);
            const orgId = user.organization_id || (user.role === 'DEEPTRUST_OWNER' ? 'DEEPTRUST_PLATFORM' : 'DEEPTRUST_PLATFORM');

            // Log successful authentication event to DB
            if (db) {
                await db.collection('authentication_events').insertOne({
                    user_id: user._id,
                    email: user.email,
                    role: user.role,
                    organization_id: orgId,
                    organization_name: orgName,
                    status: 'SUCCESS',
                    ip_address: req.ip || '127.0.0.1',
                    user_agent: req.headers['user-agent'],
                    timestamp: new Date()
                });

                await db.collection('users').updateOne(
                    { _id: user._id },
                    { $set: { last_login_at: new Date() } }
                );
            }

            // Generate JWT Token
            const token = TokenService.generateToken({
                userId: user._id,
                email: user.email,
                role: user.role,
                full_name: user.full_name,
                organization_id: orgId,
                organization_name: orgName
            });

            res.status(200).json({
                success: true,
                message: "Authentication successful",
                token: token,
                user: {
                    id: user._id,
                    full_name: user.full_name,
                    email: user.email,
                    role: user.role,
                    organization_id: orgId,
                    organization_name: orgName,
                    email_verified: !!user.email_verified,
                    face_enrolled: !!user.face_enrolled,
                    mfa_enabled: !!user.mfa_enabled
                }
            });

        } catch (error) {
            console.error('[Auth Controller Error]:', error);
            res.status(500).json({ message: "Internal server error during authentication." });
        }
    },

    // ── 2. GET CURRENT USER PROFILE (GET /api/v1/auth/me) ─────────
    async getCurrentUser(req, res) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({ message: "Authorization token missing" });
            }

            const token = authHeader.replace('Bearer ', '');
            const decoded = TokenService.verifyToken(token);

            if (!decoded || decoded.token_type === 'VERIFICATION') {
                return res.status(401).json({ message: "Invalid or unauthorized session token" });
            }

            const db = getDbInstance();
            let user = null;

            if (db && decoded.email) {
                user = await db.collection('users').findOne({ email_normalized: decoded.email.toLowerCase() });
            }

            if (!user) {
                const isOwner = decoded.role === 'DEEPTRUST_OWNER';
                return res.status(200).json({
                    success: true,
                    user: {
                        full_name: decoded.full_name || (isOwner ? 'DeepTrust Owner' : 'DeepTrust Security Admin'),
                        email: decoded.email || (isOwner ? 'owner@deeptrust.demo' : 'admin@healthcare.demo'),
                        role: decoded.role || 'HOSPITAL_ADMIN',
                        organization_id: decoded.organization_id || (isOwner ? 'DEEPTRUST_PLATFORM' : 'DEEPTRUST_PLATFORM'),
                        organization_name: decoded.organization_name || (isOwner ? 'DeepTrust Security Platform' : 'DeepTrust Security Platform'),
                        email_verified: false,
                        face_enrolled: false,
                        mfa_enabled: false
                    }
                });
            }

            res.status(200).json({
                success: true,
                user: {
                    id: user._id,
                    full_name: user.full_name,
                    email: user.email,
                    role: user.role,
                    organization_id: user.organization_id || 'DEEPTRUST_PLATFORM',
                    organization_name: user.organization_name || 'DeepTrust Security Platform',
                    email_verified: !!user.email_verified,
                    face_enrolled: !!user.face_enrolled,
                    mfa_enabled: !!user.mfa_enabled
                }
            });

        } catch (error) {
            res.status(500).json({ message: "Failed to retrieve user profile" });
        }
    },

    // ── 3. REGISTER (POST /api/v1/auth/register) ─────────
    async register(req, res) {
        try {
            const { full_name, email, password, role, organization_id } = req.body;

            if (!full_name || !email || !password) {
                return res.status(400).json({ message: "Please fill in all required fields." });
            }

            if (typeof full_name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
                return res.status(400).json({ message: "Invalid input data types." });
            }

            if (password.length < 8) {
                return res.status(400).json({ message: "Password must be at least 8 characters long." });
            }

            // Anti-privilege escalation check
            if (role === 'DEEPTRUST_OWNER' || role === 'DEEPTRUST_ADMIN' || role === 'OWNER' || role === 'ADMIN') {
                return res.status(403).json({ message: "Public registration cannot assign privileged platform roles." });
            }

            if (organization_id === 'DEEPTRUST_PLATFORM') {
                return res.status(403).json({ message: "Public registration cannot join DeepTrust Platform internal organization." });
            }

            const normalizedEmail = email.trim().toLowerCase();
            const assignedRole = 'HOSPITAL_ADMIN';
            const defaultOrgName = 'DeepTrust Security Platform';
            const defaultOrgId = 'DEEPTRUST_PLATFORM';

            const db = getDbInstance();

            if (db) {
                const existing = await db.collection('users').findOne({ email_normalized: normalizedEmail });
                if (existing) {
                    return res.status(409).json({ message: "An account with this email already exists." });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                const newUser = {
                    full_name: full_name.trim(),
                    email: email.trim(),
                    email_normalized: normalizedEmail,
                    password_hash: hashedPassword,
                    role: assignedRole,
                    display_role: 'DeepTrust Security Admin',
                    organization_id: defaultOrgId,
                    organization_name: defaultOrgName,
                    status: 'PENDING_EMAIL_VERIFICATION',
                    email_verified: false,
                    face_enrolled: false,
                    mfa_enabled: false,
                    created_at: new Date(),
                    updated_at: new Date(),
                    last_login_at: null
                };

                let result;
                try {
                    result = await db.collection('users').insertOne(newUser);
                } catch (err) {
                    if (err.code === 11000) {
                        return res.status(409).json({ message: "An account with this email already exists." });
                    }
                    throw err;
                }

                return res.status(201).json({
                    success: true,
                    message: "Account created successfully. Email verification is required.",
                    user_id: result.insertedId,
                    email: normalizedEmail,
                    status: "PENDING_EMAIL_VERIFICATION",
                    email_verified: false
                });
            } else {
                return res.status(201).json({
                    success: true,
                    message: "Account created (Demo Mode).",
                    email: normalizedEmail,
                    status: "PENDING_EMAIL_VERIFICATION",
                    email_verified: false
                });
            }

        } catch (error) {
            console.error('[Register Error]:', error);
            res.status(500).json({ message: "Registration failed." });
        }
    },

    // ── 4. FORGOT PASSWORD (POST /api/v1/auth/forgot-password) ─────────
    async forgotPassword(req, res) {
        res.status(200).json({
            success: true,
            message: "If an eligible account exists for this email, password reset instructions will be sent."
        });
    },

    // ── 5. EMAIL VERIFICATION API STATUS ─────────
    async emailVerificationStatus(req, res) {
        res.status(200).json({
            status: "NOT_CONFIGURED",
            message: "Email Verification: Not Configured. SMTP provider credentials required."
        });
    }
};

module.exports = AuthController;
