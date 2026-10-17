const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const LoginAttempt = require('../models/LoginAttempt');

function calculateRisk({ user, ipAddress, deviceFingerprint, failedAttempts }) {
  const newIp = user.lastLoginIp && user.lastLoginIp !== ipAddress ? 75 : 15;
  const newDevice = user.lastDeviceFingerprint && user.lastDeviceFingerprint !== deviceFingerprint ? 80 : 15;
  const suspiciousLocation = user.lastLoginIp && user.lastLoginIp !== ipAddress ? 70 : 20;
  const failedFactor = Math.min(100, failedAttempts * 25);

  const risk = (newDevice * 0.3) + (newIp * 0.25) + (suspiciousLocation * 0.2) + (failedFactor * 0.25);
  return Math.round(Math.max(0, Math.min(100, risk)));
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES || '1d' }
  );
}

const crypto = require('crypto');

exports.register = async (req, res) => {
  try {
    const { fullName, email, password, organization, role } = req.body;
    if (!fullName || !email || !password || !role) {
      return res.status(400).json({ ok: false, message: 'Missing required fields' });
    }
    
    // Strict domain checking
    if (role === 'ADMIN' && !email.endsWith('@deeptrust.com')) {
      return res.status(403).json({ ok: false, message: 'ADMIN email must end with @deeptrust.com' });
    }
    if (role === 'USER' && !email.endsWith('@gmail.com')) {
      return res.status(403).json({ ok: false, message: 'USER email must end with @gmail.com' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ ok: false, message: 'Email already exists' });
    }

    // Generate secure DeepTrust ID
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    const prefix = role === 'ADMIN' ? 'DTA-ADM' : 'DTA-USR';
    const deepTrustId = `${prefix}-${randomHex}`;

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      fullName,
      email: email.toLowerCase(),
      passwordHash,
      organization,
      role,
      deepTrustId,
    });

    return res.status(201).json({ ok: true, userId: user._id, deepTrustId });
  } catch (error) {
    console.error("Register Error:", error);
    return res.status(500).json({ ok: false, message: 'Registration failed' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password, deviceFingerprint, rememberMe } = req.body;
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';

    const user = await User.findOne({ email: String(email || '').toLowerCase() });
    if (!user) {
      return res.status(401).json({ ok: false, message: 'Invalid credentials' });
    }

    if (user.isBlocked) {
      return res.status(403).json({ ok: false, message: 'Account blocked by administrator' });
    }

    const validPassword = await bcrypt.compare(String(password || ''), user.passwordHash);
    if (!validPassword) {
      await LoginAttempt.create({
        userId: user._id,
        ipAddress,
        deviceFingerprint,
        riskScore: 100,
        status: 'failed_credentials',
      });
      return res.status(401).json({ ok: false, message: 'Invalid credentials' });
    }

    const failedAttempts = await LoginAttempt.countDocuments({
      userId: user._id,
      status: 'failed_credentials',
      createdAt: { $gte: new Date(Date.now() - 30 * 60 * 1000) },
    });

    const riskScore = calculateRisk({ user, ipAddress, deviceFingerprint, failedAttempts });

    // Always issue a temp token for the remaining stages, rather than immediately authenticating.
    // The actual decision happens in security.controller.js after Face + Voice + Behavior.
    const tempToken = jwt.sign(
      { sub: user._id.toString(), isTemp: true, tempSessionId: crypto.randomBytes(16).toString('hex') },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({
      ok: true,
      status: 'pending_verification',
      tempToken,
      message: 'Credentials verified. Proceed to biometric stages.',
      user: {
        fullName: user.fullName,
        role: user.role
      }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: 'Login failed' });
  }
};

exports.completeFaceAuth = async (req, res) => {
  try {
    const { email, deviceFingerprint } = req.body;
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';

    const user = await User.findOne({ email: String(email || '').toLowerCase() });
    if (!user) {
      return res.status(404).json({ ok: false, message: 'User not found' });
    }

    user.lastLoginIp = ipAddress;
    user.lastDeviceFingerprint = deviceFingerprint;
    user.lastLoginAt = new Date();
    await user.save();

    await LoginAttempt.create({
      userId: user._id,
      ipAddress,
      deviceFingerprint,
      riskScore: 45,
      status: 'success',
    });

    const token = signToken(user);
    return res.json({
      ok: true,
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        role: user.role,
      },
      redirect: '/dashboard',
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: 'Face authentication failed' });
  }
};
