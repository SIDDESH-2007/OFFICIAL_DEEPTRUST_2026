const User = require('../models/User');
const LoginEvent = require('../models/LoginEvent');
const BehaviorEvent = require('../models/BehaviorEvent');
const RiskAssessment = require('../models/RiskAssessment');
const SecurityAlert = require('../models/SecurityAlert');
const jwt = require('jsonwebtoken');

// Helper to extract session data from temp token
const getTempSession = (req) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isTemp) return null;
    return decoded;
  } catch (e) {
    return null;
  }
};

exports.enrollFace = async (req, res) => {
  // Mock implementation. In production, this would use an actual AI service
  return res.json({ ok: false, message: 'ENGINE UNAVAILABLE' });
};

exports.enrollVoice = async (req, res) => {
  // Mock implementation
  return res.json({ ok: false, message: 'ENGINE UNAVAILABLE' });
};

exports.verifyFace = async (req, res) => {
  const session = getTempSession(req);
  if (!session) return res.status(401).json({ ok: false, message: 'Invalid session' });

  // Mock implementation for MVP upgrade as per instructions
  // In a real system, we'd compare the captured face with the enrolled one
  return res.json({ ok: true, status: 'ENGINE_UNAVAILABLE', message: 'Face Verification Engine Unavailable. Skipping.' });
};

exports.verifyVoice = async (req, res) => {
  const session = getTempSession(req);
  if (!session) return res.status(401).json({ ok: false, message: 'Invalid session' });

  return res.json({ ok: true, status: 'ENGINE_UNAVAILABLE', message: 'Voice Verification Engine Unavailable. Skipping.' });
};

exports.recordBehavior = async (req, res) => {
  const session = getTempSession(req);
  if (!session) return res.status(401).json({ ok: false, message: 'Invalid session' });

  try {
    const { typingMetrics, mouseMetrics, focusChanges, tabVisibilityChanges } = req.body;
    
    await BehaviorEvent.create({
      userId: session.sub,
      sessionId: session.tempSessionId,
      typingMetrics,
      mouseMetrics,
      focusChanges,
      tabVisibilityChanges
    });

    return res.json({ ok: true, message: 'Behavior recorded' });
  } catch (error) {
    console.error("Behavior record error:", error);
    return res.status(500).json({ ok: false, message: 'Failed to record behavior' });
  }
};

exports.calculateFinalRisk = async (req, res) => {
  const session = getTempSession(req);
  if (!session) return res.status(401).json({ ok: false, message: 'Invalid session' });

  try {
    const { deviceFingerprint } = req.body;
    const userId = session.sub;
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });

    // In a real system, we fetch past behavior, device history, etc. to compute this.
    // We will do a basic check here.
    let credentialRisk = 10;
    let deviceRisk = user.lastDeviceFingerprint && user.lastDeviceFingerprint !== deviceFingerprint ? 50 : 10;
    let behavioralRisk = 20; // Default if not enough history
    let biometricRisk = 0; // Skipped if engine unavailable
    let patternRisk = user.lastLoginIp && user.lastLoginIp !== ipAddress ? 40 : 10;

    // Fetch behavior event for this session
    const behavior = await BehaviorEvent.findOne({ sessionId: session.tempSessionId });
    if (behavior) {
       // Simple heuristic: too many focus changes or tab changes -> higher risk
       if (behavior.focusChanges > 5 || behavior.tabVisibilityChanges > 2) {
           behavioralRisk += 40;
       }
    }

    const finalRiskScore = Math.min(100, credentialRisk + deviceRisk + behavioralRisk + biometricRisk + patternRisk);
    
    let riskLevel = 'LOW';
    let decision = 'ALLOW';

    if (finalRiskScore >= 80) {
      riskLevel = 'CRITICAL';
      decision = 'BLOCK';
    } else if (finalRiskScore >= 60) {
      riskLevel = 'HIGH';
      decision = 'BLOCK';
    } else if (finalRiskScore >= 30) {
      riskLevel = 'MEDIUM';
      decision = 'CHALLENGE';
    }

    const riskAssessment = await RiskAssessment.create({
      userId,
      sessionId: session.tempSessionId,
      credentialRisk,
      deviceRisk,
      behavioralRisk,
      biometricRisk,
      patternRisk,
      finalRiskScore,
      riskLevel,
      decision
    });

    const loginEvent = await LoginEvent.create({
      userId,
      ipAddress,
      deviceHash: deviceFingerprint,
      riskScore: finalRiskScore,
      riskLevel,
      loginResult: decision === 'ALLOW' ? 'SUCCESS' : (decision === 'CHALLENGE' ? 'CHALLENGED' : 'BLOCKED'),
    });

    if (decision === 'BLOCK') {
      await SecurityAlert.create({
         userId,
         eventType: 'HIGH_RISK_LOGIN_ATTEMPT',
         severity: 'CRITICAL',
         message: 'Blocked a critical risk login attempt',
         riskScore: finalRiskScore
      });
      return res.status(403).json({ ok: false, message: 'Login blocked due to high security risk', riskAssessment });
    }

    if (decision === 'CHALLENGE') {
      return res.status(401).json({ ok: false, message: 'Additional verification required (Challenge)', riskAssessment });
    }

    // Success
    user.lastLoginIp = ipAddress;
    user.lastDeviceFingerprint = deviceFingerprint;
    user.lastLoginAt = new Date();
    await user.save();

    const finalToken = jwt.sign(
      { sub: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES || '1d' }
    );

    return res.json({
      ok: true,
      status: 'success',
      token: finalToken,
      user: {
        id: user._id,
        fullName: user.fullName,
        role: user.role,
      },
      riskAssessment,
      redirect: '/dashboard',
    });
  } catch (error) {
    console.error("Risk calculation error:", error);
    return res.status(500).json({ ok: false, message: 'Risk calculation failed' });
  }
};
