/**
 * riskEngine.js
 * Deterministic enterprise login risk policy.
 *
 * Rules:
 * - Risk is calculated from concrete authentication signals only.
 * - No timer-based increments and no random factors.
 * - Decision engine remains isolated from page/UI side effects.
 */

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const toNumber = (value, fallback = 0) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
};

export const faceTrustTier = (faceScore) => {
    const score = clamp(toNumber(faceScore, 85), 0, 100);
    if (score > 85) {
        return 'TRUSTED';
    }
    if (score >= 70) {
        return 'NORMAL';
    }
    return 'SUSPICIOUS';
};

export const calculateLoginRisk = ({
    faceScore,
    isNewDevice,
    failedAttempts,
    behaviorScore,
    locationChanged
}) => {
    const normalizedFace = clamp(toNumber(faceScore, 85), 0, 100);
    const normalizedBehavior = clamp(toNumber(behaviorScore, 75), 0, 100);
    const attempts = Math.max(0, Math.floor(toNumber(failedAttempts, 0)));

    let risk = 0;
    const reasons = [];

    if (normalizedFace < 70) {
        risk += 30;
        reasons.push('Face confidence below 70%');
    }

    if (Boolean(isNewDevice)) {
        risk += 20;
        reasons.push('Untrusted or new device');
    }

    if (attempts >= 3) {
        risk += 25;
        reasons.push('Three or more failed attempts');
    }

    if (normalizedBehavior < 60) {
        risk += 15;
        reasons.push('Behavior anomaly detected');
    }

    if (Boolean(locationChanged)) {
        risk += 15;
        reasons.push('Location change detected');
    }

    const boundedRisk = clamp(risk, 0, 100);
    const level = boundedRisk < 30 ? 'LOW' : boundedRisk <= 60 ? 'MEDIUM' : 'HIGH';

    return {
        riskScore: boundedRisk,
        level,
        reasons,
        faceTier: faceTrustTier(normalizedFace),
        input: {
            faceScore: normalizedFace,
            behaviorScore: normalizedBehavior,
            failedAttempts: attempts,
            isNewDevice: Boolean(isNewDevice),
            locationChanged: Boolean(locationChanged)
        }
    };
};

export const getDecisionFromRisk = ({ riskScore }) => {
    const score = clamp(toNumber(riskScore, 0), 0, 100);
    if (score < 30) {
        return 'NORMAL_LOGIN';
    }
    if (score <= 60) {
        return 'REQUIRE_BIOMETRIC';
    }
    return 'REQUIRE_BIOMETRIC';
};
