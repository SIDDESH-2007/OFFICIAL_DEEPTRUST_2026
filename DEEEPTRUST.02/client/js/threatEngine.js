export const calculateWeightedRisk = ({ weights, signals }) => {
    const face = Number(signals?.face || 0);
    const voice = Number(signals?.voice || 0);
    const behavior = Number(signals?.behavior || 0);
    const ip = Number(signals?.ip || 0);

    return Math.max(
        0,
        Math.min(
            100,
            Math.round(
                (face * (weights?.face || 0)) +
                (voice * (weights?.voice || 0)) +
                (behavior * (weights?.behavior || 0)) +
                (ip * (weights?.ip || 0))
            )
        )
    );
};

export const mapRiskToAction = (riskScore) => {
    if (riskScore < 30) {
        return 'ALLOW';
    }
    if (riskScore <= 60) {
        return 'STEP_UP_VERIFICATION';
    }
    return 'BLOCK_ALERT_VOICE';
};

export const getRiskLevel = (riskScore) => {
    if (riskScore < 30) {
        return 'low';
    }
    if (riskScore <= 60) {
        return 'medium';
    }
    return 'high';
};