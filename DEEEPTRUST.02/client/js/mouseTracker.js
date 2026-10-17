/**
 * mouseTracker.js
 * Layer 2 - Behavioral intelligence telemetry module.
 *
 * Security design notes:
 * - Captures movement velocity, acceleration changes, click cadence, idle pauses.
 * - Computes compact aggregate metrics only (no raw path exfiltration by default).
 * - Produces deterministic features suitable for risk model weighting.
 */

let startedAt = 0;
let moves = [];
let clicks = [];
let keyDownEvents = [];
let keyIntervals = [];
let holdDurations = [];
let scrollEvents = [];
let backspaceCount = 0;
let idleMs = 0;
let lastActivityTs = 0;
let active = false;
let keyboardListenerTarget = document;

const MAX_POINTS = 500;

const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

const variance = (values) => {
    if (!values.length) {
        return 0;
    }

    const mean = values.reduce((total, value) => total + value, 0) / values.length;
    const squaredDiff = values.map((value) => (value - mean) ** 2);
    return squaredDiff.reduce((total, value) => total + value, 0) / values.length;
};

const movementHandler = (event) => {
    if (!active) {
        return;
    }

    recordActivity();
    moves.push({ x: event.clientX, y: event.clientY, t: performance.now() });
    if (moves.length > MAX_POINTS) {
        moves = moves.slice(moves.length - MAX_POINTS);
    }
};

const clickHandler = (event) => {
    if (!active) {
        return;
    }

    recordActivity();
    clicks.push({ x: event.clientX, y: event.clientY, t: performance.now() });
    if (clicks.length > MAX_POINTS) {
        clicks = clicks.slice(clicks.length - MAX_POINTS);
    }
};

const recordActivity = () => {
    const now = performance.now();
    if (lastActivityTs > 0) {
        const gap = now - lastActivityTs;
        if (gap > 1000) {
            idleMs += gap;
        }
    }
    lastActivityTs = now;
};

const keydownHandler = (event) => {
    if (!active) {
        return;
    }

    recordActivity();
    const now = performance.now();
    const previous = keyDownEvents[keyDownEvents.length - 1];
    if (previous) {
        keyIntervals.push(now - previous.t);
    }

    if (event.key === 'Backspace') {
        backspaceCount += 1;
    }

    keyDownEvents.push({ key: event.key, t: now });
};

const keyupHandler = (event) => {
    if (!active) {
        return;
    }

    recordActivity();
    const now = performance.now();
    const downEvent = [...keyDownEvents].reverse().find((item) => item.key === event.key);
    if (downEvent) {
        holdDurations.push(now - downEvent.t);
    }
};

const scrollHandler = () => {
    if (!active) {
        return;
    }

    recordActivity();
    scrollEvents.push({
        y: window.scrollY,
        t: performance.now()
    });
};

export const startBehaviorTracking = ({ keyboardTarget = document } = {}) => {
    if (active) {
        return;
    }

    startedAt = performance.now();
    moves = [];
    clicks = [];
    keyDownEvents = [];
    keyIntervals = [];
    holdDurations = [];
    scrollEvents = [];
    backspaceCount = 0;
    idleMs = 0;
    lastActivityTs = performance.now();
    active = true;
    keyboardListenerTarget = keyboardTarget;

    document.addEventListener('mousemove', movementHandler, { passive: true });
    document.addEventListener('click', clickHandler, { passive: true });
    keyboardListenerTarget.addEventListener('keydown', keydownHandler);
    keyboardListenerTarget.addEventListener('keyup', keyupHandler);
    document.addEventListener('scroll', scrollHandler, { passive: true });
};

export const stopBehaviorTracking = () => {
    active = false;
    document.removeEventListener('mousemove', movementHandler);
    document.removeEventListener('click', clickHandler);
    keyboardListenerTarget.removeEventListener('keydown', keydownHandler);
    keyboardListenerTarget.removeEventListener('keyup', keyupHandler);
    document.removeEventListener('scroll', scrollHandler);
};

export const computeBehaviorMetrics = () => {
    const speedSeries = [];
    const accelerationSeries = [];
    const pauseIntervals = [];

    for (let index = 1; index < moves.length; index += 1) {
        const prev = moves[index - 1];
        const curr = moves[index];
        const dt = (curr.t - prev.t) / 1000;
        if (dt <= 0) {
            continue;
        }

        const d = distance(curr, prev);
        const speed = d / dt;
        speedSeries.push(speed);

        if (dt > 0.35) {
            pauseIntervals.push(dt);
        }

        const previousSpeed = speedSeries[speedSeries.length - 2];
        if (previousSpeed !== undefined) {
            accelerationSeries.push((speed - previousSpeed) / dt);
        }
    }

    const clickIntervals = [];
    for (let index = 1; index < clicks.length; index += 1) {
        clickIntervals.push((clicks[index].t - clicks[index - 1].t) / 1000);
    }

    const averageKeyInterval = keyIntervals.length
        ? keyIntervals.reduce((total, value) => total + value, 0) / keyIntervals.length
        : 0;
    const averageHoldDuration = holdDurations.length
        ? holdDurations.reduce((total, value) => total + value, 0) / holdDurations.length
        : 0;
    const keystrokeSpeedPerSecond = keyDownEvents.length
        ? (keyDownEvents.length / Math.max((performance.now() - startedAt) / 1000, 1))
        : 0;

    const scrollPatternVariance = variance(
        scrollEvents.slice(1).map((event, index) => Math.abs(event.y - scrollEvents[index].y))
    );

    const movementAngles = [];
    for (let index = 2; index < moves.length; index += 1) {
        const a = moves[index - 2];
        const b = moves[index - 1];
        const c = moves[index];

        const angle1 = Math.atan2(b.y - a.y, b.x - a.x);
        const angle2 = Math.atan2(c.y - b.y, c.x - b.x);
        movementAngles.push(Math.abs(angle2 - angle1));
    }

    const avgSpeed = speedSeries.length ? speedSeries.reduce((t, s) => t + s, 0) / speedSeries.length : 0;
    const speedVariance = variance(speedSeries);
    const accelerationVariance = variance(accelerationSeries);
    const clickIntervalVariance = variance(clickIntervals);
    const randomnessScore = movementAngles.length
        ? Math.min(1, movementAngles.reduce((t, a) => t + a, 0) / movementAngles.length / Math.PI)
        : 0;
    const idleRatio = pauseIntervals.length
        ? Math.min(1, pauseIntervals.reduce((t, p) => t + p, 0) / ((performance.now() - startedAt) / 1000))
        : 0;

    return {
        sampleCount: moves.length,
        clickCount: clicks.length,
        keyCount: keyDownEvents.length,
        backspaceFrequency: Number((backspaceCount / Math.max(keyDownEvents.length || 1, 1)).toFixed(4)),
        keystrokeSpeed: Number(keystrokeSpeedPerSecond.toFixed(2)),
        keyHoldDurationAverageMs: Number(averageHoldDuration.toFixed(2)),
        keyIntervalAverageMs: Number(averageKeyInterval.toFixed(2)),
        averageSpeed: Number(avgSpeed.toFixed(2)),
        speedVariance: Number(speedVariance.toFixed(2)),
        accelerationCurveVariance: Number(accelerationVariance.toFixed(2)),
        clickIntervalVariance: Number(clickIntervalVariance.toFixed(2)),
        idlePauseRatio: Number(idleRatio.toFixed(4)),
        idleDurationMs: Number(idleMs.toFixed(0)),
        scrollPatternVariance: Number(scrollPatternVariance.toFixed(2)),
        pathRandomness: Number(randomnessScore.toFixed(4)),
        durationSeconds: Number(((performance.now() - startedAt) / 1000).toFixed(2))
    };
};

export const clearBehaviorData = () => {
    moves = [];
    clicks = [];
    keyDownEvents = [];
    keyIntervals = [];
    holdDurations = [];
    scrollEvents = [];
    backspaceCount = 0;
    idleMs = 0;
    startedAt = performance.now();
    lastActivityTs = startedAt;
};
