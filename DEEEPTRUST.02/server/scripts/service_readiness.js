/** Wait for actual health, allowing cold AI imports without hiding crashes. */
async function waitForService({ child, checkReady, timeoutMs = 90000, pollMs = 500, onProgress = () => {} }) {
    let spawnError;
    const onError = error => { spawnError = error; };
    child.on('error', onError);
    const started = Date.now();
    const deadline = started + timeoutMs;
    let lastProgress = 0;
    const checkProcess = () => {
        if (spawnError) throw new Error(`AI process could not start: ${spawnError.message}`);
        if (child.exitCode !== null || child.signalCode) {
            throw new Error(`AI process exited before readiness (code ${child.exitCode}, signal ${child.signalCode || 'none'}).`);
        }
    };
    try {
        while (Date.now() < deadline) {
            checkProcess();
            const healthy = await checkReady();
            checkProcess();
            if (healthy) return;
            const elapsed = Math.floor((Date.now() - started) / 1000);
            if (elapsed >= lastProgress + 10) { lastProgress = elapsed; onProgress(elapsed); }
            const remaining = deadline - Date.now();
            if (remaining > 0) await new Promise(resolve => setTimeout(resolve, Math.min(pollMs, remaining)));
        }
        throw new Error(`AI health endpoint did not become ready within ${Math.round(timeoutMs / 1000)} seconds.`);
    } finally {
        child.removeListener('error', onError);
    }
}
module.exports = { waitForService };
