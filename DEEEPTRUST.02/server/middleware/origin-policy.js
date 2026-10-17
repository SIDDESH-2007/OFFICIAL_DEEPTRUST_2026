/** Explicit frontend origins plus this application's own HTTPS development tunnel. */
function allowedOrigin(origin, host, configuredOrigins) {
  if (!origin) return true;
  if (configuredOrigins.includes(origin)) return true;
  try {
    const url = new URL(origin);
    return url.origin === origin && url.protocol === 'https:' &&
      url.hostname.endsWith('.loca.lt') && url.host === host;
  } catch (_) { return false; }
}
module.exports = { allowedOrigin };
