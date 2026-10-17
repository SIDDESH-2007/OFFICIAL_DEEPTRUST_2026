/** Production startup must reject incomplete or demo configuration. */
function validateProductionConfig(env = process.env) {
  if (env.NODE_ENV !== 'production') return;
  const errors = [];
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) errors.push('JWT_SECRET must contain at least 32 characters');
  if (!env.AUDIT_SIGNING_KEY || env.AUDIT_SIGNING_KEY.length < 32 || env.AUDIT_SIGNING_KEY === env.JWT_SECRET) errors.push('Set a separate AUDIT_SIGNING_KEY of at least 32 characters');
  for (const key of ['MONGODB_URI', 'MONGODB_DATABASE', 'AI_SERVICE_URL', 'AUDIT_CHECKPOINT_PATH']) if (!env[key]) errors.push(key + ' is required');
  if (String(env.ENABLE_DEMO_SEEDING).toLowerCase() === 'true') errors.push('Demo seeding is forbidden in production');
  const origins = (env.FRONTEND_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  if (!origins.length || origins.some(x => {try {const u=new URL(x);return u.protocol!=='https:' || u.origin!==x;} catch (_) {return true;}})) errors.push('FRONTEND_ORIGINS must contain exact HTTPS origins');
  if (errors.length) throw Error('Production configuration rejected: ' + errors.join('; '));
}
module.exports = { validateProductionConfig };
