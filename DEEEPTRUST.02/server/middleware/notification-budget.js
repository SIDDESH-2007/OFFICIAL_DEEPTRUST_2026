/** Keep read-only notification polling separate from login and mutation budgets. */
function isNotificationRead(req) {
    return req.method === 'GET' && /^\/api\/v1\/notifications(?:\/unread-count)?\/?$/.test(req.path);
}
module.exports = { isNotificationRead };
