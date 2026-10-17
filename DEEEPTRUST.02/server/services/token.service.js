/**
 * services/token.service.js
 * Generates and verifies JWT tokens
 */
const jwt = require('jsonwebtoken');

const TokenService = {
    generateToken(payload) {
        const secret = process.env.JWT_SECRET;
        if (!secret) throw new Error("JWT_SECRET environment variable is missing.");
        // Token expires in 1 hour
        return jwt.sign(payload, secret, { expiresIn: '1h' });
    },

    verifyToken(token) {
        const secret = process.env.JWT_SECRET;
        if (!secret) throw new Error("JWT_SECRET environment variable is missing.");
        return jwt.verify(token, secret, { algorithms: ['HS256'] });
    }
};

module.exports = TokenService;
