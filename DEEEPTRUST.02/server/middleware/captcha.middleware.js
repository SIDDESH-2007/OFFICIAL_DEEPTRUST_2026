/**
 * middleware/captcha.middleware.js
 * Stage 3: CAPTCHA validation
 */
const LogService = require('../services/log.service');

const captchaMiddleware = async (req, res, next) => {
    try {
        const { username, captchaToken } = req.body;

        if (!captchaToken) {
            await LogService.logFailedAttempt(username, 'Stage 3: Missing Captcha', {});
            return res.status(401).json({ message: "Stage 3 Failed: CAPTCHA required" });
        }

        // Ideally, verify the token with reCAPTCHA/hCaptcha APIs here
        // const isCaptchaValid = await verifyCaptchaApi(captchaToken);
        // if (!isCaptchaValid) throw Error

        next();
    } catch (error) {
        res.status(500).json({ message: "Server error during Stage 3 validation" });
    }
};

module.exports = captchaMiddleware;
