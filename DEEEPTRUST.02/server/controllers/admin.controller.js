/**
 * controllers/admin.controller.js
 * Admin Login handler forwarding to AuthController
 */

const AuthController = require('./auth.controller');

const AdminController = {
    async login(req, res) {
        return AuthController.login(req, res);
    }
};

module.exports = AdminController;
