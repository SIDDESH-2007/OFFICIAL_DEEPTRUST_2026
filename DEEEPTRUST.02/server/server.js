/**
 * server.js
 * Entry point for the backend server
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') }); // Load environment variables from parent folder
require('./config/production.config').validateProductionConfig();
const app = require('./app');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
