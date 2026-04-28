const apiClient = require('../utils/apiClient');
const logger = require('../utils/logger');

/**
 * Scans HTTP basic security and performance
 * @param {string} url - Normalized URL
 * @returns {Promise<Object>}
 */
const scan = async (url) => {
    const startTime = Date.now();
    try {
        const response = await apiClient.get(url, {
            maxRedirects: 5,
            validateStatus: () => true
        });

        const responseTime = Date.now() - startTime;
        
        logger.info(`HTTP Scan completed for ${url} in ${responseTime}ms`);

        return {
            httpsEnabled: url.startsWith('https'),
            statusCode: response.status,
            responseTime: `${responseTime}ms`,
            status: response.status >= 200 && response.status < 400 ? 'Healthy' : 'Warning'
        };
    } catch (error) {
        logger.error(`HTTP Scan failed for ${url}: ${error.message}`);
        return {
            error: error.message,
            status: 'Error'
        };
    }
};

module.exports = { scan };
