const apiClient = require('../utils/apiClient');
const logger = require('../utils/logger');

/**
 * Scans HTTP Security Headers
 * @param {string} url - Normalized URL
 * @returns {Promise<Object>}
 */
const scan = async (url) => {
    try {
        const response = await apiClient.head(url, {
            maxRedirects: 5,
            validateStatus: () => true
        });

        const headers = response.headers;
        logger.info(`Header Scan completed for ${url}`);

        return {
            hsts: headers['strict-transport-security'] || 'Missing',
            csp: headers['content-security-policy'] || 'Missing',
            xFrameOptions: headers['x-frame-options'] || 'Missing',
            xContentTypeOptions: headers['x-content-type-options'] || 'Missing',
            referrerPolicy: headers['referrer-policy'] || 'Missing'
        };
    } catch (error) {
        logger.error(`Header Scan failed for ${url}: ${error.message}`);
        return {
            error: `Failed to fetch headers: ${error.message}`
        };
    }
};

module.exports = { scan };
