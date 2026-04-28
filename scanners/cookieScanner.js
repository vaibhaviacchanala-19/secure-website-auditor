const apiClient = require('../utils/apiClient');
const logger = require('../utils/logger');

/**
 * Scans Cookies for security attributes
 * @param {string} url - Normalized URL
 * @returns {Promise<Object>}
 */
const scan = async (url) => {
    try {
        const response = await apiClient.get(url, {
            maxRedirects: 5,
            validateStatus: () => true
        });

        const setCookieHeaders = response.headers['set-cookie'] || [];
        logger.info(`Cookie Scan completed for ${url}. Found ${setCookieHeaders.length} cookies.`);
        
        if (setCookieHeaders.length === 0) {
            return { message: 'No cookies set by this site.' };
        }

        const cookieReports = setCookieHeaders.map(cookieStr => {
            return {
                name: cookieStr.split('=')[0],
                secure: cookieStr.toLowerCase().includes('secure'),
                httpOnly: cookieStr.toLowerCase().includes('httponly'),
                sameSite: cookieStr.toLowerCase().includes('samesite') ? 
                          (cookieStr.match(/samesite=([^;]+)/i) || [])[1] : 'Missing'
            };
        });

        return {
            count: setCookieHeaders.length,
            cookies: cookieReports
        };
    } catch (error) {
        logger.error(`Cookie Scan failed for ${url}: ${error.message}`);
        return { error: `Failed to fetch cookies: ${error.message}` };
    }
};

module.exports = { scan };
