const apiClient = require('../utils/apiClient');
const logger = require('../utils/logger');

/**
 * Fetches IP reputation from AbuseIPDB
 * @param {string} ip - IP address to check
 * @returns {Promise<Object>}
 */
const getIpReport = async (ip) => {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
        logger.warn(`AbuseIPDB API key missing. Skipping check for ${ip}`);
        return { error: 'AbuseIPDB API key missing', status: 'skipped' };
    }

    try {
        const response = await apiClient.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { 'Key': apiKey, 'Accept': 'application/json' }
        });

        const data = response.data.data;
        logger.info(`AbuseIPDB report fetched for ${ip}`);
        
        return {
            abuseConfidenceScore: data.abuseConfidenceScore,
            totalReports: data.totalReports,
            lastReportedAt: data.lastReportedAt,
            country: data.countryCode,
            usageType: data.usageType,
            isp: data.isp,
            domain: data.domain,
            isWhitelisted: data.isWhitelisted,
            status: 'success'
        };
    } catch (error) {
        logger.error(`AbuseIPDB API error for ${ip}: ${error.message}`);
        return { 
            error: error.response?.data?.errors?.[0]?.detail || error.message, 
            status: 'failed' 
        };
    }
};

module.exports = { getIpReport };
