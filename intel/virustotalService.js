const apiClient = require('../utils/apiClient');
const logger = require('../utils/logger');

/**
 * Fetches domain reputation from VirusTotal
 * @param {string} domain - Domain to check
 * @returns {Promise<Object>}
 */
const getDomainReport = async (domain) => {
    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) {
        logger.warn(`VirusTotal API key missing. Skipping check for ${domain}`);
        return { error: 'VirusTotal API key missing', status: 'skipped' };
    }

    try {
        const response = await apiClient.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            headers: { 'x-apikey': apiKey }
        });

        const stats = response.data.data.attributes.last_analysis_stats;
        logger.info(`VirusTotal report fetched for ${domain}`);
        
        return {
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            harmless: stats.harmless,
            undetermined: stats.undetected,
            reputation: response.data.data.attributes.reputation,
            status: 'success'
        };
    } catch (error) {
        logger.error(`VirusTotal API error for ${domain}: ${error.message}`);
        return { 
            error: error.response?.data?.error?.message || error.message, 
            status: 'failed' 
        };
    }
};

module.exports = { getDomainReport };
