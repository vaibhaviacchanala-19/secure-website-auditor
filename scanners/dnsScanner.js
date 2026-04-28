const dns = require('dns').promises;

/**
 * Scans DNS records
 * @param {string} hostname - Domain hostname
 * @returns {Promise<Object>}
 */
const scan = async (hostname) => {
    const results = {};

    try {
        // A Record (IP)
        results.ip = await dns.resolve4(hostname).catch(() => []);
        
        // MX Records
        results.mx = await dns.resolveMx(hostname).catch(() => []);

        // TXT Records (SPF and DMARC often live here)
        const txt = await dns.resolveTxt(hostname).catch(() => []);
        results.spf = txt.flat().find(t => t.startsWith('v=spf1')) || 'Missing';
        
        // DMARC
        const dmarc = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
        results.dmarc = dmarc.flat().find(t => t.startsWith('v=DMARC1')) || 'Missing';

        // CNAME
        results.cname = await dns.resolveCname(hostname).catch(() => 'No CNAME');

        return results;
    } catch (error) {
        return { error: error.message };
    }
};

module.exports = { scan };
