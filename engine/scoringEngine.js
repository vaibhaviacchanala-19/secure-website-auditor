/**
 * Calculates security score based on scan results
 * @param {Object} results - Aggregated scan results
 * @returns {number} - Calculated score (0-100)
 */
const calculateScore = (results) => {
    let score = 0;
    const { summary, reputationIntel } = results;

    // 1. HTTP/HTTPS Checks (Max 35 points)
    if (summary.http.httpsEnabled) score += 20;
    if (summary.http.statusCode === 200) score += 10;
    if (summary.http.status === 'Healthy') score += 5;

    // 2. SSL/TLS Checks (Max 15 points)
    if (summary.ssl.valid) score += 15;
    if (summary.ssl.isExpired) score -= 20;
    if (summary.ssl.daysRemaining < 30) score -= 5;

    // 3. Security Headers (Max 40 points)
    if (summary.headers.hsts !== 'Missing') score += 10;
    if (summary.headers.csp !== 'Missing') score += 15;
    if (summary.headers.xFrameOptions !== 'Missing') score += 5;
    if (summary.headers.xContentTypeOptions !== 'Missing') score += 5;
    if (summary.headers.referrerPolicy !== 'Missing') score += 5;

    // 4. Cookies (Max 10 points)
    if (summary.cookies.cookies) {
        const allSecure = summary.cookies.cookies.every(c => c.secure);
        const allHttpOnly = summary.cookies.cookies.every(c => c.httpOnly);
        if (allSecure) score += 5;
        if (allHttpOnly) score += 5;
    } else {
        // No cookies is fine/secure
        score += 10;
    }

    // 5. Threat Intel Penalties
    if (reputationIntel.virustotal.malicious > 0) score -= (reputationIntel.virustotal.malicious * 10);
    if (reputationIntel.virustotal.suspicious > 0) score -= (reputationIntel.virustotal.suspicious * 5);
    
    if (reputationIntel.abuseipdb.abuseConfidenceScore > 20) {
        score -= Math.floor(reputationIntel.abuseipdb.abuseConfidenceScore / 2);
    }

    // Normalize score between 0 and 100
    return Math.max(0, Math.min(100, score));
};

/**
 * Maps numerical score to risk rating
 * @param {number} score 
 * @returns {string}
 */
const getRating = (score) => {
    if (score >= 70) return 'Low Risk';
    if (score >= 40) return 'Medium Risk';
    return 'High Risk';
};

module.exports = { calculateScore, getRating };
