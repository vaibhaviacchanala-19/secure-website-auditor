/**
 * Generates findings and recommendations based on scan results
 * @param {Object} results - Aggregated scan results
 * @returns {Object} - { findings: [], recommendations: [] }
 */
const generateRecommendations = (results) => {
    const findings = [];
    const recommendations = [];
    const { summary, reputationIntel } = results;

    // 1. HTTPS/SSL
    if (!summary.http.httpsEnabled) {
        findings.push('HTTPS is not enabled.');
        recommendations.push('Enable HTTPS by installing an SSL/TLS certificate.');
    } else if (!summary.ssl.valid) {
        findings.push(`SSL certificate is invalid: ${summary.ssl.authorizedError || 'Unknown error'}`);
        recommendations.push('Renew or fix your SSL certificate configuration.');
    }

    if (summary.ssl.daysRemaining < 30 && summary.ssl.daysRemaining > 0) {
        findings.push(`SSL certificate expires soon (${summary.ssl.daysRemaining} days).`);
        recommendations.push('Schedule an SSL certificate renewal.');
    }

    // 2. Headers
    if (summary.headers.hsts === 'Missing') {
        findings.push('HSTS (Strict-Transport-Security) header is missing.');
        recommendations.push('Enable HSTS to force browsers to use HTTPS.');
    }
    if (summary.headers.csp === 'Missing') {
        findings.push('Content-Security-Policy (CSP) is not defined.');
        recommendations.push('Implement a strong CSP to prevent XSS and data injection attacks.');
    }
    if (summary.headers.xFrameOptions === 'Missing') {
        findings.push('X-Frame-Options header is missing.');
        recommendations.push('Add X-Frame-Options (DENY or SAMEORIGIN) to prevent Clickjacking.');
    }

    // 3. Cookies
    if (summary.cookies.cookies) {
        const insecure = summary.cookies.cookies.filter(c => !c.secure);
        if (insecure.length > 0) {
            findings.push(`${insecure.length} cookie(s) missing the 'Secure' attribute.`);
            recommendations.push("Ensure all sensitive cookies have the 'Secure' flag.");
        }
        const nonHttpOnly = summary.cookies.cookies.filter(c => !c.httpOnly);
        if (nonHttpOnly.length > 0) {
            findings.push(`${nonHttpOnly.length} cookie(s) missing the 'HttpOnly' attribute.`);
            recommendations.push("Add 'HttpOnly' to cookies to prevent access via JavaScript.");
        }
    }

    // 4. DNS
    if (summary.dns.spf === 'Missing') {
        findings.push('SPF record is missing.');
        recommendations.push('Add an SPF TXT record to your DNS to prevent email spoofing.');
    }
    if (summary.dns.dmarc === 'Missing') {
        findings.push('DMARC record is missing.');
        recommendations.push('Implement DMARC to define how to handle emails that fail SPF/DKIM.');
    }

    // 5. Threat Intel
    if (reputationIntel.virustotal.malicious > 0) {
        findings.push(`VirusTotal detected ${reputationIntel.virustotal.malicious} malicious indicators.`);
        recommendations.push('Investigate potential malware infection or compromise.');
    }
    if (reputationIntel.abuseipdb.abuseConfidenceScore > 50) {
        findings.push(`High abuse confidence score (${reputationIntel.abuseipdb.abuseConfidenceScore}%) on AbuseIPDB.`);
        recommendations.push('Check server logs for signs of malicious activity or unauthorized use.');
    }

    return { findings, recommendations };
};

module.exports = { generateRecommendations };
