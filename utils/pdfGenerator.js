const PDFDocument = require('pdfkit');

/**
 * Generates a security report PDF
 * @param {Object} report - The scan report object
 * @param {Stream} stream - Writable stream (res)
 */
const generatePDF = (report, stream) => {
    const doc = new PDFDocument({ margin: 50 });

    doc.pipe(stream);

    // Header
    doc.fontSize(25).fillColor('#00f2ff').text('SECURE AUDIT REPORT', { align: 'center' });
    doc.moveDown();
    
    // Target Info
    doc.fontSize(12).fillColor('#000').text(`Domain: ${report.target.domain}`);
    doc.text(`IP: ${report.target.ip}`);
    doc.text(`Timestamp: ${new Date(report.target.timestamp).toLocaleString()}`);
    doc.moveDown();

    // Security Score
    doc.fontSize(16).text('Security Audit Summary', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(14).text(`Score: ${report.securityAudit.score}/100`);
    doc.text(`Rating: ${report.securityAudit.rating}`);
    doc.moveDown();

    // Findings
    doc.fontSize(16).text('Findings', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(10);
    report.securityAudit.findings.forEach((finding, i) => {
        doc.fillColor('red').text(`• ${finding}`);
        doc.fillColor('black').text(`  Recommendation: ${report.securityAudit.recommendations[i]}`);
        doc.moveDown(0.5);
    });
    doc.moveDown();

    // Threat Intel
    doc.fontSize(16).fillColor('black').text('Threat Intelligence', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(10);
    doc.text(`VirusTotal Malicious Detections: ${report.details.reputationIntel.virustotal.malicious || 0}`);
    doc.text(`AbuseIPDB Confidence Score: ${report.details.reputationIntel.abuseipdb.abuseConfidenceScore || 0}%`);
    
    doc.end();
};

module.exports = { generatePDF };
