const express = require('express');
const router = express.Router();
const { validateAndSanitize } = require('../utils/validator');

// Import Scanners
const httpScanner = require('../scanners/httpScanner');
const headerScanner = require('../scanners/headerScanner');
const sslScanner = require('../scanners/sslScanner');
const dnsScanner = require('../scanners/dnsScanner');
const cookieScanner = require('../scanners/cookieScanner');

// Import Intel Services
const vtService = require('../intel/virustotalService');
const abuseService = require('../intel/abuseipdbService');

// Import Engine
const scoringEngine = require('../engine/scoringEngine');
const recEngine = require('../engine/recommendationEngine');

// Import Utils
const storage = require('../utils/storage');
const pdfGenerator = require('../utils/pdfGenerator');

// ─── Request timeout (ms) ─────────────────────────────────────────────────────
const REQUEST_TIMEOUT_MS = 30_000;

// ─── POST /scan ───────────────────────────────────────────────────────────────
router.post('/scan', async (req, res, next) => {
  const timeout = setTimeout(() => {
    const err = new Error('Request timed out during scanning. Please try again.');
    err.statusCode = 408;
    next(err);
  }, REQUEST_TIMEOUT_MS);

  res.on('finish', () => clearTimeout(timeout));
  res.on('close',  () => clearTimeout(timeout));

  try {
    const { target } = req.body;

    if (!target) {
      clearTimeout(timeout);
      return res.status(400).json({ success: false, message: 'Missing target.' });
    }

    const { domain, normalizedUrl } = await validateAndSanitize(target);

    const [httpResults, headerResults, sslResults, dnsResults, cookieResults, vtResults] = await Promise.all([
        httpScanner.scan(normalizedUrl),
        headerScanner.scan(normalizedUrl),
        sslScanner.scan(domain),
        dnsScanner.scan(domain),
        cookieScanner.scan(normalizedUrl),
        vtService.getDomainReport(domain)
    ]);

    let abuseResults = { status: 'skipped', message: 'No IP found' };
    if (dnsResults.ip && dnsResults.ip.length > 0) {
        abuseResults = await abuseService.getIpReport(dnsResults.ip[0]);
    }

    const rawResults = {
        summary: { http: httpResults, ssl: sslResults, dns: dnsResults, headers: headerResults, cookies: cookieResults },
        reputationIntel: { virustotal: vtResults, abuseipdb: abuseResults }
    };

    const score = scoringEngine.calculateScore(rawResults);
    const rating = scoringEngine.getRating(score);
    const { findings, recommendations } = recEngine.generateRecommendations(rawResults);

    const reportData = {
        target: { domain, normalizedUrl, ip: dnsResults.ip?.[0] || 'Unknown', timestamp: new Date().toISOString() },
        securityAudit: { score, rating, findings, recommendations },
        details: rawResults,
        status: 'completed'
    };

    // Save to storage
    const savedReport = await storage.saveReport(reportData);

    clearTimeout(timeout);
    return res.status(200).json({
      success: true,
      report: savedReport
    });
  } catch (err) {
    clearTimeout(timeout);
    if (err.statusCode) return res.status(err.statusCode).json({ success: false, message: err.message });
    next(err);
  }
});

// ─── GET /history ─────────────────────────────────────────────────────────────
router.get('/history', async (req, res, next) => {
    try {
        const reports = await storage.getAllReports();
        res.json({ success: true, reports });
    } catch (err) {
        next(err);
    }
});

// ─── GET /report/:id ──────────────────────────────────────────────────────────
router.get('/report/:id', async (req, res, next) => {
    try {
        const report = await storage.getReportById(req.params.id);
        if (!report) return res.status(404).json({ success: false, message: 'Report not found' });
        res.json({ success: true, report });
    } catch (err) {
        next(err);
    }
});

// ─── GET /report/:id/pdf ──────────────────────────────────────────────────────
router.get('/report/:id/pdf', async (req, res, next) => {
    try {
        const report = await storage.getReportById(req.params.id);
        if (!report) return res.status(404).json({ success: false, message: 'Report not found' });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=report_${report.target.domain}.pdf`);
        
        pdfGenerator.generatePDF(report, res);
    } catch (err) {
        next(err);
    }
});

// ─── DELETE /report/:id ───────────────────────────────────────────────────────
router.delete('/report/:id', async (req, res, next) => {
    try {
        await storage.deleteReport(req.params.id);
        res.json({ success: true, message: 'Report deleted' });
    } catch (err) {
        next(err);
    }
});

module.exports = router;
