const express = require('express');
const router = express.Router();

const scanRoutes = require('./scanRoutes');

/**
 * @route   GET /
 * @desc    Base route
 * @access  Public
 */
router.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Welcome to the Secure Website Checklist Auditor API',
        version: '1.0.0'
    });
});

/**
 * @route   GET /health
 * @desc    Health check endpoint
 * @access  Public
 */
router.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Scan routes
router.use('/', scanRoutes);

module.exports = router;
