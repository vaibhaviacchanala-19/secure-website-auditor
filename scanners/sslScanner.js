const tls = require('tls');

/**
 * Scans SSL/TLS certificate details
 * @param {string} hostname - Domain hostname
 * @returns {Promise<Object>}
 */
const scan = (hostname) => {
    return new Promise((resolve) => {
        const options = {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false // We want to inspect the cert even if invalid
        };

        try {
            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate();
                if (!cert || Object.keys(cert).length === 0) {
                    resolve({ status: 'No Certificate Found' });
                    socket.destroy();
                    return;
                }

                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const now = new Date();

                resolve({
                    valid: socket.authorized || false,
                    authorizedError: socket.authorizationError,
                    issuer: cert.issuer.O || cert.issuer.CN,
                    expiryDate: cert.valid_to,
                    daysRemaining: Math.floor((validTo - now) / (1000 * 60 * 60 * 24)),
                    isExpired: now > validTo
                });
                socket.destroy();
            });

            socket.on('error', (err) => {
                resolve({ error: err.message, status: 'Connection Failed' });
            });

            socket.setTimeout(5000, () => {
                resolve({ error: 'Timeout', status: 'Timeout' });
                socket.destroy();
            });
        } catch (error) {
            resolve({ error: error.message, status: 'Error' });
        }
    });
};

module.exports = { scan };
