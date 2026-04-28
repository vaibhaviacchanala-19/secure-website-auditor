document.addEventListener('DOMContentLoaded', () => {
    const domainInput = document.getElementById('domainInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const btnLoader = document.getElementById('btnLoader');
    const resultsSection = document.getElementById('resultsSection');
    const loaderSection = document.getElementById('loaderSection');
    const errorMsg = document.getElementById('errorMsg');

    // UI Elements for Data
    const scoreText = document.getElementById('scoreText');
    const scoreGauge = document.getElementById('scoreGauge');
    const riskRating = document.getElementById('riskRating');
    const resDomain = document.getElementById('resDomain');
    const resIp = document.getElementById('resIp');
    const resTime = document.getElementById('resTime');
    const recommendationsList = document.getElementById('recommendationsList');
    const vtStats = document.getElementById('vtStats');
    const abuseStats = document.getElementById('abuseStats');
    const rawReport = document.getElementById('rawReport');

    let currentReport = null;

    // UI Elements for History
    const historyList = document.getElementById('historyList');
    const downloadJson = document.getElementById('downloadJson');
    const downloadPdf = document.getElementById('downloadPdf');
    const downloadPdfTab = document.getElementById('downloadPdfTab');

    // Fetch History on Load
    fetchHistory();

    // Tab Logic
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.tab;
            
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(target).classList.add('active');
        });
    });

    // Download JSON
    downloadJson.addEventListener('click', () => {
        if (!currentReport) return;
        const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit_${currentReport.target.domain}.json`;
        a.click();
    });

    // Download PDF
    downloadPdf.addEventListener('click', () => {
        if (!currentReport || !currentReport.id) return;
        window.open(`/report/${currentReport.id}/pdf`, '_blank');
    });

    downloadPdfTab.addEventListener('click', () => {
        if (!currentReport || !currentReport.id) return;
        window.open(`/report/${currentReport.id}/pdf`, '_blank');
    });

    // Scan Logic
    scanBtn.addEventListener('click', async () => {
        const target = domainInput.value.trim();
        if (!target) {
            showError('Please enter a domain or URL.');
            return;
        }

        startLoading();

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.message || 'Scan failed.');
            }

            currentReport = data.report;
            renderResults(data.report);
            fetchHistory(); // Refresh history
        } catch (err) {
            showError(err.message);
        } finally {
            stopLoading();
        }
    });

    async function fetchHistory() {
        try {
            const res = await fetch('/history');
            const data = await res.json();
            if (data.success) {
                renderHistory(data.reports);
            }
        } catch (err) {
            console.error('Failed to fetch history:', err);
        }
    }

    function renderHistory(reports) {
        historyList.innerHTML = '';
        if (reports.length === 0) {
            historyList.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 1rem;">No scan history found.</p>';
            return;
        }

        reports.forEach(report => {
            const item = document.createElement('div');
            item.className = 'history-item';
            
            const score = report.securityAudit.score;
            let ratingClass = 'risk-medium';
            if (score >= 70) ratingClass = 'risk-low';
            else if (score < 40) ratingClass = 'risk-high';

            item.innerHTML = `
                <div class="history-info">
                    <span class="history-domain">${report.target.domain}</span>
                    <span class="history-meta">${new Date(report.target.timestamp).toLocaleString()} • ${report.target.ip}</span>
                </div>
                <div class="history-score-badge ${ratingClass}">${score}</div>
                <div class="history-actions">
                    <button class="view-btn" title="View"><i class="fas fa-eye"></i></button>
                    <button class="delete-btn" title="Delete"><i class="fas fa-trash"></i></button>
                </div>
            `;

            item.querySelector('.view-btn').onclick = () => {
                currentReport = report;
                renderResults(report);
            };

            item.querySelector('.delete-btn').onclick = async (e) => {
                e.stopPropagation();
                if (confirm('Delete this report?')) {
                    await fetch(`/report/${report.id}`, { method: 'DELETE' });
                    fetchHistory();
                }
            };

            historyList.appendChild(item);
        });
    }

    function renderResults(report) {
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        // 1. Basic Info
        resDomain.textContent = report.target.domain;
        resIp.textContent = report.target.ip;
        resTime.textContent = new Date(report.target.timestamp).toLocaleString();

        // 2. Score & Rating
        const score = report.securityAudit.score;
        scoreText.textContent = score;
        
        // Update Gauge (283 is total circumference)
        const offset = 283 - (283 * score / 100);
        scoreGauge.style.strokeDasharray = `${283 - offset}, 283`;
        
        // Update Risk Class
        riskRating.textContent = report.securityAudit.rating;
        riskRating.className = 'risk-badge'; // reset
        if (score >= 70) riskRating.classList.add('risk-low');
        else if (score >= 40) riskRating.classList.add('risk-medium');
        else riskRating.classList.add('risk-high');

        // 3. Recommendations
        recommendationsList.innerHTML = '';
        if (report.securityAudit.findings.length === 0) {
            recommendationsList.innerHTML = '<div class="recommendation-item success" style="border-color: var(--success);">All checks passed! No critical security vulnerabilities found.</div>';
        } else {
            report.securityAudit.findings.forEach((finding, i) => {
                const item = document.createElement('div');
                item.className = 'recommendation-item';
                item.innerHTML = `
                    <span class="rec-finding"><i class="fas fa-exclamation-triangle"></i> ${finding}</span>
                    <p class="rec-advice">${report.securityAudit.recommendations[i]}</p>
                `;
                recommendationsList.appendChild(item);
            });
        }

        // 4. Intel
        renderVT(report.details.reputationIntel.virustotal);
        renderAbuse(report.details.reputationIntel.abuseipdb);

        // 5. Raw Report
        rawReport.textContent = JSON.stringify(report, null, 2);
    }

    function renderVT(vt) {
        vtStats.innerHTML = '';
        if (vt.status === 'skipped') {
            vtStats.innerHTML = '<p class="val">API key missing.</p>';
            return;
        }
        if (vt.status === 'failed') {
            vtStats.innerHTML = `<p class="val">Error: ${vt.error}</p>`;
            return;
        }

        const stats = [
            { label: 'Malicious', val: vt.malicious, color: vt.malicious > 0 ? 'var(--danger)' : 'var(--success)' },
            { label: 'Suspicious', val: vt.suspicious, color: vt.suspicious > 0 ? 'var(--warning)' : 'var(--text-primary)' },
            { label: 'Reputation', val: vt.reputation, color: 'var(--accent-primary)' }
        ];

        stats.forEach(s => {
            const div = document.createElement('div');
            div.className = 'intel-stat';
            div.innerHTML = `<span class="label">${s.label}</span> <span class="val" style="color: ${s.color}">${s.val}</span>`;
            vtStats.appendChild(div);
        });
    }

    function renderAbuse(abuse) {
        abuseStats.innerHTML = '';
        if (abuse.status === 'skipped') {
            abuseStats.innerHTML = '<p class="val">API key missing.</p>';
            return;
        }
        if (abuse.status === 'failed') {
            abuseStats.innerHTML = `<p class="val">Error: ${abuse.error}</p>`;
            return;
        }

        const stats = [
            { label: 'Abuse Score', val: `${abuse.abuseConfidenceScore}%`, color: abuse.abuseConfidenceScore > 20 ? 'var(--danger)' : 'var(--success)' },
            { label: 'Country', val: abuse.country, color: 'inherit' },
            { label: 'ISP', val: abuse.isp, color: 'inherit' },
            { label: 'Whitelisted', val: abuse.isWhitelisted ? 'YES' : 'NO', color: abuse.isWhitelisted ? 'var(--success)' : 'inherit' }
        ];

        stats.forEach(s => {
            const div = document.createElement('div');
            div.className = 'intel-stat';
            div.innerHTML = `<span class="label">${s.label}</span> <span class="val" style="color: ${s.color}">${s.val}</span>`;
            abuseStats.appendChild(div);
        });
    }

    function startLoading() {
        scanBtn.disabled = true;
        btnText.classList.add('hidden');
        btnLoader.classList.remove('hidden');
        loaderSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        errorMsg.classList.add('hidden');
    }

    function stopLoading() {
        scanBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
        loaderSection.classList.add('hidden');
    }

    function showError(msg) {
        errorMsg.textContent = msg;
        errorMsg.classList.remove('hidden');
        setTimeout(() => errorMsg.classList.add('hidden'), 5000);
    }
});
