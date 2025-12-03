const API_BASE = '/api';

let threatData = [];
let incidentData = [];
let logsData = [];

document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
    setInterval(refreshDashboard, 30000);
});

async function initializeDashboard() {
    try {
        await updateSystemStatus();
        await loadDashboardData();
        await loadThreats();
        await loadIncidents();
        await loadLogs();
        await loadConfig();
        await loadAIDefenseData();
        await loadInfrastructureData();
        await loadExplainabilityData();
    } catch (error) {
        console.error('Error initializing dashboard:', error);
        showNotification('Failed to initialize dashboard', 'error');
    }
}

function switchTab(tabName, clickElement) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');

    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    if (clickElement) {
        clickElement.classList.add('active');
    } else {
        document.querySelector(`button[onclick="switchTab('${tabName}')"]`)?.classList.add('active');
    }
}

async function updateSystemStatus() {
    try {
        const response = await fetch(`${API_BASE}/status`);
        const data = await response.json();
        const badge = document.getElementById('systemStatus');
        badge.className = 'status-badge healthy';
        badge.textContent = '✓ System Healthy';
    } catch (error) {
        const badge = document.getElementById('systemStatus');
        badge.className = 'status-badge critical';
        badge.textContent = '✗ System Offline';
    }
}

async function loadDashboardData() {
    try {
        const response = await fetch(`${API_BASE}/status`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const stats = data.stats || {};

        document.getElementById('totalThreats').textContent = stats.totalThreats || 0;
        document.getElementById('activeIncidents').textContent = stats.activeIncidents || 0;
        document.getElementById('recentLogs').textContent = stats.recentLogs || 0;
        document.getElementById('highSeverity').textContent = stats.highSeverityThreats || 0;

        await loadThreatAnalytics();
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        document.getElementById('totalThreats').textContent = '0';
        document.getElementById('activeIncidents').textContent = '0';
        document.getElementById('recentLogs').textContent = '0';
        document.getElementById('highSeverity').textContent = '0';
    }
}

async function loadThreatAnalytics() {
    try {
        const typeResponse = await fetch(`${API_BASE}/analytics/threats-by-type`);
        const typeData = typeResponse.ok ? await typeResponse.json() : [];

        const severityResponse = await fetch(`${API_BASE}/analytics/threats-by-severity`);
        const severityData = severityResponse.ok ? await severityResponse.json() : [];

        renderChart('threatsByType', typeData);
        renderChart('threatsBySeverity', severityData);
    } catch (error) {
        console.error('Failed to load threat analytics:', error);
        renderChart('threatsByType', []);
        renderChart('threatsBySeverity', []);
    }
}

function renderChart(elementId, data) {
    const container = document.getElementById(elementId);
    if (!data || data.length === 0) {
        container.innerHTML = '<p>No data available</p>';
        return;
    }

    let html = '<ul style="list-style: none; padding: 0;">';
    data.forEach(item => {
        const label = item.type || item.severity;
        const count = item.count;
        const percentage = Math.round((count / Math.max(...data.map(d => d.count))) * 100);
        html += `
            <li style="margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                    <span>${label}</span>
                    <span style="font-weight: bold;">${count}</span>
                </div>
                <div style="width: 100%; height: 8px; background: #eee; border-radius: 4px; overflow: hidden;">
                    <div style="width: ${percentage}%; height: 100%; background: linear-gradient(90deg, #667eea, #764ba2);"></div>
                </div>
            </li>
        `;
    });
    html += '</ul>';
    container.innerHTML = html;
}

async function loadThreats() {
    try {
        const response = await fetch(`${API_BASE}/threats?limit=50`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        threatData = await response.json();
        displayThreats(threatData);
    } catch (error) {
        console.error('Failed to load threats:', error);
        threatData = [];
        displayEmptyState('threatsList', 'Failed to load threats');
    }
}

function displayThreats(threats) {
    const container = document.getElementById('threatsList');

    if (!threats || threats.length === 0) {
        displayEmptyState('threatsList', 'No threats detected');
        return;
    }

    let html = '';
    threats.forEach(threat => {
        const severityClass = threat.severity.toLowerCase();
        const timestamp = new Date(threat.timestamp).toLocaleString();

        html += `
            <div class="threat-item ${severityClass}">
                <h4>${threat.type}</h4>
                <p>${threat.description}</p>
                <div class="threat-meta">
                    <span class="badge badge-${severityClass}">${threat.severity}</span>
                    ${threat.source_ip ? `<span>IP: ${threat.source_ip}</span>` : ''}
                    ${threat.protocol ? `<span>Protocol: ${threat.protocol}</span>` : ''}
                    ${threat.port ? `<span>Port: ${threat.port}</span>` : ''}
                    <span>Time: ${timestamp}</span>
                    ${threat.aiPrediction ? `<span>🤖 ${threat.aiPrediction}</span>` : ''}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function filterThreats() {
    const searchTerm = document.getElementById('threatFilter').value.toLowerCase();
    const severityFilter = document.getElementById('severityFilter').value;

    const filtered = threatData.filter(threat => {
        const matchesSearch = threat.description.toLowerCase().includes(searchTerm) ||
            threat.type.toLowerCase().includes(searchTerm);
        const matchesSeverity = !severityFilter || threat.severity === severityFilter;
        return matchesSearch && matchesSeverity;
    });

    displayThreats(filtered);
}

async function loadIncidents() {
    try {
        const response = await fetch(`${API_BASE}/incidents?limit=50`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        incidentData = await response.json();
        displayIncidents(incidentData);
    } catch (error) {
        console.error('Failed to load incidents:', error);
        incidentData = [];
        displayEmptyState('incidentsList', 'Failed to load incidents');
    }
}

function displayIncidents(incidents) {
    const container = document.getElementById('incidentsList');

    if (!incidents || incidents.length === 0) {
        displayEmptyState('incidentsList', 'No incidents');
        return;
    }

    let html = '';
    incidents.forEach(incident => {
        const statusClass = incident.status.toLowerCase();
        const timestamp = new Date(incident.timestamp).toLocaleString();

        html += `
            <div class="incident-item ${statusClass}">
                <h4>Incident #${incident.id}</h4>
                <p>Threat: ${incident.threat_type || 'Unknown'}</p>
                <div class="incident-meta">
                    <span class="badge badge-${statusClass}">${incident.status}</span>
                    ${incident.severity ? `<span class="badge badge-${incident.severity.toLowerCase()}">${incident.severity}</span>` : ''}
                    <span>Created: ${timestamp}</span>
                    ${incident.response ? `<span>Response: ${incident.response}</span>` : ''}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function filterIncidents() {
    const statusFilter = document.getElementById('incidentStatusFilter').value;

    const filtered = incidentData.filter(incident => {
        return !statusFilter || incident.status === statusFilter;
    });

    displayIncidents(filtered);
}

async function loadLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs?limit=100`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        logsData = await response.json();
        displayLogs(logsData);
    } catch (error) {
        console.error('Failed to load logs:', error);
        logsData = [];
        displayEmptyState('logsList', 'Failed to load logs');
    }
}

function displayLogs(logs) {
    const container = document.getElementById('logsList');

    if (!logs || logs.length === 0) {
        displayEmptyState('logsList', 'No logs available');
        return;
    }

    let html = '';
    logs.forEach(log => {
        const levelBadgeClass = `badge-${log.level}`;
        const timestamp = new Date(log.timestamp).toLocaleString();

        html += `
            <div class="log-item">
                <div class="log-message">${log.message}</div>
                <div class="log-meta">
                    <span class="badge badge-${log.level}">${log.level.toUpperCase()}</span>
                    <span>Source: ${log.source || 'unknown'}</span>
                    ${log.ip ? `<span>IP: ${log.ip}</span>` : ''}
                    <span>Time: ${timestamp}</span>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function filterLogs() {
    const levelFilter = document.getElementById('logLevelFilter').value;

    const filtered = logsData.filter(log => {
        return !levelFilter || log.level === levelFilter;
    });

    displayLogs(filtered);
}

async function loadConfig() {
    try {
        const response = await fetch(`${API_BASE}/config`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const config = await response.json();
        displayConfig(config);
    } catch (error) {
        console.error('Failed to load config:', error);
        const defaultConfig = {
            monitoring_interval_minutes: 5,
            monitoring_enabled: true,
            alert_on_high_severity: true,
            alert_on_medium_severity: false,
            ai_enabled: true,
            ai_confidence_threshold: 0.7
        };
        displayConfig(defaultConfig);
    }
}

function displayConfig(config) {
    const container = document.getElementById('configForm');

    let html = '';
    Object.entries(config).forEach(([key, value]) => {
        const inputType = typeof value === 'boolean' ? 'checkbox' : 'text';
        const checked = value ? 'checked' : '';

        html += `
            <div class="form-group">
                <label for="${key}">${formatLabel(key)}</label>
                ${inputType === 'checkbox' ? 
                    `<input type="checkbox" id="${key}" data-key="${key}" ${checked} onchange="saveConfig()">` :
                    `<input type="text" id="${key}" data-key="${key}" value="${value}" onchange="saveConfig()">`
                }
            </div>
        `;
    });

    container.innerHTML = html;
}

function formatLabel(key) {
    return key
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

async function saveConfig() {
    const configUpdates = {};
    document.querySelectorAll('[data-key]').forEach(element => {
        const key = element.dataset.key;
        if (element.type === 'checkbox') {
            configUpdates[key] = element.checked;
        } else {
            configUpdates[key] = element.value;
        }
    });

    try {
        const response = await fetch(`${API_BASE}/config`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(configUpdates)
        });

        if (response.ok) {
            showNotification('Configuration saved successfully', 'success');
        } else {
            showNotification('Failed to save configuration', 'error');
        }
    } catch (error) {
        console.error('Failed to save config:', error);
        showNotification('Error saving configuration', 'error');
    }
}

async function runManualScan() {
    try {
        showNotification('Starting manual scan...', 'success');

        const response = await fetch(`${API_BASE}/threats/scan`, {
            method: 'POST'
        });

        if (response.ok) {
            const data = await response.json();
            showNotification(`Scan complete. Found ${data.totalFound} threats.`, 'success');
            setTimeout(() => {
                loadDashboardData();
                loadThreats();
            }, 1000);
        } else {
            showNotification('Scan failed', 'error');
        }
    } catch (error) {
        console.error('Failed to run scan:', error);
        showNotification('Error running scan', 'error');
    }
}

async function refreshDashboard() {
    try {
        await updateSystemStatus();
        await loadDashboardData();
        await loadThreats();
        await loadIncidents();
        await loadLogs();
        await loadAIDefenseData();
        await loadInfrastructureData();
        await loadExplainabilityData();
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
    }
}

function displayEmptyState(elementId, message) {
    const container = document.getElementById(elementId);
    container.innerHTML = `<div class="empty-state"><p>${message}</p></div>`;
}

function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification show ${type}`;

    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

async function loadAIDefenseData() {
    try {
        const [behavioralStats, rulesStats] = await Promise.all([
            fetch(`${API_BASE}/ai/behavioral-analytics/stats`).then(r => r.json()),
            fetch(`${API_BASE}/ai/security-rules/stats`).then(r => r.json())
        ]);

        if (behavioralStats) {
            document.getElementById('avgAnomaly').textContent = behavioralStats.avgScore || '0';
            document.getElementById('maxAnomaly').textContent = behavioralStats.maxScore || '0';
            document.getElementById('anomalyCount').textContent = behavioralStats.anomalyCount || '0';
        }

        if (rulesStats) {
            const totalRules = rulesStats.length;
            const totalMatches = rulesStats.reduce((sum, r) => sum + r.matches, 0);
            document.getElementById('activeRules').textContent = totalRules;
            document.getElementById('ruleMatches').textContent = totalMatches;
        }
    } catch (error) {
        console.error('Failed to load AI defense data:', error);
    }
}

async function loadSecurityRules() {
    try {
        const response = await fetch(`${API_BASE}/ai/security-rules`);
        const rules = await response.json();

        const rulesList = document.getElementById('securityRulesList');
        rulesList.style.display = rulesList.style.display === 'none' ? 'block' : 'none';

        if (rules && rules.length > 0) {
            rulesList.innerHTML = rules.map(rule => `
                <div class="rule-item">
                    <div class="rule-header">
                        <h4>${rule.name}</h4>
                        <span class="rule-badge ${rule.enabled ? 'active' : 'inactive'}">
                            ${rule.enabled ? 'Active' : 'Inactive'}
                        </span>
                    </div>
                    <p>Type: ${rule.actionType}</p>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Failed to load security rules:', error);
        showNotification('Error loading security rules', 'error');
    }
}

async function loadInfrastructureData() {
    try {
        const response = await fetch(`${API_BASE}/ai/infrastructure/status`);
        const infrastructure = await response.json();

        document.getElementById('totalAssets').textContent = infrastructure.totalAssets || '0';
        document.getElementById('healthyAssets').textContent = infrastructure.healthyAssets || '0';
        document.getElementById('atRiskAssets').textContent = infrastructure.atRiskAssets || '0';
        document.getElementById('activeThreatCount').textContent = infrastructure.activeCriticalThreats || '0';

        if (infrastructure.assets && infrastructure.assets.length > 0) {
            const assetsList = document.getElementById('assetsList');
            assetsList.innerHTML = infrastructure.assets.map(asset => `
                <div class="asset-card ${asset.status === 'healthy' ? 'healthy' : 'at-risk'}">
                    <div class="asset-name">${asset.name}</div>
                    <div class="asset-details">
                        <span>Status: ${asset.status}</span>
                        <span>Uptime: ${asset.uptime}%</span>
                        <span>Active Threats: ${asset.threats}</span>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Failed to load infrastructure data:', error);
    }
}

async function loadExplainabilityData() {
    try {
        const [report, predictions] = await Promise.all([
            fetch(`${API_BASE}/ai/explainability/report`).then(r => r.json()),
            fetch(`${API_BASE}/ai/explainability/predictions`).then(r => r.json())
        ]);

        if (report) {
            document.getElementById('totalPreds').textContent = report.totalPredictions || '0';
            document.getElementById('avgConfidence').textContent = report.averageConfidence || '0';
            const biasCount = report.predictionBreakdown?.biasDetected || 0;
            document.getElementById('biasCount').textContent = biasCount;
        }

        if (predictions && predictions.length > 0) {
            const explanationsList = document.getElementById('explanationsList');
            explanationsList.innerHTML = predictions.slice(0, 10).map(pred => `
                <div class="explanation-item">
                    <div class="explanation-header">
                        <span class="threat-type">${pred.threatType}</span>
                        <span class="confidence">Confidence: ${(pred.confidence * 100).toFixed(1)}%</span>
                    </div>
                    <p class="prediction">${pred.prediction}</p>
                    ${pred.reasoning ? `<p class="reasoning">Reason: ${pred.reasoning.summary || ''}</p>` : ''}
                    ${pred.biasRisk?.riskDetected ? `<div class="bias-warning">⚠️ Potential bias detected</div>` : ''}
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Failed to load explainability data:', error);
    }
}
