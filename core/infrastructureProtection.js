const logger = require('../utils/loggerSetup')('infrastructure-protection');

function getDb() {
  return require('../database/db').getDatabase();
}

class InfrastructureProtection {
  constructor() {
    this.criticalAssets = new Map();
    this.protectionStrategies = new Map();
    this.assetHealth = new Map();
    this.initializeCriticalAssets();
  }

  initializeCriticalAssets() {
    const criticalAssets = [
      {
        id: 'asset_database',
        name: 'Primary Database Server',
        type: 'database',
        ports: [3306, 5432, 27017],
        protectionLevel: 'critical',
        dependents: ['web_server', 'api_server']
      },
      {
        id: 'asset_web_server',
        name: 'Web Server',
        type: 'web',
        ports: [80, 443],
        protectionLevel: 'high',
        dependents: ['load_balancer']
      },
      {
        id: 'asset_api_server',
        name: 'API Server',
        type: 'api',
        ports: [3000, 8000, 8080],
        protectionLevel: 'high',
        dependents: []
      },
      {
        id: 'asset_auth_server',
        name: 'Authentication Server',
        type: 'auth',
        ports: [389, 636],
        protectionLevel: 'critical',
        dependents: ['web_server', 'api_server']
      },
      {
        id: 'asset_dns_server',
        name: 'DNS Server',
        type: 'dns',
        ports: [53],
        protectionLevel: 'critical',
        dependents: []
      },
      {
        id: 'asset_firewall',
        name: 'Firewall',
        type: 'firewall',
        ports: [],
        protectionLevel: 'critical',
        dependents: []
      }
    ];

    criticalAssets.forEach(asset => {
      this.criticalAssets.set(asset.id, asset);
      this.assetHealth.set(asset.id, {
        status: 'healthy',
        lastChecked: Date.now(),
        threats: [],
        uptime: 100
      });
      this.setupProtectionStrategy(asset);
    });

    logger.info(`Initialized ${criticalAssets.length} critical assets`);
  }

  setupProtectionStrategy(asset) {
    const strategy = {
      assetId: asset.id,
      protectionLevel: asset.protectionLevel,
      measures: this.generateProtectionMeasures(asset),
      monitoring: true,
      redundancy: asset.protectionLevel === 'critical',
      backupFrequency: asset.protectionLevel === 'critical' ? 'hourly' : 'daily'
    };

    this.protectionStrategies.set(asset.id, strategy);
  }

  generateProtectionMeasures(asset) {
    const baseMeasures = [
      { name: 'rate_limiting', enabled: true, threshold: 1000 },
      { name: 'request_validation', enabled: true },
      { name: 'encryption', enabled: true },
      { name: 'access_control', enabled: true }
    ];

    if (asset.protectionLevel === 'critical') {
      baseMeasures.push(
        { name: 'redundancy', enabled: true },
        { name: 'failover', enabled: true },
        { name: 'health_checks', enabled: true, interval: 30000 },
        { name: 'traffic_inspection', enabled: true }
      );
    }

    if (asset.type === 'database') {
      baseMeasures.push(
        { name: 'sql_injection_prevention', enabled: true },
        { name: 'query_logging', enabled: true },
        { name: 'backup_encryption', enabled: true }
      );
    }

    if (asset.type === 'web') {
      baseMeasures.push(
        { name: 'waf_enabled', enabled: true },
        { name: 'ddos_protection', enabled: true },
        { name: 'ssl_tls_enforcement', enabled: true }
      );
    }

    return baseMeasures;
  }

  assessThreatToAsset(threat, asset) {
    const severity = {
      'Critical': 1.0,
      'High': 0.75,
      'Medium': 0.5,
      'Low': 0.25
    };

    const portMatch = asset.ports.includes(parseInt(threat.port));
    const typeMatch = this.threatTypeMatchesAsset(threat.type, asset.type);
    const threatScore = severity[threat.severity] || 0.25;

    const riskScore = (portMatch ? 0.5 : 0.2) +
                      (typeMatch ? 0.3 : 0) +
                      threatScore;

    return {
      assetId: asset.id,
      assetName: asset.name,
      threatId: threat.id,
      threatType: threat.type,
      riskScore: Math.min(riskScore, 1.0),
      isDirectThreat: portMatch,
      isTypicalThreat: typeMatch,
      recommendedAction: this.getRecommendedAction(riskScore, asset)
    };
  }

  threatTypeMatchesAsset(threatType, assetType) {
    const mappings = {
      'database': ['SQL Injection', 'Intrusion', 'Credential Compromise'],
      'web': ['DDoS', 'Web Attack', 'Intrusion'],
      'api': ['API Abuse', 'Intrusion', 'DDoS'],
      'auth': ['Credential Compromise', 'Brute Force', 'Intrusion'],
      'dns': ['DNS Spoofing', 'DDoS', 'Cache Poisoning'],
      'firewall': ['Network Intrusion', 'Port Scanning', 'DDoS']
    };

    return mappings[assetType]?.some(type => threatType.includes(type)) || false;
  }

  getRecommendedAction(riskScore, asset) {
    if (riskScore > 0.8) {
      return {
        priority: 'immediate',
        actions: [
          'Isolate asset from network',
          'Activate failover systems',
          'Enable enhanced monitoring',
          'Escalate to security team'
        ]
      };
    } else if (riskScore > 0.5) {
      return {
        priority: 'high',
        actions: [
          'Increase monitoring intensity',
          'Apply defensive rules',
          'Prepare incident response',
          'Alert security team'
        ]
      };
    } else {
      return {
        priority: 'medium',
        actions: [
          'Continue standard monitoring',
          'Log event for analysis',
          'Update threat intelligence'
        ]
      };
    }
  }

  assessAssetHealth(assetId) {
    const asset = this.criticalAssets.get(assetId);
    if (!asset) return null;

    const health = this.assetHealth.get(assetId);
    const strategy = this.protectionStrategies.get(assetId);

    return {
      assetId,
      assetName: asset.name,
      status: health.status,
      uptime: health.uptime,
      activeThreats: health.threats.length,
      protectionLevel: asset.protectionLevel,
      activeMeasures: strategy.measures.filter(m => m.enabled).length,
      totalMeasures: strategy.measures.length,
      lastChecked: new Date(health.lastChecked).toISOString(),
      recommendedActions: health.threats.length > 0 ? 
        ['Review active threats', 'Verify protection measures are active'] : 
        ['Status normal', 'Continue monitoring']
    };
  }

  updateAssetHealth(assetId, healthData) {
    if (this.assetHealth.has(assetId)) {
      const current = this.assetHealth.get(assetId);
      this.assetHealth.set(assetId, {
        ...current,
        ...healthData,
        lastChecked: Date.now()
      });
      logger.info(`Updated health for asset: ${assetId}`);
    }
  }

  recordThreatToAsset(threat, assetId) {
    const asset = this.criticalAssets.get(assetId);
    if (!asset) return;

    const assessment = this.assessThreatToAsset(threat, asset);
    const health = this.assetHealth.get(assetId);

    health.threats.push({
      threatId: threat.id,
      threatType: threat.type,
      riskScore: assessment.riskScore,
      timestamp: Date.now()
    });

    if (health.threats.length > 100) {
      health.threats.shift();
    }

    this.assetHealth.set(assetId, health);
  }

  protectCriticalAssets(threats) {
    const protectionActions = [];

    for (const threat of threats) {
      for (const [assetId, asset] of this.criticalAssets) {
        const assessment = this.assessThreatToAsset(threat, asset);

        if (assessment.riskScore > 0.5) {
          this.recordThreatToAsset(threat, assetId);
          protectionActions.push({
            assetId,
            assetName: asset.name,
            threatId: threat.id,
            threatType: threat.type,
            riskScore: assessment.riskScore,
            recommendedAction: assessment.recommendedAction,
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    return protectionActions;
  }

  getInfrastructureStatus() {
    const assets = Array.from(this.criticalAssets.values());
    const statuses = assets.map(asset => {
      const health = this.assetHealth.get(asset.id);
      return {
        id: asset.id,
        name: asset.name,
        type: asset.type,
        status: health?.status || 'unknown',
        uptime: health?.uptime || 0,
        threats: health?.threats.length || 0
      };
    });

    const criticalThreats = statuses.reduce((sum, s) => sum + s.threats, 0);
    const healthyAssets = statuses.filter(s => s.status === 'healthy').length;

    return {
      totalAssets: assets.length,
      healthyAssets,
      atRiskAssets: assets.length - healthyAssets,
      activeCriticalThreats: criticalThreats,
      assets: statuses,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = InfrastructureProtection;
