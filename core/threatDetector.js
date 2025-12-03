const NetworkMonitor = require('./networkMonitor');
const LogAnalyzer = require('./logAnalyzer');
const AnomalyDetector = require('../ai/anomalyDetector');
const BehavioralAnalytics = require('../ai/behavioralAnalytics');
const ExplainabilityEngine = require('../ai/explainabilityEngine');
const SecurityRulesEngine = require('./securityRulesEngine');
const IncidentResponseOrchestrator = require('./incidentResponseOrchestrator');
const InfrastructureProtection = require('./infrastructureProtection');

function getDb() {
  return require('../database/db').getDatabase();
}

class ThreatDetector {
  constructor() {
    this.networkMonitor = new NetworkMonitor();
    this.logAnalyzer = new LogAnalyzer();
    this.anomalyDetector = new AnomalyDetector();
    this.behavioralAnalytics = new BehavioralAnalytics();
    this.explainabilityEngine = new ExplainabilityEngine();
    this.securityRulesEngine = new SecurityRulesEngine();
    this.incidentResponseOrchestrator = new IncidentResponseOrchestrator();
    this.infrastructureProtection = new InfrastructureProtection();
  }

  async detectThreats() {
    const networkResult = await this.networkMonitor.run();
    const logThreats = await this.logAnalyzer.run();

    const allThreats = [...networkResult.threats, ...logThreats];

    // AI-enhanced classification with all modules
    const classifiedThreats = await this.classifyThreats(allThreats);

    return classifiedThreats;
  }

  async classifyThreats(threats) {
    if (!threats || threats.length === 0) {
      return [];
    }

    let analyzedThreats = threats;
    
    try {
      await this.behavioralAnalytics.loadModel();
      await this.anomalyDetector.loadModel();
      
      const aiAnalyzed = await this.anomalyDetector.analyzeThreats(threats);
      if (aiAnalyzed && Array.isArray(aiAnalyzed)) {
        analyzedThreats = aiAnalyzed;
      }

      const behavioralAnomalies = await this.behavioralAnalytics.detectBehavioralAnomalies(analyzedThreats);
      analyzedThreats = behavioralAnomalies.length > 0 ? behavioralAnomalies : analyzedThreats;
    } catch (error) {
      console.error('AI analysis failed, continuing with base threats:', error.message);
    }

    let rulesAppliedThreats = this.securityRulesEngine.applyRules(analyzedThreats);

    const classifiedThreats = rulesAppliedThreats.map(threat => {
      const classified = { ...threat };
      
      if (classified.aiAnomaly || classified.isBehavioralAnomaly) {
        classified.aiPrediction = 'AI-Detected Anomaly';
        classified.confidence = Math.max(
          classified.behavioralAnomalyScore || 0.5,
          0.7
        );

        if (classified.severity === 'Low') {
          classified.severity = 'Medium';
        } else if (classified.severity === 'Medium') {
          classified.severity = 'High';
        }
      } else {
        classified.aiPrediction = 'Normal Pattern';
        classified.confidence = 0.5;
      }

      if (classified.severity === 'High' || classified.severity === 'Critical') {
        classified.recommendation = 'Immediate investigation required';
      } else if (classified.severity === 'Medium') {
        classified.recommendation = 'Monitor closely';
      } else {
        classified.recommendation = 'Log for reference';
      }

      const explanation = this.explainabilityEngine.explainPrediction(
        threat,
        { result: classified.aiPrediction, confidence: classified.confidence },
        this.behavioralAnalytics.extractBehavioralFeatures ? 
          this.behavioralAnalytics.extractBehavioralFeatures(threat, threat.source_ip) : []
      );
      
      classified.explainability = explanation;
      
      return classified;
    });

    const protectionActions = this.infrastructureProtection.protectCriticalAssets(classifiedThreats);
    classifiedThreats.forEach(threat => {
      threat.infrastructureProtection = protectionActions.filter(a => a.threatId === threat.id);
    });

    return classifiedThreats;
  }

  async createIncidents(threats) {
    for (const threat of threats) {
      if ((threat.severity === 'High' || threat.severity === 'Critical') && threat.id) {
        try {
          const responseResult = await this.incidentResponseOrchestrator.orchestrateResponse(threat);
          if (responseResult) {
            console.log(`Incident response initiated for threat ${threat.id}:`, responseResult);
          }
        } catch (error) {
          console.warn('Failed to orchestrate incident response for threat:', threat.id, error);
          
          const db = getDb();
          await new Promise((resolve) => {
            db.run(`INSERT INTO incidents (threat_id, status, response) VALUES (?, ?, ?)`,
              [threat.id, 'Open', 'Automated alert sent'], (err) => {
                if (err) {
                  console.warn('Failed to create incident for threat:', threat.id, err);
                }
                resolve();
              });
          });
        }
      }
    }
  }

  async run() {
    try {
      const threats = await this.detectThreats();
      await this.persistThreats(threats);
      const persistedThreats = await this.getPersistedThreats();
      await this.createIncidents(persistedThreats);
      return persistedThreats;
    } catch (error) {
      console.error('Threat detection error:', error);
      return [];
    }
  }

  async persistThreats(threats) {
    const db = getDb();
    for (const threat of threats) {
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO threats (type, severity, description, source_ip, destination_ip, protocol, port) 
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [threat.type, threat.severity, threat.description, threat.source_ip || null, threat.destination_ip || null, threat.protocol || null, threat.port || null],
          (err) => {
            if (err) {
              console.warn('Failed to persist threat:', err);
            }
            resolve();
          }
        );
      });
    }
  }

  async getPersistedThreats() {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all(
        `SELECT * FROM threats WHERE timestamp > datetime('now', '-1 minute') ORDER BY timestamp DESC`,
        (err, rows) => {
          if (err) {
            console.warn('Failed to retrieve persisted threats:', err);
            resolve([]);
          } else {
            resolve(rows || []);
          }
        }
      );
    });
  }
}

module.exports = ThreatDetector;