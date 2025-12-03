const NetworkMonitor = require('./networkMonitor');
const LogAnalyzer = require('./logAnalyzer');
const AnomalyDetector = require('../ai/anomalyDetector');

function getDb() {
  return require('../database/db').getDatabase();
}

class ThreatDetector {
  constructor() {
    this.networkMonitor = new NetworkMonitor();
    this.logAnalyzer = new LogAnalyzer();
    this.anomalyDetector = new AnomalyDetector();
  }

  async detectThreats() {
    const networkResult = await this.networkMonitor.run();
    const logThreats = await this.logAnalyzer.run();

    const allThreats = [...networkResult.threats, ...logThreats];

    // AI-enhanced classification (placeholder)
    const classifiedThreats = await this.classifyThreats(allThreats);

    return classifiedThreats;
  }

  async classifyThreats(threats) {
    if (!threats || threats.length === 0) {
      return [];
    }

    let analyzedThreats = threats;
    try {
      // Use AI anomaly detector for enhanced classification
      const aiAnalyzed = await this.anomalyDetector.analyzeThreats(threats);
      if (aiAnalyzed && Array.isArray(aiAnalyzed)) {
        analyzedThreats = aiAnalyzed;
      }
    } catch (error) {
      console.error('AI analysis failed, continuing with base threats:', error.message);
    }

    // Apply additional AI-enhanced logic
    const classifiedThreats = analyzedThreats.map(threat => {
      const classified = { ...threat };
      if (classified.aiAnomaly) {
        classified.aiPrediction = 'AI-Detected Anomaly';
        classified.confidence = 'High';
        // Increase severity if AI detects anomaly
        if (classified.severity === 'Low') {
          classified.severity = 'Medium';
        } else if (classified.severity === 'Medium') {
          classified.severity = 'High';
        }
      } else {
        classified.aiPrediction = 'Normal Pattern';
        classified.confidence = 'Medium';
      }

      // Additional rule-based enhancements
      if (classified.severity === 'High') {
        classified.recommendation = 'Immediate investigation required';
      } else if (classified.severity === 'Medium') {
        classified.recommendation = 'Monitor closely';
      } else {
        classified.recommendation = 'Log for reference';
      }
      return classified;
    });

    return classifiedThreats;
  }

  async createIncidents(threats) {
    for (const threat of threats) {
      if (threat.severity === 'High' && threat.id) {
        const db = getDb();
        await new Promise((resolve, reject) => {
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