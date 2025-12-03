const logger = require('../utils/loggerSetup')('incident-orchestrator');

function getDb() {
  return require('../database/db').getDatabase();
}

class IncidentResponseOrchestrator {
  constructor() {
    this.responseStrategies = {
      'DDoS': this.handleDDoS.bind(this),
      'Intrusion': this.handleIntrusion.bind(this),
      'Malware': this.handleMalware.bind(this),
      'Credential Compromise': this.handleCredentialCompromise.bind(this),
      'Suspicious Connection': this.handleSuspiciousConnection.bind(this)
    };

    this.responseStatuses = new Map();
  }

  async orchestrateResponse(threat, config = {}) {
    const incidentId = await this.createIncident(threat);

    if (!incidentId) {
      logger.error('Failed to create incident for threat:', threat.id);
      return null;
    }

    const strategy = this.responseStrategies[threat.type];
    if (!strategy) {
      logger.warn(`No response strategy for threat type: ${threat.type}`);
      return this.defaultResponse(threat, incidentId);
    }

    const responses = await strategy(threat, incidentId, config);
    await this.updateIncidentResponse(incidentId, responses);

    return {
      incidentId,
      responses,
      status: 'initiated'
    };
  }

  async handleDDoS(threat, incidentId, config) {
    logger.warn(`Initiating DDoS response for incident ${incidentId}`);
    const responses = [
      {
        action: 'rate_limiting',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'ip_blocking',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'traffic_filtering',
        target: threat.destination_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'alert_notification',
        recipient: config.alertEmail || 'admin@sentinel.local',
        message: `DDoS attack detected from ${threat.source_ip}. Automatic mitigation activated.`,
        status: 'pending',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async handleIntrusion(threat, incidentId, config) {
    logger.warn(`Initiating Intrusion response for incident ${incidentId}`);
    const responses = [
      {
        action: 'isolate_source',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'capture_traffic',
        target: `${threat.source_ip}:${threat.port}`,
        duration: 3600,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'enable_forensics',
        incidentId,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'escalate_alert',
        severity: 'Critical',
        status: 'pending',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async handleMalware(threat, incidentId, config) {
    logger.warn(`Initiating Malware response for incident ${incidentId}`);
    const responses = [
      {
        action: 'quarantine_process',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'isolate_host',
        target: threat.source_ip,
        duration: 86400,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'initiate_scan',
        scope: 'network_wide',
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'update_signatures',
        status: 'enabled',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async handleCredentialCompromise(threat, incidentId, config) {
    logger.warn(`Initiating Credential Compromise response for incident ${incidentId}`);
    const responses = [
      {
        action: 'force_password_reset',
        scope: 'affected_users',
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'revoke_sessions',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'enable_mfa',
        scope: 'affected_accounts',
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'audit_access',
        timeWindow: 86400,
        status: 'enabled',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async handleSuspiciousConnection(threat, incidentId, config) {
    logger.warn(`Initiating Suspicious Connection response for incident ${incidentId}`);
    const responses = [
      {
        action: 'monitor_connection',
        target: `${threat.source_ip}:${threat.port}`,
        duration: 3600,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'enable_logging',
        target: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'create_alert_rule',
        pattern: threat.source_ip,
        status: 'enabled',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async defaultResponse(threat, incidentId) {
    logger.info(`Using default response for incident ${incidentId}`);
    const responses = [
      {
        action: 'log_event',
        target: threat.id,
        status: 'enabled',
        timestamp: new Date().toISOString()
      },
      {
        action: 'create_alert',
        severity: threat.severity,
        status: 'enabled',
        timestamp: new Date().toISOString()
      }
    ];

    return responses;
  }

  async createIncident(threat) {
    return new Promise((resolve) => {
      const db = getDb();
      db.run(
        `INSERT INTO incidents (threat_id, status, response) VALUES (?, ?, ?)`,
        [threat.id, 'Active', 'Automated response initiated'],
        function(err) {
          if (err) {
            logger.error('Failed to create incident:', err);
            resolve(null);
          } else {
            resolve(this.lastID);
          }
        }
      );
    });
  }

  async updateIncidentResponse(incidentId, responses) {
    return new Promise((resolve) => {
      const db = getDb();
      const responseData = JSON.stringify(responses);
      db.run(
        `UPDATE incidents SET response = ? WHERE id = ?`,
        [responseData, incidentId],
        (err) => {
          if (err) {
            logger.error('Failed to update incident response:', err);
          }
          resolve();
        }
      );
    });
  }

  async getResponseStatus(incidentId) {
    return new Promise((resolve) => {
      const db = getDb();
      db.get(
        `SELECT id, status, response FROM incidents WHERE id = ?`,
        [incidentId],
        (err, row) => {
          if (err) {
            resolve(null);
          } else {
            resolve(row ? {
              incidentId: row.id,
              status: row.status,
              responses: JSON.parse(row.response || '[]')
            } : null);
          }
        }
      );
    });
  }

  async closeIncident(incidentId, resolution) {
    return new Promise((resolve) => {
      const db = getDb();
      db.run(
        `UPDATE incidents SET status = ? WHERE id = ?`,
        ['Closed', incidentId],
        (err) => {
          if (err) {
            logger.error('Failed to close incident:', err);
            resolve(false);
          } else {
            logger.info(`Incident ${incidentId} closed with resolution: ${resolution}`);
            resolve(true);
          }
        }
      );
    });
  }
}

module.exports = IncidentResponseOrchestrator;
