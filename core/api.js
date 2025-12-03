const express = require('express');
const { getDatabase } = require('../database/db');
const ThreatDetector = require('./threatDetector');

class API {
  constructor(threatDetector) {
    this.threatDetector = threatDetector;
    this.router = express.Router();
    this.setupRoutes();
  }

  setupRoutes() {
    // Threat monitoring endpoints
    this.router.get('/threats', this.getThreats.bind(this));
    this.router.get('/threats/:id', this.getThreatById.bind(this));
    this.router.post('/threats/scan', this.scanThreats.bind(this));
    this.router.delete('/threats/:id', this.deleteThreat.bind(this));

    // Log management endpoints
    this.router.get('/logs', this.getLogs.bind(this));
    this.router.get('/logs/recent', this.getRecentLogs.bind(this));
    this.router.post('/logs', this.createLog.bind(this));

    // Incident management endpoints
    this.router.get('/incidents', this.getIncidents.bind(this));
    this.router.get('/incidents/:id', this.getIncidentById.bind(this));
    this.router.post('/incidents', this.createIncident.bind(this));
    this.router.put('/incidents/:id/status', this.updateIncidentStatus.bind(this));

    // System status and configuration
    this.router.get('/status', this.getSystemStatus.bind(this));
    this.router.get('/config', this.getConfig.bind(this));
    this.router.put('/config', this.updateConfig.bind(this));

    // Analytics endpoints
    this.router.get('/analytics/threats-by-type', this.getThreatsByType.bind(this));
    this.router.get('/analytics/threats-by-severity', this.getThreatsBySeverity.bind(this));
    this.router.get('/analytics/threats-timeline', this.getThreatsTimeline.bind(this));
  }

  // Threat endpoints
  async getThreats(req, res) {
    try {
      const { limit = 50, offset = 0, severity, type } = req.query;

      let query = 'SELECT * FROM threats WHERE 1=1';
      const params = [];

      if (severity) {
        query += ' AND severity = ?';
        params.push(severity);
      }

      if (type) {
        query += ' AND type = ?';
        params.push(type);
      }

      query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
      params.push(parseInt(limit), parseInt(offset));

      getDatabase().all(query, params, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch threats' });
        }
        res.json(rows || []);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getThreatById(req, res) {
    try {
      const { id } = req.params;
      getDatabase().get('SELECT * FROM threats WHERE id = ?', [id], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch threat' });
        }
        if (!row) {
          return res.status(404).json({ error: 'Threat not found' });
        }
        res.json(row);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async scanThreats(req, res) {
    try {
      const threats = await this.threatDetector.run();
      res.json({
        threats,
        scanTime: new Date().toISOString(),
        totalFound: threats.length
      });
    } catch (error) {
      res.status(500).json({ error: 'Scan failed' });
    }
  }

  async deleteThreat(req, res) {
    try {
      const { id } = req.params;
      getDatabase().run('DELETE FROM threats WHERE id = ?', [id], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to delete threat' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ error: 'Threat not found' });
        }
        res.json({ message: 'Threat deleted successfully' });
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // Log endpoints
  async getLogs(req, res) {
    try {
      const { limit = 100, offset = 0, level, source } = req.query;

      let query = 'SELECT * FROM logs WHERE 1=1';
      const params = [];

      if (level) {
        query += ' AND level = ?';
        params.push(level);
      }

      if (source) {
        query += ' AND source = ?';
        params.push(source);
      }

      query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
      params.push(parseInt(limit), parseInt(offset));

      getDatabase().all(query, params, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch logs' });
        }
        res.json(rows);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getRecentLogs(req, res) {
    try {
      const hours = req.query.hours || 1;
      getDatabase().all(`SELECT * FROM logs WHERE timestamp > datetime('now', '-${hours} hours') ORDER BY timestamp DESC`,
        (err, rows) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to fetch recent logs' });
          }
          res.json(rows);
        });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async createLog(req, res) {
    try {
      const { source, level, message, ip, user_agent } = req.body;

      if (!source || !level || !message) {
        return res.status(400).json({ error: 'Source, level, and message are required' });
      }

      getDatabase().run(`INSERT INTO logs (source, level, message, ip, user_agent) VALUES (?, ?, ?, ?, ?)`,
        [source, level, message, ip, user_agent], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create log' });
          }
          res.status(201).json({ id: this.lastID, message: 'Log created successfully' });
        });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // Incident endpoints
  async getIncidents(req, res) {
    try {
      const { status, limit = 50, offset = 0 } = req.query;

      let query = `SELECT incidents.*, threats.type as threat_type, threats.severity, threats.description
                   FROM incidents
                   LEFT JOIN threats ON incidents.threat_id = threats.id
                   WHERE 1=1`;
      const params = [];

      if (status) {
        query += ' AND incidents.status = ?';
        params.push(status);
      }

      query += ' ORDER BY incidents.timestamp DESC LIMIT ? OFFSET ?';
      params.push(parseInt(limit), parseInt(offset));

      getDatabase().all(query, params, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch incidents' });
        }
        res.json(rows);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getIncidentById(req, res) {
    try {
      const { id } = req.params;
      getDatabase().get(`SELECT incidents.*, threats.type as threat_type, threats.severity, threats.description
              FROM incidents
              LEFT JOIN threats ON incidents.threat_id = threats.id
              WHERE incidents.id = ?`, [id], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch incident' });
        }
        if (!row) {
          return res.status(404).json({ error: 'Incident not found' });
        }
        res.json(row);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async createIncident(req, res) {
    try {
      const { threat_id, status = 'Open', response } = req.body;

      if (!threat_id) {
        return res.status(400).json({ error: 'Threat ID is required' });
      }

      getDatabase().run(`INSERT INTO incidents (threat_id, status, response) VALUES (?, ?, ?)`,
        [threat_id, status, response], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create incident' });
          }
          res.status(201).json({ id: this.lastID, message: 'Incident created successfully' });
        });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async updateIncidentStatus(req, res) {
    try {
      const { id } = req.params;
      const { status, response } = req.body;

      if (!status) {
        return res.status(400).json({ error: 'Status is required' });
      }

      getDatabase().run(`UPDATE incidents SET status = ?, response = ? WHERE id = ?`,
        [status, response, id], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to update incident' });
          }
          if (this.changes === 0) {
            return res.status(404).json({ error: 'Incident not found' });
          }
          res.json({ message: 'Incident updated successfully' });
        });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // System endpoints
  async getSystemStatus(req, res) {
    try {
      // Get some basic stats
      const stats = await this.getSystemStats();
      res.json({
        status: 'running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        stats
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get system status' });
    }
  }

  async getSystemStats() {
    return new Promise((resolve, reject) => {
      const queries = {
        totalThreats: 'SELECT COUNT(*) as count FROM threats',
        activeIncidents: 'SELECT COUNT(*) as count FROM incidents WHERE status = "Open"',
        recentLogs: 'SELECT COUNT(*) as count FROM logs WHERE timestamp > datetime("now", "-1 hour")',
        highSeverityThreats: 'SELECT COUNT(*) as count FROM threats WHERE severity = "High" AND timestamp > datetime("now", "-24 hours")'
      };

      const results = {};
      let completed = 0;
      const total = Object.keys(queries).length;

      Object.entries(queries).forEach(([key, query]) => {
        getDatabase().get(query, (err, row) => {
          if (err) {
            reject(err);
            return;
          }
          results[key] = row.count;
          completed++;
          if (completed === total) {
            resolve(results);
          }
        });
      });
    });
  }

  parseValue(value) {
    try {
      return JSON.parse(value);
    } catch {
      const numValue = Number(value);
      return isNaN(numValue) ? value : numValue;
    }
  }

  async getConfig(req, res) {
    try {
      getDatabase().all('SELECT key, value FROM configs', (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch config' });
        }
        const config = this.getDefaultConfig();
        if (rows && rows.length > 0) {
          rows.forEach(row => {
            config[row.key] = this.parseValue(row.value);
          });
        }
        res.json(config);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  getDefaultConfig() {
    return {
      monitoring_interval_minutes: 5,
      monitoring_enabled: true,
      max_suspicious_connections: 10,
      alert_on_high_severity: true,
      alert_on_medium_severity: false,
      ai_enabled: true,
      ai_confidence_threshold: 0.7,
      log_level: 'info',
      log_max_files: 10,
      log_max_size: '10m',
      network_monitoring_enabled: true,
      suspicious_ports: '22,23,3389,5900',
      log_analysis_enabled: true,
      keyword_sensitivity: 'medium',
      email_notifications: false,
      email_recipient: '',
      smtp_server: '',
      smtp_port: 587,
      max_concurrent_scans: 3,
      scan_timeout_seconds: 30
    };
  }

  async updateConfig(req, res) {
    try {
      const updates = req.body;
      const promises = Object.entries(updates).map(([key, value]) => {
        return new Promise((resolve, reject) => {
          const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
          const db = getDatabase();
          db.run('INSERT OR REPLACE INTO configs (key, value) VALUES (?, ?)', [key, stringValue], function(err) {
            if (err) {
              console.error('Error updating config:', key, err);
              reject(err);
            } else {
              resolve();
            }
          });
        });
      });

      await Promise.all(promises);
      res.json({ message: 'Configuration updated successfully' });
    } catch (error) {
      console.error('Config update error:', error);
      res.status(500).json({ error: 'Failed to update configuration', details: error.message });
    }
  }

  // Analytics endpoints
  async getThreatsByType(req, res) {
    try {
      getDatabase().all(`SELECT type, COUNT(*) as count FROM threats
              WHERE timestamp > datetime('now', '-30 days')
              GROUP BY type ORDER BY count DESC`, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch threat analytics' });
        }
        res.json(rows);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getThreatsBySeverity(req, res) {
    try {
      getDatabase().all(`SELECT severity, COUNT(*) as count FROM threats
              WHERE timestamp > datetime('now', '-30 days')
              GROUP BY severity ORDER BY count DESC`, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch severity analytics' });
        }
        res.json(rows);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getThreatsTimeline(req, res) {
    try {
      const days = req.query.days || 7;
      getDatabase().all(`SELECT DATE(timestamp) as date, COUNT(*) as count
              FROM threats
              WHERE timestamp > datetime('now', '-${days} days')
              GROUP BY DATE(timestamp)
              ORDER BY date`, (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to fetch timeline data' });
        }
        res.json(rows);
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

module.exports = API;