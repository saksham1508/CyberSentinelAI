const { getDatabase } = require('../database/db');
const fs = require('fs');
const path = require('path');

class ConfigManager {
  constructor() {
    this.config = {};
    this.defaultConfig = {
      // Monitoring settings
      monitoring_interval_minutes: 5,
      monitoring_enabled: true,

      // Threat detection thresholds
      max_suspicious_connections: 10,
      alert_on_high_severity: true,
      alert_on_medium_severity: false,

      // AI settings
      ai_enabled: true,
      ai_confidence_threshold: 0.7,

      // Logging settings
      log_level: 'info',
      log_max_files: 10,
      log_max_size: '10m',

      // Network monitoring
      network_monitoring_enabled: true,
      suspicious_ports: '22,23,3389,5900',

      // Log analysis
      log_analysis_enabled: true,
      keyword_sensitivity: 'medium',

      // Notification settings
      email_notifications: false,
      email_recipient: '',
      smtp_server: '',
      smtp_port: 587,

      // System settings
      max_concurrent_scans: 3,
      scan_timeout_seconds: 30
    };
  }

  async loadConfig() {
    try {
      // Load from database
      const rows = await this.getAllConfigFromDB();
      this.config = { ...this.defaultConfig };

      // Override defaults with database values
      rows.forEach(row => {
        this.config[row.key] = this.parseValue(row.value);
      });

      // Load from config file if exists
      await this.loadFromFile();

      return this.config;
    } catch (error) {
      console.error('Failed to load configuration:', error);
      return this.defaultConfig;
    }
  }

  getAllConfigFromDB() {
    return new Promise((resolve, reject) => {
      const db = getDatabase();
      db.all('SELECT key, value FROM configs', (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async loadFromFile() {
    const configPath = path.join(__dirname, '..', 'config.json');
    if (fs.existsSync(configPath)) {
      try {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        this.config = { ...this.config, ...fileConfig };
      } catch (error) {
        console.warn('Failed to load config file:', error.message);
      }
    }
  }

  parseValue(value) {
    // Try to parse as JSON first, then as number, otherwise return as string
    try {
      return JSON.parse(value);
    } catch {
      const numValue = Number(value);
      return isNaN(numValue) ? value : numValue;
    }
  }

  get(key, defaultValue = null) {
    return this.config[key] !== undefined ? this.config[key] : defaultValue;
  }

  async set(key, value) {
    // Update in memory
    this.config[key] = value;

    // Persist to database
    await this.saveToDB(key, value);

    // Update file if it exists
    await this.saveToFile();
  }

  async setMultiple(configUpdates) {
    const updates = Object.entries(configUpdates);

    for (const [key, value] of updates) {
      this.config[key] = value;
    }

    // Batch update database
    const promises = updates.map(([key, value]) => this.saveToDB(key, value));
    await Promise.all(promises);

    // Update file
    await this.saveToFile();
  }

  saveToDB(key, value) {
    return new Promise((resolve, reject) => {
      const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
      const db = getDatabase();
      db.run('INSERT OR REPLACE INTO configs (key, value) VALUES (?, ?)', [key, stringValue], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async saveToFile() {
    const configPath = path.join(__dirname, '..', 'config.json');
    try {
      fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    } catch (error) {
      console.warn('Failed to save config file:', error.message);
    }
  }

  // Convenience methods for common config operations
  getMonitoringInterval() {
    return this.get('monitoring_interval_minutes', 5);
  }

  isMonitoringEnabled() {
    return this.get('monitoring_enabled', true);
  }

  shouldAlertOnSeverity(severity) {
    if (severity === 'High') return this.get('alert_on_high_severity', true);
    if (severity === 'Medium') return this.get('alert_on_medium_severity', false);
    return false;
  }

  getSuspiciousPorts() {
    const ports = this.get('suspicious_ports', '22,23,3389,5900');
    return ports.split(',').map(p => parseInt(p.trim()));
  }

  isAIEnabled() {
    return this.get('ai_enabled', true);
  }

  getAIConfidenceThreshold() {
    return this.get('ai_confidence_threshold', 0.7);
  }

  getLogLevel() {
    return this.get('log_level', 'info');
  }

  getMaxConcurrentScans() {
    return this.get('max_concurrent_scans', 3);
  }

  getScanTimeout() {
    return this.get('scan_timeout_seconds', 30) * 1000; // Convert to milliseconds
  }

  // Validation methods
  validateConfig() {
    const errors = [];

    if (this.get('monitoring_interval_minutes') < 1) {
      errors.push('Monitoring interval must be at least 1 minute');
    }

    if (this.get('ai_confidence_threshold') < 0 || this.get('ai_confidence_threshold') > 1) {
      errors.push('AI confidence threshold must be between 0 and 1');
    }

    const validLogLevels = ['error', 'warn', 'info', 'debug'];
    if (!validLogLevels.includes(this.get('log_level'))) {
      errors.push('Invalid log level. Must be one of: ' + validLogLevels.join(', '));
    }

    return errors;
  }

  // Reset to defaults
  async resetToDefaults() {
    this.config = { ...this.defaultConfig };
    await this.clearDatabaseConfig();
    await this.saveToFile();
  }

  clearDatabaseConfig() {
    return new Promise((resolve, reject) => {
      const db = getDatabase();
      db.run('DELETE FROM configs', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  // Export config for backup/sharing
  exportConfig() {
    return { ...this.config };
  }

  // Import config
  async importConfig(newConfig) {
    // Validate the imported config
    const tempConfig = { ...this.defaultConfig, ...newConfig };
    const originalConfig = { ...this.config };

    try {
      this.config = tempConfig;
      const errors = this.validateConfig();

      if (errors.length > 0) {
        throw new Error('Invalid configuration: ' + errors.join(', '));
      }

      await this.setMultiple(tempConfig);
    } catch (error) {
      // Restore original config on error
      this.config = originalConfig;
      throw error;
    }
  }
}

module.exports = ConfigManager;