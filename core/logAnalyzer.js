const natural = require('natural');

function getDb() {
  return require('../database/db').getDatabase();
}

class LogAnalyzer {
  constructor() {
    this.tokenizer = new natural.WordTokenizer();
    this.stemmer = natural.PorterStemmer;
  }

  async analyzeLogs() {
    return new Promise((resolve, reject) => {
      try {
        const db = getDb();
        db.all(`SELECT * FROM logs WHERE timestamp > datetime('now', '-1 hour')`, (err, rows) => {
          if (err) {
            reject(err);
            return;
          }

          const threats = this.detectThreats(rows || []);
          resolve(threats);
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  detectThreats(logs) {
    const threats = [];
    const suspiciousKeywords = ['attack', 'intrusion', 'hack', 'breach', 'exploit', 'malware', 'virus', 'failed login', 'unauthorized', 'error'];

    for (const log of logs) {
      const tokens = this.tokenizer.tokenize(log.message.toLowerCase());
      const stemmed = tokens.map(token => this.stemmer.stem(token));

      for (const keyword of suspiciousKeywords) {
        if (stemmed.includes(this.stemmer.stem(keyword))) {
          threats.push({
            type: 'Log Anomaly',
            severity: 'Medium',
            description: `Suspicious keyword '${keyword}' found in log: ${log.message}`,
            source_ip: log.ip,
            protocol: 'N/A',
            port: null
          });
          break;
        }
      }

      // Check for repeated errors
      if (log.level === 'error' && this.isRepeatedError(logs, log)) {
        threats.push({
          type: 'Repeated Errors',
          severity: 'Low',
          description: `Repeated error messages: ${log.message}`,
          source_ip: log.ip,
          protocol: 'N/A',
          port: null
        });
      }
    }

    return threats;
  }

  isRepeatedError(logs, currentLog) {
    const similarLogs = logs.filter(log => log.level === 'error' && log.message === currentLog.message);
    return similarLogs.length > 5; // Arbitrary threshold
  }

  async logThreats(threats) {
    try {
      const db = getDb();
      for (const threat of threats) {
        await new Promise((resolve, reject) => {
          db.run(`INSERT INTO threats (type, severity, description, source_ip, protocol, port) VALUES (?, ?, ?, ?, ?, ?)`,
            [threat.type, threat.severity, threat.description, threat.source_ip, threat.protocol, threat.port],
            (err) => {
              if (err) reject(err);
              else resolve();
            });
        });
      }
    } catch (error) {
      throw new Error(`Failed to log threats: ${error.message}`);
    }
  }

  async run() {
    try {
      const threats = await this.analyzeLogs();
      if (threats.length > 0) {
        await this.logThreats(threats);
      }
      return threats;
    } catch (error) {
      console.error('Log analysis error:', error);
      return [];
    }
  }
}

module.exports = LogAnalyzer;