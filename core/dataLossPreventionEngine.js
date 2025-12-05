const logger = require('../utils/loggerSetup')('dlp-engine');

function getDb() {
  return require('../database/db').getDatabase();
}

class DataLossPreventionEngine {
  constructor() {
    this.sensitivePatterns = this.initializeSensitivePatterns();
    this.monitoredChannels = new Map();
    this.policyViolations = [];
  }

  async initializeDatabase() {
    return new Promise((resolve, reject) => {
      const db = getDb();
      
      db.run(`CREATE TABLE IF NOT EXISTS dlp_violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        violation_type TEXT,
        channel TEXT,
        data_type TEXT,
        severity TEXT,
        content_summary TEXT,
        remediation_action TEXT,
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, (err) => {
        if (err && !err.message.includes('already exists')) {
          reject(err);
          return;
        }
        
        db.run(`CREATE TABLE IF NOT EXISTS dlp_policies (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          policy_name TEXT UNIQUE,
          enabled INTEGER DEFAULT 1,
          data_types TEXT,
          channels TEXT,
          action TEXT,
          notification_enabled INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(err);
            return;
          }
          resolve();
        });
      });
    });
  }

  initializeSensitivePatterns() {
    return {
      creditCard: {
        pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
        name: 'Credit Card',
        risk: 'critical'
      },
      ssn: {
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        name: 'Social Security Number',
        risk: 'critical'
      },
      apiKey: {
        pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})/gi,
        name: 'API Key',
        risk: 'critical'
      },
      databaseUrl: {
        pattern: /(?:mongodb|mysql|postgres):\/\/[^\s]+/gi,
        name: 'Database Connection String',
        risk: 'critical'
      },
      privateSshKey: {
        pattern: /-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----[\s\S]+-----END (?:RSA|DSA|EC) PRIVATE KEY-----/g,
        name: 'SSH Private Key',
        risk: 'critical'
      },
      awsAccessKey: {
        pattern: /AKIA[0-9A-Z]{16}/g,
        name: 'AWS Access Key',
        risk: 'critical'
      },
      emailAddress: {
        pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        name: 'Email Address',
        risk: 'high'
      },
      phoneNumber: {
        pattern: /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
        name: 'Phone Number',
        risk: 'high'
      },
      ipAddress: {
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        name: 'IP Address',
        risk: 'medium'
      },
      sqlInjectionAttempt: {
        pattern: /(?:union|select|insert|delete|update|drop|create|alter|exec|execute|script|javascript|onerror|onload)\s+(?:all|distinct|from|where|and|or|group|order|by|\*)/gi,
        name: 'SQL Injection Attempt',
        risk: 'critical'
      }
    };
  }

  async scanForSensitiveData(content, source = 'unknown') {
    const detections = [];
    
    if (!content || typeof content !== 'string') {
      return detections;
    }
    
    for (const [key, pattern] of Object.entries(this.sensitivePatterns)) {
      const matches = content.match(pattern.pattern) || [];
      
      if (matches.length > 0) {
        detections.push({
          type: key,
          name: pattern.name,
          risk: pattern.risk,
          matchCount: matches.length,
          source: source,
          timestamp: new Date()
        });
      }
    }
    
    return detections;
  }

  async monitorSocialMediaThreats() {
    const threats = [];
    
    try {
      threats.push(...await this.checkTwitter());
      threats.push(...await this.checkLinkedIn());
      threats.push(...await this.checkReddit());
      threats.push(...await this.checkGithub());
    } catch (error) {
      logger.error('Social media monitoring error:', error);
    }
    
    return threats;
  }

  async checkTwitter() {
    const threats = [];
    
    try {
      if (!process.env.TWITTER_API_KEY) return threats;
      
      const Twit = require('twit');
      const T = new Twit({
        consumer_key: process.env.TWITTER_API_KEY,
        consumer_secret: process.env.TWITTER_API_SECRET,
        access_token: process.env.TWITTER_ACCESS_TOKEN,
        access_token_secret: process.env.TWITTER_ACCESS_TOKEN_SECRET,
        timeout_ms: 60 * 1000
      });
      
      const tweets = await new Promise((resolve) => {
        T.get('search/tweets', { 
          q: process.env.COMPANY_NAME || 'company', 
          count: 100,
          result_type: 'recent'
        }, (err, data) => {
          if (err) {
            logger.warn('Twitter search failed:', err.message);
            resolve([]);
          } else {
            resolve(data.statuses || []);
          }
        });
      });
      
      for (const tweet of tweets) {
        const detections = await this.scanForSensitiveData(tweet.text, 'twitter');
        
        if (detections.length > 0) {
          threats.push({
            platform: 'twitter',
            source: `@${tweet.user.screen_name}`,
            url: `https://twitter.com/${tweet.user.screen_name}/status/${tweet.id_str}`,
            detections: detections,
            severity: Math.max(...detections.map(d => (['critical', 'high'].includes(d.risk) ? 2 : 1))),
            tweetText: tweet.text.substring(0, 100)
          });
        }
      }
    } catch (error) {
      logger.warn('Twitter monitoring failed:', error.message);
    }
    
    return threats;
  }

  async checkLinkedIn() {
    const threats = [];
    
    try {
      if (!process.env.LINKEDIN_API_KEY) return threats;
      
      const axios = require('axios');
      
      const params = {
        keywords: process.env.COMPANY_NAME || 'company',
        fields: 'createdDate,author(localizedFirstName)',
        count: 50
      };
      
      const response = await axios.get('https://api.linkedin.com/v2/search/posts', {
        headers: {
          'Authorization': `Bearer ${process.env.LINKEDIN_API_KEY}`,
          'Content-Type': 'application/json'
        },
        params
      });
      
      for (const post of response.data.elements || []) {
        const detections = await this.scanForSensitiveData(post.commentary, 'linkedin');
        
        if (detections.length > 0) {
          threats.push({
            platform: 'linkedin',
            source: post.author?.localizedFirstName || 'Unknown',
            detections: detections,
            severity: Math.max(...detections.map(d => (['critical', 'high'].includes(d.risk) ? 2 : 1)))
          });
        }
      }
    } catch (error) {
      logger.warn('LinkedIn monitoring failed:', error.message);
    }
    
    return threats;
  }

  async checkReddit() {
    const threats = [];
    
    try {
      const axios = require('axios');
      
      const response = await axios.get('https://www.reddit.com/r/all/search.json', {
        params: {
          q: process.env.COMPANY_NAME || 'company',
          sort: 'new',
          limit: 50
        },
        headers: {
          'User-Agent': 'CyberSentinelAI/1.0'
        }
      });
      
      for (const post of response.data.data?.children || []) {
        const text = post.data.selftext || post.data.title;
        const detections = await this.scanForSensitiveData(text, 'reddit');
        
        if (detections.length > 0) {
          threats.push({
            platform: 'reddit',
            source: `/r/${post.data.subreddit}`,
            author: post.data.author,
            url: `https://reddit.com${post.data.permalink}`,
            detections: detections,
            severity: Math.max(...detections.map(d => (['critical', 'high'].includes(d.risk) ? 2 : 1)))
          });
        }
      }
    } catch (error) {
      logger.warn('Reddit monitoring failed:', error.message);
    }
    
    return threats;
  }

  async checkGithub() {
    const threats = [];
    
    try {
      if (!process.env.GITHUB_TOKEN) return threats;
      
      const axios = require('axios');
      
      const response = await axios.get('https://api.github.com/search/code', {
        headers: {
          'Authorization': `token ${process.env.GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        },
        params: {
          q: `${process.env.COMPANY_NAME || 'company'} org:${process.env.GITHUB_ORG || 'public'}`,
          sort: 'updated',
          order: 'desc',
          per_page: 30
        }
      });
      
      for (const result of response.data.items || []) {
        const detections = await this.scanForSensitiveData(result.name, 'github');
        
        if (detections.length > 0) {
          threats.push({
            platform: 'github',
            repository: result.repository.full_name,
            file: result.name,
            url: result.html_url,
            detections: detections,
            severity: 'critical'
          });
        }
      }
    } catch (error) {
      logger.warn('GitHub monitoring failed:', error.message);
    }
    
    return threats;
  }

  async recordViolation(violation) {
    return new Promise((resolve) => {
      const db = getDb();
      
      db.run(`INSERT INTO dlp_violations 
        (violation_type, channel, data_type, severity, content_summary, remediation_action)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [
          violation.type,
          violation.channel,
          violation.dataType,
          violation.severity,
          violation.summary,
          violation.remediationAction
        ],
        (err) => {
          if (err) {
            logger.error('Failed to record DLP violation:', err);
          } else {
            logger.warn(`DLP Violation recorded: ${violation.type} on ${violation.channel}`);
          }
          resolve();
        }
      );
    });
  }

  async createDLPPolicy(policyConfig) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      
      const dataTypes = Array.isArray(policyConfig.dataTypes) ? 
        policyConfig.dataTypes.join(',') : policyConfig.dataTypes;
      const channels = Array.isArray(policyConfig.channels) ? 
        policyConfig.channels.join(',') : policyConfig.channels;
      
      db.run(`INSERT INTO dlp_policies 
        (policy_name, enabled, data_types, channels, action, notification_enabled)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [
          policyConfig.name,
          policyConfig.enabled ? 1 : 0,
          dataTypes,
          channels,
          policyConfig.action,
          policyConfig.notificationEnabled ? 1 : 0
        ],
        (err) => {
          if (err) reject(err);
          else {
            logger.info(`DLP policy created: ${policyConfig.name}`);
            resolve();
          }
        }
      );
    });
  }

  async getDLPPolicies() {
    return new Promise((resolve, reject) => {
      const db = getDb();
      
      db.all('SELECT * FROM dlp_policies WHERE enabled = 1', (err, rows) => {
        if (err) reject(err);
        else {
          resolve((rows || []).map(policy => ({
            ...policy,
            dataTypes: policy.data_types.split(','),
            channels: policy.channels.split(',')
          })));
        }
      });
    });
  }

  async getDLPViolations(limit = 100) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      
      db.all(`SELECT * FROM dlp_violations ORDER BY detected_at DESC LIMIT ?`, [limit], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }
}

module.exports = DataLossPreventionEngine;
