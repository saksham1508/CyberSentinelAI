const logger = require('../utils/loggerSetup')('rules-engine');

function getDb() {
  return require('../database/db').getDatabase();
}

class SecurityRulesEngine {
  constructor() {
    this.rules = [];
    this.ruleMatches = new Map();
    this.initializeDefaultRules();
  }

  initializeDefaultRules() {
    this.addRule({
      id: 'rule_ddos_detection',
      name: 'DDoS Detection',
      condition: (threat) => {
        return threat.type === 'Suspicious Connection' &&
               threat.severity === 'High' &&
               Math.random() < 0.3;
      },
      action: { type: 'escalate', newSeverity: 'Critical' },
      enabled: true
    });

    this.addRule({
      id: 'rule_privilege_escalation',
      name: 'Privilege Escalation Detection',
      condition: (threat) => {
        return threat.description.toLowerCase().includes('privilege') ||
               threat.description.toLowerCase().includes('sudo') ||
               threat.description.toLowerCase().includes('admin');
      },
      action: { type: 'alert', channel: 'security_team' },
      enabled: true
    });

    this.addRule({
      id: 'rule_data_exfiltration',
      name: 'Data Exfiltration Detection',
      condition: (threat) => {
        return threat.description.toLowerCase().includes('data') ||
               threat.description.toLowerCase().includes('exfiltrat') ||
               threat.description.toLowerCase().includes('transfer');
      },
      action: { type: 'isolate', duration: 3600 },
      enabled: true
    });

    this.addRule({
      id: 'rule_brute_force',
      name: 'Brute Force Detection',
      condition: (threat) => {
        return threat.port === 22 || threat.port === 3389 || threat.port === 5900;
      },
      action: { type: 'block_ip', duration: 86400 },
      enabled: true
    });

    this.addRule({
      id: 'rule_malware_signature',
      name: 'Malware Signature Match',
      condition: (threat) => {
        const malwareKeywords = ['trojan', 'ransomware', 'backdoor', 'worm', 'virus'];
        return malwareKeywords.some(keyword => 
          threat.description.toLowerCase().includes(keyword)
        );
      },
      action: { type: 'quarantine', scope: 'immediate' },
      enabled: true
    });

    this.addRule({
      id: 'rule_sql_injection',
      name: 'SQL Injection Detection',
      condition: (threat) => {
        const sqlPatterns = ['sql', 'injection', 'union', 'select', 'drop'];
        return sqlPatterns.some(pattern =>
          threat.description.toLowerCase().includes(pattern)
        );
      },
      action: { type: 'alert', severity: 'High' },
      enabled: true
    });

    this.addRule({
      id: 'rule_port_scanning',
      name: 'Port Scanning Detection',
      condition: (threat) => {
        return threat.description.toLowerCase().includes('port') &&
               threat.description.toLowerCase().includes('scan');
      },
      action: { type: 'monitor', duration: 1800 },
      enabled: true
    });

    this.addRule({
      id: 'rule_critical_service',
      name: 'Critical Service Protection',
      condition: (threat) => {
        const criticalPorts = [443, 80, 3306, 5432, 27017];
        return criticalPorts.includes(parseInt(threat.port));
      },
      action: { type: 'increase_priority', level: 'critical' },
      enabled: true
    });
  }

  addRule(rule) {
    if (!rule.id || !rule.name || !rule.condition || !rule.action) {
      throw new Error('Invalid rule structure');
    }
    this.rules.push(rule);
    logger.info(`Added rule: ${rule.name}`);
  }

  applyRules(threats) {
    const results = [];

    for (const threat of threats) {
      const appliedRules = [];
      let modifiedThreat = { ...threat };

      for (const rule of this.rules) {
        if (!rule.enabled) continue;

        try {
          if (rule.condition(modifiedThreat)) {
            const actionResult = this.executeAction(rule.action, modifiedThreat);
            modifiedThreat = { ...modifiedThreat, ...actionResult.modifications };
            appliedRules.push({
              ruleId: rule.id,
              ruleName: rule.name,
              action: rule.action.type,
              result: actionResult.result
            });

            this.recordRuleMatch(rule.id);
          }
        } catch (error) {
          logger.error(`Error applying rule ${rule.id}:`, error);
        }
      }

      modifiedThreat.appliedRules = appliedRules;
      results.push(modifiedThreat);
    }

    return results;
  }

  executeAction(action, threat) {
    const result = {
      modifications: {},
      result: {}
    };

    switch (action.type) {
      case 'escalate':
        result.modifications.severity = action.newSeverity;
        result.result.escalated = true;
        result.result.newSeverity = action.newSeverity;
        break;

      case 'alert':
        result.result.alertChannel = action.channel;
        result.result.alertSent = true;
        break;

      case 'isolate':
        result.result.isolation = {
          enabled: true,
          duration: action.duration,
          startTime: new Date().toISOString()
        };
        break;

      case 'block_ip':
        result.result.blocked = true;
        result.result.blockDuration = action.duration;
        break;

      case 'quarantine':
        result.result.quarantined = true;
        result.result.scope = action.scope;
        break;

      case 'monitor':
        result.result.monitoring = {
          enabled: true,
          duration: action.duration
        };
        break;

      case 'increase_priority':
        result.modifications.priority = action.level;
        result.result.priorityIncreased = true;
        break;

      default:
        result.result.unknown = true;
    }

    return result;
  }

  recordRuleMatch(ruleId) {
    const count = (this.ruleMatches.get(ruleId) || 0) + 1;
    this.ruleMatches.set(ruleId, count);
  }

  getRuleStats() {
    return Array.from(this.ruleMatches.entries()).map(([ruleId, count]) => {
      const rule = this.rules.find(r => r.id === ruleId);
      return {
        ruleId,
        ruleName: rule?.name || 'Unknown',
        matches: count
      };
    });
  }

  updateRule(ruleId, updates) {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      Object.assign(rule, updates);
      logger.info(`Updated rule: ${ruleId}`);
      return true;
    }
    return false;
  }

  disableRule(ruleId) {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = false;
      logger.info(`Disabled rule: ${ruleId}`);
      return true;
    }
    return false;
  }

  enableRule(ruleId) {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = true;
      logger.info(`Enabled rule: ${ruleId}`);
      return true;
    }
    return false;
  }

  getRules() {
    return this.rules.map(rule => ({
      id: rule.id,
      name: rule.name,
      enabled: rule.enabled,
      actionType: rule.action.type
    }));
  }

  createCustomRule(name, conditionCode, actionType, actionParams = {}) {
    const ruleId = `custom_${Date.now()}`;
    try {
      const condition = new Function('threat', `return ${conditionCode}`);
      this.addRule({
        id: ruleId,
        name,
        condition,
        action: { type: actionType, ...actionParams },
        enabled: true
      });
      return { ruleId, success: true };
    } catch (error) {
      logger.error('Failed to create custom rule:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = SecurityRulesEngine;
