const logger = require('../utils/loggerSetup')('explainability');

class ExplainabilityEngine {
  constructor() {
    this.biasMetrics = new Map();
    this.featureImportance = new Map();
    this.predictionExplanations = [];
    this.biasThreshold = 0.15;
  }

  explainPrediction(threat, prediction, features) {
    const explanation = {
      threatId: threat.id,
      threatType: threat.type,
      prediction: prediction.result,
      confidence: prediction.confidence,
      timestamp: new Date().toISOString(),
      reasoning: [],
      riskFactors: [],
      mitigatingFactors: [],
      biasRisk: null
    };

    explanation.reasoning.push(this.explainFeatureContribution(features));
    explanation.riskFactors = this.extractRiskFactors(threat, features);
    explanation.mitigatingFactors = this.extractMitigatingFactors(threat);
    explanation.biasRisk = this.assessBiasRisk(threat, prediction);

    this.predictionExplanations.push(explanation);
    if (this.predictionExplanations.length > 1000) {
      this.predictionExplanations.shift();
    }

    return explanation;
  }

  explainFeatureContribution(features) {
    const contributions = [];

    if (features.length > 0) {
      features.forEach((feature, index) => {
        if (feature > 0.7) {
          contributions.push({
            feature: `Feature_${index}`,
            value: feature,
            impact: 'high',
            description: this.getFeatureDescription(index)
          });
        } else if (feature > 0.4) {
          contributions.push({
            feature: `Feature_${index}`,
            value: feature,
            impact: 'medium',
            description: this.getFeatureDescription(index)
          });
        }
      });
    }

    return {
      type: 'feature_analysis',
      topContributors: contributions.slice(0, 5),
      summary: this.generateFeatureSummary(contributions)
    };
  }

  getFeatureDescription(index) {
    const descriptions = [
      'Threat severity level',
      'Protocol classification',
      'Port risk assessment',
      'Source IP reputation',
      'Connection frequency',
      'Temporal pattern anomaly',
      'Behavioral deviation',
      'Pattern matching score',
      'Network position risk',
      'Historical threat correlation',
      'Real-time threat indicators',
      'Anomaly confidence score'
    ];

    return descriptions[index] || `Feature ${index}`;
  }

  generateFeatureSummary(contributions) {
    if (contributions.length === 0) {
      return 'No significant feature contributions detected';
    }

    const topFactor = contributions[0];
    const summary = `The primary threat indicator is ${topFactor.description.toLowerCase()} with ${(topFactor.value * 100).toFixed(1)}% confidence. ${
      contributions.length > 1 ? `Secondary indicators include ${contributions.slice(1, 3).map(c => c.description.toLowerCase()).join(', ')}.` : ''
    }`;

    return summary;
  }

  extractRiskFactors(threat, features) {
    const factors = [];

    if (threat.severity === 'High' || threat.severity === 'Critical') {
      factors.push({
        factor: 'High Severity Classification',
        description: `Threat classified as ${threat.severity} severity`,
        riskLevel: 'high'
      });
    }

    if (features.some(f => f > 0.8)) {
      factors.push({
        factor: 'Strong Anomaly Signal',
        description: 'Multiple anomaly detection signals triggered',
        riskLevel: 'high'
      });
    }

    if (threat.type && ['Malware', 'Intrusion', 'DDoS'].includes(threat.type)) {
      factors.push({
        factor: 'Known Threat Vector',
        description: `Threat type "${threat.type}" matches known attack patterns`,
        riskLevel: 'high'
      });
    }

    if (threat.port && [3306, 5432, 27017].includes(parseInt(threat.port))) {
      factors.push({
        factor: 'Critical Service Targeted',
        description: `Attack targets critical service on port ${threat.port}`,
        riskLevel: 'critical'
      });
    }

    return factors;
  }

  extractMitigatingFactors(threat) {
    const factors = [];

    if (threat.severity === 'Low') {
      factors.push({
        factor: 'Low Severity',
        description: 'Threat classified as low severity, limited immediate impact',
        mitigation: 'Standard monitoring protocols sufficient'
      });
    }

    if (threat.description && threat.description.length < 50) {
      factors.push({
        factor: 'Limited Threat Indicators',
        description: 'Few threat characteristics detected',
        mitigation: 'Continue monitoring for escalation'
      });
    }

    return factors;
  }

  assessBiasRisk(threat, prediction) {
    const biasIndicators = [];

    const sourceIpBias = this.detectSourceIpBias(threat.source_ip);
    if (sourceIpBias.biased) {
      biasIndicators.push(sourceIpBias);
    }

    const portBias = this.detectPortBias(threat.port);
    if (portBias.biased) {
      biasIndicators.push(portBias);
    }

    const typeBias = this.detectThreatTypeBias(threat.type);
    if (typeBias.biased) {
      biasIndicators.push(typeBias);
    }

    const totalBias = biasIndicators.reduce((sum, b) => sum + b.score, 0) / Math.max(biasIndicators.length, 1);

    return {
      riskDetected: totalBias > this.biasThreshold,
      biasScore: totalBias,
      indicators: biasIndicators,
      recommendation: totalBias > this.biasThreshold ? 
        'Review prediction with human analyst due to potential model bias' : 
        'Prediction appears unbiased'
    };
  }

  detectSourceIpBias(sourceIp) {
    const ipPattern = sourceIp?.split('.')[0];
    const count = (this.biasMetrics.get(`source_${ipPattern}`) || 0) + 1;
    this.biasMetrics.set(`source_${ipPattern}`, count);

    const bias = count > 50;
    return {
      type: 'source_ip_concentration',
      sourceIp,
      frequency: count,
      biased: bias,
      score: bias ? 0.3 : 0.05,
      description: `Source IP subnet ${ipPattern}.* has ${count} detection${count !== 1 ? 's' : ''}`
    };
  }

  detectPortBias(port) {
    const count = (this.biasMetrics.get(`port_${port}`) || 0) + 1;
    this.biasMetrics.set(`port_${port}`, count);

    const bias = count > 100;
    return {
      type: 'port_bias',
      port,
      frequency: count,
      biased: bias,
      score: bias ? 0.25 : 0.05,
      description: `Port ${port} has ${count} detection${count !== 1 ? 's' : ''}`
    };
  }

  detectThreatTypeBias(threatType) {
    const count = (this.biasMetrics.get(`type_${threatType}`) || 0) + 1;
    this.biasMetrics.set(`type_${threatType}`, count);

    const bias = count > 80;
    return {
      type: 'threat_type_bias',
      threatType,
      frequency: count,
      biased: bias,
      score: bias ? 0.2 : 0.05,
      description: `Threat type "${threatType}" has ${count} detection${count !== 1 ? 's' : ''}`
    };
  }

  generateTransparencyReport() {
    const report = {
      timestamp: new Date().toISOString(),
      totalPredictions: this.predictionExplanations.length,
      averageConfidence: this.calculateAverageConfidence(),
      biasMetrics: {
        detectedBiases: Array.from(this.biasMetrics.entries())
          .filter(([_, count]) => count > 50)
          .map(([key, count]) => ({ indicator: key, frequency: count }))
      },
      predictionBreakdown: this.generatePredictionBreakdown(),
      recommendations: this.generateRecommendations()
    };

    return report;
  }

  calculateAverageConfidence() {
    if (this.predictionExplanations.length === 0) return 0;
    const sum = this.predictionExplanations.reduce((sum, exp) => sum + (exp.confidence || 0), 0);
    return (sum / this.predictionExplanations.length).toFixed(3);
  }

  generatePredictionBreakdown() {
    const breakdown = {
      highConfidence: 0,
      mediumConfidence: 0,
      lowConfidence: 0,
      biasDetected: 0
    };

    this.predictionExplanations.forEach(exp => {
      if (exp.confidence > 0.8) breakdown.highConfidence++;
      else if (exp.confidence > 0.5) breakdown.mediumConfidence++;
      else breakdown.lowConfidence++;

      if (exp.biasRisk?.riskDetected) breakdown.biasDetected++;
    });

    return breakdown;
  }

  generateRecommendations() {
    const recommendations = [];

    const biasCount = this.predictionExplanations.filter(e => e.biasRisk?.riskDetected).length;
    if (biasCount > 0) {
      recommendations.push({
        priority: 'high',
        message: `${biasCount} predictions flagged for potential bias. Review and retrain model if necessary.`
      });
    }

    const avgConfidence = parseFloat(this.calculateAverageConfidence());
    if (avgConfidence < 0.6) {
      recommendations.push({
        priority: 'medium',
        message: `Average confidence is ${(avgConfidence * 100).toFixed(1)}%. Consider additional training data.`
      });
    }

    if (this.predictionExplanations.length < 100) {
      recommendations.push({
        priority: 'low',
        message: 'Collect more prediction data for better bias analysis.'
      });
    }

    return recommendations;
  }

  getExplanations(limit = 20) {
    return this.predictionExplanations.slice(-limit).reverse();
  }
}

module.exports = ExplainabilityEngine;
