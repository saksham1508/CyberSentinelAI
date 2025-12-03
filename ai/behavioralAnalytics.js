const tf = require('@tensorflow/tfjs');

class BehavioralAnalytics {
  constructor() {
    this.baselineProfiles = new Map();
    this.anomalyScores = [];
    this.model = null;
  }

  async loadModel() {
    this.model = tf.sequential({
      layers: [
        tf.layers.dense({ inputShape: [12], units: 64, activation: 'relu' }),
        tf.layers.dropout({ rate: 0.2 }),
        tf.layers.dense({ units: 32, activation: 'relu' }),
        tf.layers.dropout({ rate: 0.2 }),
        tf.layers.dense({ units: 16, activation: 'relu' }),
        tf.layers.dense({ units: 1, activation: 'sigmoid' })
      ]
    });

    this.model.compile({
      optimizer: tf.train.adam(0.01),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });
  }

  createBehavioralProfile(threat) {
    const profile = {
      threatType: threat.type,
      sourceIp: threat.source_ip,
      protocol: threat.protocol,
      port: threat.port,
      firstSeen: Date.now(),
      count: 1,
      patterns: [threat],
      severity: threat.severity
    };
    return profile;
  }

  updateBaselineProfile(sourceIp, threat) {
    const key = `${sourceIp}:${threat.protocol}`;
    
    if (!this.baselineProfiles.has(key)) {
      this.baselineProfiles.set(key, this.createBehavioralProfile(threat));
    } else {
      const profile = this.baselineProfiles.get(key);
      profile.count++;
      profile.patterns.push(threat);
      
      if (profile.patterns.length > 100) {
        profile.patterns.shift();
      }
    }
  }

  extractBehavioralFeatures(threat, sourceIp) {
    const key = `${sourceIp}:${threat.protocol}`;
    const profile = this.baselineProfiles.get(key);
    
    const severityMap = { 'Critical': 1.0, 'High': 0.75, 'Medium': 0.5, 'Low': 0.25 };
    const protocolMap = { 'TCP': 0.8, 'UDP': 0.6, 'ICMP': 0.4 };
    
    const features = [
      severityMap[threat.severity] || 0.5,
      (threat.port || 0) / 65535,
      protocolMap[threat.protocol] || 0.5,
      threat.description.length / 1000,
      (profile?.count || 0) / 100,
      (profile?.count || 0) > 5 ? 1 : 0,
      threat.type === 'DDoS' ? 1 : 0,
      threat.type === 'Intrusion' ? 1 : 0,
      threat.type === 'Malware' ? 1 : 0,
      threat.type === 'Credential Compromise' ? 1 : 0,
      this.calculateTemporalAnomaly(profile),
      this.calculateFrequencyAnomaly(profile)
    ];

    return features;
  }

  calculateTemporalAnomaly(profile) {
    if (!profile || profile.patterns.length < 2) return 0;
    
    const timeDifferences = [];
    for (let i = 1; i < profile.patterns.length; i++) {
      const diff = profile.patterns[i].timestamp - profile.patterns[i - 1].timestamp;
      timeDifferences.push(diff);
    }
    
    const avgInterval = timeDifferences.reduce((a, b) => a + b, 0) / timeDifferences.length;
    const lastInterval = timeDifferences[timeDifferences.length - 1];
    
    return Math.abs(lastInterval - avgInterval) / (avgInterval || 1) > 2 ? 1 : 0;
  }

  calculateFrequencyAnomaly(profile) {
    if (!profile || profile.count < 3) return 0;
    
    const recentWindow = profile.patterns.slice(-5);
    const recentCount = recentWindow.length;
    const avgCount = profile.count / profile.patterns.length;
    
    return recentCount > avgCount * 3 ? 1 : 0;
  }

  async detectBehavioralAnomalies(threats) {
    if (!this.model) await this.loadModel();

    const anomalyThreats = [];

    for (const threat of threats) {
      this.updateBaselineProfile(threat.source_ip, threat);
      
      const features = this.extractBehavioralFeatures(threat, threat.source_ip);
      const input = tf.tensor2d([features]);
      const prediction = this.model.predict(input);
      const score = await prediction.data();

      threat.behavioralAnomalyScore = parseFloat(score[0]).toFixed(3);
      threat.isBehavioralAnomaly = score[0] > 0.6;

      if (threat.isBehavioralAnomaly) {
        threat.behavioralReason = this.generateBehavioralExplanation(threat, features);
        anomalyThreats.push(threat);
      }

      this.anomalyScores.push({
        threatId: threat.id,
        score: score[0],
        timestamp: Date.now()
      });

      input.dispose();
      prediction.dispose();
    }

    return anomalyThreats;
  }

  generateBehavioralExplanation(threat, features) {
    const reasons = [];
    
    if (features[4] > 0.7) reasons.push('High repetition pattern');
    if (features[5] === 1) reasons.push('Increased frequency');
    if (features[10] === 1) reasons.push('Unusual timing');
    if (features[11] === 1) reasons.push('Burst detection');
    if (threat.severity === 'High') reasons.push('High severity classification');

    return reasons.length > 0 ? reasons.join(', ') : 'Behavioral anomaly detected';
  }

  getAnomalyStats(timeWindow = 3600000) {
    const now = Date.now();
    const recentScores = this.anomalyScores.filter(s => now - s.timestamp < timeWindow);
    
    if (recentScores.length === 0) {
      return {
        avgScore: 0,
        maxScore: 0,
        minScore: 0,
        anomalyCount: 0
      };
    }

    const scores = recentScores.map(s => s.score);
    return {
      avgScore: (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(3),
      maxScore: Math.max(...scores).toFixed(3),
      minScore: Math.min(...scores).toFixed(3),
      anomalyCount: recentScores.filter(s => s.score > 0.6).length
    };
  }
}

module.exports = BehavioralAnalytics;
