const tf = require('@tensorflow/tfjs');

function getDb() {
  return require('../database/db').getDatabase();
}

class AnomalyDetector {
  constructor() {
    this.model = null;
  }

  async loadModel() {
    // Placeholder: In a real implementation, load a pre-trained model or train one
    // For now, create a simple sequential model
    this.model = tf.sequential();
    this.model.add(tf.layers.dense({ inputShape: [10], units: 32, activation: 'relu' }));
    this.model.add(tf.layers.dense({ units: 16, activation: 'relu' }));
    this.model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

    this.model.compile({ optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy'] });

    // Dummy training data
    const xs = tf.randomNormal([100, 10]);
    const ys = tf.randomUniform([100, 1]);

    await this.model.fit(xs, ys, { epochs: 10 });
  }

  async predictAnomaly(features) {
    if (!this.model) await this.loadModel();

    const input = tf.tensor2d([features]);
    const prediction = this.model.predict(input);
    const result = await prediction.data();

    return result[0] > 0.5; // Threshold for anomaly
  }

  // Feature extraction from threat data
  extractFeatures(threat) {
    // Simple feature vector: severity score, keyword count, etc.
    const severityScore = threat.severity === 'High' ? 1 : threat.severity === 'Medium' ? 0.5 : 0;
    const keywordCount = (threat.description.match(/attack|intrusion|hack/gi) || []).length;
    const ipNumeric = this.ipToNumber(threat.source_ip || '0.0.0.0');
    const port = threat.port || 0;

    return [severityScore, keywordCount, ipNumeric / 4294967295, port / 65535, 0, 0, 0, 0, 0, 0]; // Pad to 10
  }

  ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }

  async analyzeThreats(threats) {
    const analyzed = [];
    for (const threat of threats) {
      const features = this.extractFeatures(threat);
      const isAnomaly = await this.predictAnomaly(features);
      threat.aiAnomaly = isAnomaly;
      analyzed.push(threat);
    }
    return analyzed;
  }
}

module.exports = AnomalyDetector;