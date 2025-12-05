const tf = require('@tensorflow/tfjs');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/loggerSetup')('ml-model-manager');

class MLModelManager {
  constructor() {
    this.models = new Map();
    this.trainingData = [];
    this.modelDirectory = path.join(__dirname, '..', 'models');
    this.ensureModelDirectory();
    this.modelMetadata = new Map();
  }

  ensureModelDirectory() {
    if (!fs.existsSync(this.modelDirectory)) {
      fs.mkdirSync(this.modelDirectory, { recursive: true });
    }
  }

  async createThreatDetectionModel(inputShape = 10) {
    const model = tf.sequential({
      layers: [
        tf.layers.dense({
          inputShape: [inputShape],
          units: 64,
          activation: 'relu',
          kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
        }),
        tf.layers.dropout({ rate: 0.3 }),
        tf.layers.dense({
          units: 32,
          activation: 'relu',
          kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
        }),
        tf.layers.dropout({ rate: 0.2 }),
        tf.layers.dense({
          units: 16,
          activation: 'relu'
        }),
        tf.layers.dense({
          units: 1,
          activation: 'sigmoid'
        })
      ]
    });

    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy', 'auc']
    });

    return model;
  }

  async createBehavioralAnalysisModel(inputShape = 15) {
    const model = tf.sequential({
      layers: [
        tf.layers.dense({
          inputShape: [inputShape],
          units: 128,
          activation: 'relu'
        }),
        tf.layers.batchNormalization(),
        tf.layers.dropout({ rate: 0.4 }),
        tf.layers.dense({
          units: 64,
          activation: 'relu'
        }),
        tf.layers.dropout({ rate: 0.3 }),
        tf.layers.dense({
          units: 32,
          activation: 'relu'
        }),
        tf.layers.dense({
          units: 5,
          activation: 'softmax'
        })
      ]
    });

    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'categoricalCrossentropy',
      metrics: ['accuracy']
    });

    return model;
  }

  async trainModel(modelName, trainingData, config = {}) {
    const {
      epochs = 50,
      batchSize = 32,
      validationSplit = 0.2,
      verbose = 1
    } = config;

    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    const xs = tf.tensor2d(trainingData.features);
    const ys = trainingData.labels.length > 0 ?
      (Array.isArray(trainingData.labels[0]) ?
        tf.tensor2d(trainingData.labels) :
        tf.tensor1d(trainingData.labels)) :
      tf.tensor1d([]);

    try {
      logger.info(`Training model ${modelName} with ${trainingData.features.length} samples`);
      
      const history = await model.fit(xs, ys, {
        epochs,
        batchSize,
        validationSplit,
        verbose,
        shuffle: true,
        callbacks: {
          onEpochEnd: (epoch, logs) => {
            if (epoch % 10 === 0) {
              logger.debug(`Epoch ${epoch}: loss=${logs.loss?.toFixed(4)}, acc=${logs.acc?.toFixed(4)}`);
            }
          }
        }
      });

      this.modelMetadata.set(modelName, {
        trainedAt: new Date(),
        samplesUsed: trainingData.features.length,
        finalLoss: history.history.loss[history.history.loss.length - 1],
        finalAccuracy: history.history.acc?.[history.history.acc.length - 1] || 0,
        version: (this.modelMetadata.get(modelName)?.version || 0) + 1
      });

      await this.saveModel(modelName);
      logger.info(`Model ${modelName} trained successfully`);
      
      xs.dispose();
      ys.dispose();
      
      return history;
    } catch (error) {
      logger.error(`Training failed for model ${modelName}:`, error);
      xs.dispose();
      ys.dispose();
      throw error;
    }
  }

  async saveModel(modelName) {
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    try {
      const modelPath = `file://${path.join(this.modelDirectory, modelName)}`;
      await model.save(modelPath);
      
      const metadata = {
        name: modelName,
        savedAt: new Date().toISOString(),
        ...this.modelMetadata.get(modelName)
      };
      
      fs.writeFileSync(
        path.join(this.modelDirectory, `${modelName}_metadata.json`),
        JSON.stringify(metadata, null, 2)
      );
      
      logger.info(`Model ${modelName} saved to ${this.modelDirectory}`);
    } catch (error) {
      logger.error(`Failed to save model ${modelName}:`, error);
      throw error;
    }
  }

  async loadModel(modelName) {
    try {
      const modelPath = `file://${path.join(this.modelDirectory, modelName)}`;
      const model = await tf.loadLayersModel(`${modelPath}/model.json`);
      
      this.models.set(modelName, model);
      
      const metadataPath = path.join(this.modelDirectory, `${modelName}_metadata.json`);
      if (fs.existsSync(metadataPath)) {
        const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
        this.modelMetadata.set(modelName, metadata);
      }
      
      logger.info(`Model ${modelName} loaded successfully`);
      return model;
    } catch (error) {
      logger.warn(`Failed to load model ${modelName}:`, error.message);
      return null;
    }
  }

  async predictThreat(modelName, features) {
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    try {
      const input = tf.tensor2d([features]);
      const prediction = await model.predict(input);
      const result = await prediction.data();
      
      input.dispose();
      prediction.dispose();
      
      return result[0];
    } catch (error) {
      logger.error(`Prediction failed for model ${modelName}:`, error);
      throw error;
    }
  }

  async batchPredict(modelName, featuresBatch) {
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    try {
      const input = tf.tensor2d(featuresBatch);
      const predictions = model.predict(input);
      const results = await predictions.data();
      
      input.dispose();
      predictions.dispose();
      
      return Array.from(results);
    } catch (error) {
      logger.error(`Batch prediction failed for model ${modelName}:`, error);
      throw error;
    }
  }

  async evaluateModel(modelName, testData) {
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    try {
      const xs = tf.tensor2d(testData.features);
      const ys = testData.labels.length > 0 ?
        (Array.isArray(testData.labels[0]) ?
          tf.tensor2d(testData.labels) :
          tf.tensor1d(testData.labels)) :
        tf.tensor1d([]);

      const evaluation = model.evaluate(xs, ys);
      const [loss, ...metrics] = await Promise.all(evaluation.map(t => t.data()));

      xs.dispose();
      ys.dispose();
      evaluation.forEach(t => t.dispose());

      const result = {
        loss: loss[0],
        metrics: metrics.map((m, i) => ({
          name: model.metricsNames?.[i + 1] || `metric_${i}`,
          value: m[0]
        }))
      };

      logger.info(`Model ${modelName} evaluation: loss=${result.loss.toFixed(4)}`);
      return result;
    } catch (error) {
      logger.error(`Evaluation failed for model ${modelName}:`, error);
      throw error;
    }
  }

  getModelMetadata(modelName) {
    return this.modelMetadata.get(modelName) || null;
  }

  getAllModels() {
    return Array.from(this.models.keys());
  }

  deleteModel(modelName) {
    try {
      this.models.delete(modelName);
      this.modelMetadata.delete(modelName);
      
      const modelPath = path.join(this.modelDirectory, modelName);
      if (fs.existsSync(modelPath)) {
        fs.rmSync(modelPath, { recursive: true });
      }
      
      const metadataPath = path.join(this.modelDirectory, `${modelName}_metadata.json`);
      if (fs.existsSync(metadataPath)) {
        fs.unlinkSync(metadataPath);
      }
      
      logger.info(`Model ${modelName} deleted`);
    } catch (error) {
      logger.error(`Failed to delete model ${modelName}:`, error);
    }
  }

  async continueTraining(modelName, newTrainingData, config = {}) {
    const { epochs = 10, batchSize = 32, validationSplit = 0.2 } = config;
    
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Model ${modelName} not found`);
    }

    const xs = tf.tensor2d(newTrainingData.features);
    const ys = newTrainingData.labels.length > 0 ?
      (Array.isArray(newTrainingData.labels[0]) ?
        tf.tensor2d(newTrainingData.labels) :
        tf.tensor1d(newTrainingData.labels)) :
      tf.tensor1d([]);

    try {
      logger.info(`Continuing training for model ${modelName}`);
      
      const history = await model.fit(xs, ys, {
        epochs,
        batchSize,
        validationSplit,
        shuffle: true
      });

      const metadata = this.modelMetadata.get(modelName) || {};
      metadata.lastRetrainingAt = new Date();
      metadata.version = (metadata.version || 1) + 1;
      this.modelMetadata.set(modelName, metadata);

      await this.saveModel(modelName);
      
      xs.dispose();
      ys.dispose();
      
      logger.info(`Model ${modelName} retraining completed`);
      return history;
    } catch (error) {
      logger.error(`Retraining failed for model ${modelName}:`, error);
      xs.dispose();
      ys.dispose();
      throw error;
    }
  }

  async getModelPerformanceMetrics(modelName) {
    const metadata = this.modelMetadata.get(modelName);
    
    if (!metadata) {
      return null;
    }

    return {
      modelName,
      version: metadata.version,
      trainedAt: metadata.trainedAt,
      samplesUsed: metadata.samplesUsed,
      finalLoss: metadata.finalLoss,
      finalAccuracy: metadata.finalAccuracy,
      lastRetraining: metadata.lastRetrainingAt,
      isActive: this.models.has(modelName)
    };
  }
}

module.exports = MLModelManager;
