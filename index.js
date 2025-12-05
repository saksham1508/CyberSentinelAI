const { initDatabase, closeDatabase } = require('./database/db');
const ThreatDetector = require('./core/threatDetector');
const AnomalyDetector = require('./ai/anomalyDetector');
const API = require('./core/api');
const ConfigManager = require('./core/configManager');
const AssetInventoryManager = require('./core/assetInventoryManager');
const CloudConfigValidator = require('./core/cloudConfigValidator');
const DataLossPreventionEngine = require('./core/dataLossPreventionEngine');
const MLModelManager = require('./ai/mlModelManager');
const SecurityMiddleware = require('./utils/securityMiddleware');
const EncryptionUtils = require('./utils/encryptionUtils');
const express = require('express');
const setupLogger = require('./utils/loggerSetup');
const PlatformHelper = require('./utils/platformHelper');
require('dotenv').config();

const logger = setupLogger('cybersentinel-ai');

class CyberSentinelAI {
  constructor() {
    this.threatDetector = new ThreatDetector();
    this.anomalyDetector = new AnomalyDetector();
    this.configManager = new ConfigManager();
    this.assetInventory = new AssetInventoryManager();
    this.cloudValidator = new CloudConfigValidator();
    this.dlpEngine = new DataLossPreventionEngine();
    this.mlModelManager = new MLModelManager();
    this.securityMiddleware = new SecurityMiddleware();
    this.encryptionUtils = new EncryptionUtils();
    this.app = express();
    this.port = process.env.PORT || 3000;
  }

  async initialize() {
    try {
      logger.info('Initializing CyberSentinel AI...');
      logger.info(`Platform: ${PlatformHelper.getPlatform()}, Node: ${process.version}`);

      await initDatabase();
      logger.info('Database initialized successfully');

      await this.assetInventory.initializeDatabase();
      logger.info('Asset inventory database initialized');

      await this.dlpEngine.initializeDatabase();
      logger.info('DLP engine database initialized');

      await this.configManager.loadConfig();
      logger.info('Configuration loaded successfully');

      if (this.configManager.isAIEnabled()) {
        try {
          await this.anomalyDetector.loadModel();
          logger.info('AI anomaly detector initialized');
        } catch (aiError) {
          logger.warn('Failed to initialize AI anomaly detector:', aiError.message);
          logger.info('Continuing without AI anomaly detection');
        }
      } else {
        logger.info('AI anomaly detector disabled in configuration');
      }

      this.setupServer();
      logger.info(`Server initialized on port ${this.port}`);

    } catch (error) {
      logger.error('Initialization failed:', error);
      throw error;
    }
  }

  setupServer() {
    const path = require('path');

    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    this.app.use(this.securityMiddleware.corsHeaders());
    this.app.use(this.securityMiddleware.securityHeaders());
    this.app.use(this.securityMiddleware.inputValidation());
    this.app.use(this.securityMiddleware.rateLimiting(100, 60000));
    this.app.use(this.securityMiddleware.requestLogging());

    this.app.use(express.static(path.join(__dirname, 'ui')));

    const api = new API(this.threatDetector);

    this.app.use('/api', this.securityMiddleware.authentication(), api.router);

    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    });

    this.setupAssetInventoryRoutes();
    this.setupCloudConfigRoutes();
    this.setupDLPRoutes();
    this.setupMLModelRoutes();

    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, 'ui', 'index.html'));
    });
  }

  setupAssetInventoryRoutes() {
    this.app.get('/api/assets', async (req, res) => {
      try {
        const assets = await this.assetInventory.getAllAssets();
        res.json(assets);
      } catch (error) {
        logger.error('Failed to fetch assets:', error);
        res.status(500).json({ error: 'Failed to fetch assets' });
      }
    });

    this.app.post('/api/assets/discover', async (req, res) => {
      try {
        const discovered = await this.assetInventory.discoverAssets();
        res.json({ discovered: discovered.length, assets: discovered });
      } catch (error) {
        logger.error('Asset discovery failed:', error);
        res.status(500).json({ error: 'Asset discovery failed' });
      }
    });

    this.app.get('/api/assets/:id', async (req, res) => {
      try {
        const asset = await this.assetInventory.getAssetById(req.params.id);
        res.json(asset);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch asset' });
      }
    });

    this.app.get('/api/assets/:id/vulnerabilities', async (req, res) => {
      try {
        const vulns = await this.assetInventory.getAssetVulnerabilities(req.params.id);
        res.json(vulns);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
      }
    });

    this.app.get('/api/assets/:id/history', async (req, res) => {
      try {
        const history = await this.assetInventory.getAssetHistory(req.params.id);
        res.json(history);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch asset history' });
      }
    });

    this.app.get('/api/assets/stale/:hours', async (req, res) => {
      try {
        const stale = await this.assetInventory.getStaleAssets(parseInt(req.params.hours));
        res.json(stale);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stale assets' });
      }
    });
  }

  setupCloudConfigRoutes() {
    this.app.post('/api/cloud/validate-config', async (req, res) => {
      try {
        const issues = await this.cloudValidator.validateAllCloudConfigs();
        await this.cloudValidator.persistMisconfigs(issues);
        res.json({
          totalIssues: issues.length,
          critical: issues.filter(i => i.severity === 'critical').length,
          high: issues.filter(i => i.severity === 'high').length,
          issues: issues
        });
      } catch (error) {
        logger.error('Cloud config validation failed:', error);
        res.status(500).json({ error: 'Cloud config validation failed' });
      }
    });

    this.app.get('/api/cloud/misconfigs', async (req, res) => {
      try {
        const db = require('./database/db').getDatabase();
        db.all('SELECT * FROM cloud_misconfigs ORDER BY detected_at DESC LIMIT 100', (err, rows) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to fetch misconfigs' });
          }
          res.json(rows || []);
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch misconfigs' });
      }
    });
  }

  setupDLPRoutes() {
    this.app.post('/api/dlp/scan', async (req, res) => {
      try {
        const { content, source } = req.body;
        const detections = await this.dlpEngine.scanForSensitiveData(content, source);
        res.json({ detections, riskLevel: Math.max(...(detections.map(d => (['critical'].includes(d.risk) ? 3 : ['high'].includes(d.risk) ? 2 : 1)) || [0])) });
      } catch (error) {
        logger.error('DLP scan failed:', error);
        res.status(500).json({ error: 'DLP scan failed' });
      }
    });

    this.app.get('/api/dlp/violations', async (req, res) => {
      try {
        const violations = await this.dlpEngine.getDLPViolations(parseInt(req.query.limit) || 100);
        res.json(violations);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch violations' });
      }
    });

    this.app.get('/api/dlp/policies', async (req, res) => {
      try {
        const policies = await this.dlpEngine.getDLPPolicies();
        res.json(policies);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch policies' });
      }
    });

    this.app.post('/api/dlp/policies', async (req, res) => {
      try {
        await this.dlpEngine.createDLPPolicy(req.body);
        res.json({ message: 'Policy created successfully' });
      } catch (error) {
        res.status(500).json({ error: 'Failed to create policy' });
      }
    });

    this.app.post('/api/dlp/monitor-social-media', async (req, res) => {
      try {
        const threats = await this.dlpEngine.monitorSocialMediaThreats();
        res.json({ socialMediaThreats: threats.length, threats });
      } catch (error) {
        logger.error('Social media monitoring failed:', error);
        res.status(500).json({ error: 'Social media monitoring failed' });
      }
    });
  }

  setupMLModelRoutes() {
    this.app.post('/api/ml/train', async (req, res) => {
      try {
        const { modelName, trainingData, config } = req.body;
        
        if (!this.mlModelManager.models.has(modelName)) {
          const model = await this.mlModelManager.createThreatDetectionModel();
          this.mlModelManager.models.set(modelName, model);
        }
        
        const history = await this.mlModelManager.trainModel(modelName, trainingData, config);
        res.json({ message: `Model ${modelName} trained successfully`, epochs: history.epoch });
      } catch (error) {
        logger.error('Model training failed:', error);
        res.status(500).json({ error: 'Model training failed' });
      }
    });

    this.app.post('/api/ml/predict', async (req, res) => {
      try {
        const { modelName, features } = req.body;
        const prediction = await this.mlModelManager.predictThreat(modelName, features);
        res.json({ prediction, isThreat: prediction > 0.5 });
      } catch (error) {
        logger.error('Prediction failed:', error);
        res.status(500).json({ error: 'Prediction failed' });
      }
    });

    this.app.get('/api/ml/models', (req, res) => {
      const models = this.mlModelManager.getAllModels();
      const metadata = models.map(m => ({
        name: m,
        ...this.mlModelManager.getModelMetadata(m)
      }));
      res.json(metadata);
    });

    this.app.get('/api/ml/models/:name/metrics', (req, res) => {
      const metrics = this.mlModelManager.getModelPerformanceMetrics(req.params.name);
      res.json(metrics || { error: 'Model not found' });
    });
  }

  async startMonitoring() {
    if (!this.configManager.isMonitoringEnabled()) {
      logger.info('Automated monitoring disabled in configuration');
      return;
    }

    const intervalMinutes = this.configManager.getMonitoringInterval();
    logger.info(`Starting automated monitoring every ${intervalMinutes} minutes`);

    const runScan = async () => {
      try {
        const threats = await this.threatDetector.run();
        const analyzedThreats = this.configManager.isAIEnabled() ?
          await this.anomalyDetector.analyzeThreats(threats) : threats;

        if (analyzedThreats.length > 0) {
          logger.warn(`Detected ${analyzedThreats.length} potential threats`);

          const highSeverityThreats = analyzedThreats.filter(t =>
            this.configManager.shouldAlertOnSeverity(t.severity)
          );

          if (highSeverityThreats.length > 0) {
            await this.handleAlerts(highSeverityThreats);
          }
        } else {
          logger.info('No threats detected in current scan');
        }
      } catch (error) {
        logger.error('Monitoring scan failed:', error);
      }
    };

    const runAssetDiscovery = async () => {
      try {
        logger.info('Running asset discovery...');
        const discovered = await this.assetInventory.discoverAssets();
        logger.info(`Asset discovery complete. Found ${discovered.length} assets`);
      } catch (error) {
        logger.error('Asset discovery failed:', error);
      }
    };

    const runCloudValidation = async () => {
      try {
        logger.info('Validating cloud configurations...');
        const issues = await this.cloudValidator.validateAllCloudConfigs();
        if (issues.length > 0) {
          logger.warn(`Found ${issues.length} cloud misconfigurations`);
          await this.cloudValidator.persistMisconfigs(issues);
        }
      } catch (error) {
        logger.error('Cloud validation failed:', error);
      }
    };

    const runDLPScan = async () => {
      try {
        logger.info('Running DLP scan...');
        const threats = await this.dlpEngine.monitorSocialMediaThreats();
        if (threats.length > 0) {
          logger.warn(`DLP detected ${threats.length} social media threats`);
        }
      } catch (error) {
        logger.error('DLP scan failed:', error);
      }
    };

    await runScan();
    await runAssetDiscovery();
    await runCloudValidation();

    this.monitoringInterval = setInterval(runScan, intervalMinutes * 60 * 1000);
    this.assetDiscoveryInterval = setInterval(runAssetDiscovery, intervalMinutes * 3 * 60 * 1000);
    this.cloudValidationInterval = setInterval(runCloudValidation, intervalMinutes * 12 * 60 * 1000);
    this.dlpScanInterval = setInterval(runDLPScan, intervalMinutes * 6 * 60 * 1000);
  }

  async handleAlerts(threats) {
    logger.warn(`Alert triggered for ${threats.length} threats`);

    // Here you could implement email notifications, system alerts, etc.
    // For now, just log the alerts
    threats.forEach(threat => {
      logger.warn(`ALERT: ${threat.severity} threat - ${threat.description}`);
    });
  }

  startServer() {
    this.app.listen(this.port, () => {
      logger.info(`CyberSentinel AI server running on port ${this.port}`);
      console.log(`🚀 CyberSentinel AI is running on http://localhost:${this.port}`);
    });
  }

  async start() {
    await this.initialize();
    this.startServer();
    await this.startMonitoring();
  }

  async stop() {
    try {
      if (this.monitoringInterval) clearInterval(this.monitoringInterval);
      if (this.assetDiscoveryInterval) clearInterval(this.assetDiscoveryInterval);
      if (this.cloudValidationInterval) clearInterval(this.cloudValidationInterval);
      if (this.dlpScanInterval) clearInterval(this.dlpScanInterval);
      logger.info('All monitoring tasks stopped');
      
      await closeDatabase();
      logger.info('Database connection closed');
    } catch (error) {
      logger.error('Error stopping CyberSentinel AI:', error);
    }
  }
}

// CLI support
const { Command } = require('commander');
const program = new Command();

program
  .name('cybersentinel-ai')
  .description('AI-powered cybersecurity monitoring system')
  .version('1.0.0');

program
  .command('start')
  .description('Start the CyberSentinel AI monitoring system')
  .option('-p, --port <port>', 'Port to run the server on', '3000')
  .option('-i, --interval <minutes>', 'Monitoring interval in minutes', '5')
  .action(async (options) => {
    const sentinel = new CyberSentinelAI();
    process.env.PORT = options.port;
    sentinel.port = options.port;

    try {
      await sentinel.start();
    } catch (error) {
      logger.error('Failed to start CyberSentinel AI:', error);
      process.exit(1);
    }
  });

program
  .command('scan')
  .description('Run a manual threat scan')
  .action(async () => {
    const sentinel = new CyberSentinelAI();
    await sentinel.initialize();

    try {
      console.log('🔍 Running manual threat scan...');
      const threats = await sentinel.threatDetector.run();
      const analyzedThreats = await sentinel.anomalyDetector.analyzeThreats(threats);

      console.log(`📊 Scan complete. Found ${analyzedThreats.length} potential threats:`);
      analyzedThreats.forEach((threat, index) => {
        console.log(`${index + 1}. ${threat.type} (${threat.severity}) - ${threat.description}`);
        if (threat.aiAnomaly) {
          console.log(`   🤖 AI flagged as anomaly`);
        }
      });
    } catch (error) {
      console.error('❌ Scan failed:', error.message);
      process.exit(1);
    }
  });

let sentinelInstance = null;

async function handleShutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  if (sentinelInstance) {
    await sentinelInstance.stop();
  }
  process.exit(0);
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

if (require.main === module) {
  program
    .action(() => {
      console.log('Use "cybersentinel-ai start" to start the server or "cybersentinel-ai scan" to run a scan');
      program.help();
    })
    .parse();
}

module.exports = CyberSentinelAI;