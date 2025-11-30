const { initDatabase, closeDatabase } = require('./database/db');
const ThreatDetector = require('./core/threatDetector');
const AnomalyDetector = require('./ai/anomalyDetector');
const API = require('./core/api');
const ConfigManager = require('./core/configManager');
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
    this.app = express();
    this.port = process.env.PORT || 3000;
  }

  async initialize() {
    try {
      logger.info('Initializing CyberSentinel AI...');
      logger.info(`Platform: ${PlatformHelper.getPlatform()}, Node: ${process.version}`);

      await initDatabase();
      logger.info('Database initialized successfully');

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
    this.app.use(express.json());

    // Serve static files from ui directory
    const path = require('path');
    this.app.use(express.static(path.join(__dirname, 'ui')));

    // Initialize API with threat detector
    const api = new API(this.threatDetector);

    // Mount API routes
    this.app.use('/api', api.router);

    // Serve dashboard as root
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, 'ui', 'index.html'));
    });

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
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

          // Check for alerts based on configuration
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

    // Run initial scan
    await runScan();

    // Schedule recurring scans
    this.monitoringInterval = setInterval(runScan, intervalMinutes * 60 * 1000);
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
      if (this.monitoringInterval) {
        clearInterval(this.monitoringInterval);
        logger.info('Monitoring stopped');
      }
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