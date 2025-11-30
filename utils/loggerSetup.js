const winston = require('winston');
const path = require('path');
const fs = require('fs');
const PlatformHelper = require('./platformHelper');

function setupLogger(serviceName = 'cybersentinel-ai') {
  const logsDir = PlatformHelper.getLogsDirectory();

  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { service: serviceName },
    transports: [
      new winston.transports.File({
        filename: path.join(logsDir, 'error.log'),
        level: 'error'
      }),
      new winston.transports.File({
        filename: path.join(logsDir, 'combined.log')
      })
    ]
  });

  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, ...meta }) => {
          const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
          return `${timestamp} [${level}]: ${message} ${metaStr}`;
        })
      )
    }));
  }

  return logger;
}

module.exports = setupLogger;
