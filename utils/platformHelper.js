const os = require('os');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

class PlatformHelper {
  static getPlatform() {
    return os.platform();
  }

  static isWindows() {
    return this.getPlatform() === 'win32';
  }

  static isMacOS() {
    return this.getPlatform() === 'darwin';
  }

  static isLinux() {
    return this.getPlatform() === 'linux';
  }

  static getNetworkCommand() {
    if (this.isWindows()) {
      return 'netstat -ano';
    } else if (this.isMacOS()) {
      return 'netstat -tulpn || lsof -i -P -n';
    } else {
      return 'ss -tulpn || netstat -tulpn';
    }
  }

  static ensureDirectoryExists(dirPath) {
    try {
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }
      return true;
    } catch (error) {
      console.error(`Failed to create directory ${dirPath}:`, error.message);
      return false;
    }
  }

  static getLogsDirectory() {
    const logsDir = path.join(__dirname, '..', 'logs');
    this.ensureDirectoryExists(logsDir);
    return logsDir;
  }

  static getConfigDirectory() {
    const configDir = path.join(__dirname, '..', 'config');
    this.ensureDirectoryExists(configDir);
    return configDir;
  }

  static getDataDirectory() {
    const dataDir = path.join(__dirname, '..', 'data');
    this.ensureDirectoryExists(dataDir);
    return dataDir;
  }

  static getDefaultDatabasePath() {
    return path.join(this.getDataDirectory(), 'cybersentinel.db');
  }

  static normalizeCommand(command) {
    if (this.isWindows()) {
      return command.replace(/\//g, '\\');
    }
    return command;
  }

  static killProcess(pid) {
    try {
      if (this.isWindows()) {
        execSync(`taskkill /PID ${pid} /F`);
      } else {
        execSync(`kill -9 ${pid}`);
      }
      return true;
    } catch (error) {
      return false;
    }
  }

  static getProcessInfo() {
    return {
      platform: this.getPlatform(),
      version: process.version,
      nodeVersion: process.versions.node,
      arch: os.arch(),
      cpuCount: os.cpus().length,
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      homedir: os.homedir(),
      tmpdir: os.tmpdir()
    };
  }

  static formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }
}

module.exports = PlatformHelper;
