const { exec } = require('child_process');
const PlatformHelper = require('../utils/platformHelper');

function getDb() {
  return require('../database/db').getDatabase();
}

class NetworkMonitor {
  constructor() {
    this.platform = PlatformHelper.getPlatform();
  }

  async monitorConnections() {
    return new Promise((resolve, reject) => {
      const command = PlatformHelper.getNetworkCommand();

      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }

        const connections = this.parseConnections(stdout);
        resolve(connections);
      });
    });
  }

  parseConnections(output) {
    const lines = output.split('\n');
    const connections = [];

    for (const line of lines) {
      if (line.includes('LISTEN') || line.includes('ESTABLISHED')) {
        // Parse line, e.g., TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 1234
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const protocol = parts[0];
          const local = parts[1];
          const remote = parts[2];
          const state = parts[3];
          const pid = parts.length > 4 ? parts[4] : null;

          connections.push({
            protocol,
            localAddress: local.split(':')[0],
            localPort: local.split(':')[1],
            remoteAddress: remote.split(':')[0],
            remotePort: remote.split(':')[1],
            state,
            pid
          });
        }
      }
    }

    return connections;
  }

  detectThreats(connections) {
    const threats = [];
    const suspiciousPorts = [22, 23, 3389, 5900]; // SSH, Telnet, RDP, VNC

    for (const conn of connections) {
      if (suspiciousPorts.includes(parseInt(conn.remotePort)) && conn.state === 'ESTABLISHED') {
        threats.push({
          type: 'Suspicious Connection',
          severity: 'High',
          description: `Connection to suspicious port ${conn.remotePort} from ${conn.remoteAddress}`,
          source_ip: conn.remoteAddress,
          destination_ip: conn.localAddress,
          protocol: conn.protocol,
          port: conn.remotePort
        });
      }
    }

    return threats;
  }

  async logConnections(connections) {
    try {
      const db = getDb();
      for (const conn of connections) {
        await new Promise((resolve, reject) => {
          db.run(`INSERT INTO logs (source, level, message, ip) VALUES (?, ?, ?, ?)`,
            ['network', 'info', `Connection: ${conn.protocol} ${conn.localAddress}:${conn.localPort} -> ${conn.remoteAddress}:${conn.remotePort} ${conn.state}`, conn.remoteAddress],
            (err) => {
              if (err) reject(err);
              else resolve();
            });
        });
      }
    } catch (error) {
      throw new Error(`Failed to log connections: ${error.message}`);
    }
  }

  async run() {
    try {
      const connections = await this.monitorConnections();
      await this.logConnections(connections);
      const threats = this.detectThreats(connections);
      return { connections, threats };
    } catch (error) {
      console.error('Network monitoring error:', error);
      return { connections: [], threats: [] };
    }
  }
}

module.exports = NetworkMonitor;