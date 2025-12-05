const logger = require('../utils/loggerSetup')('asset-inventory');

function getDb() {
  return require('../database/db').getDatabase();
}

class AssetInventoryManager {
  constructor() {
    this.assets = new Map();
    this.assetHistory = new Map();
    this.discoverySchedule = null;
  }

  async initializeDatabase() {
    return new Promise((resolve, reject) => {
      const db = getDb();
      
      db.run(`CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        category TEXT,
        os TEXT,
        ip_address TEXT UNIQUE,
        mac_address TEXT,
        hostname TEXT,
        status TEXT DEFAULT 'active',
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        criticality TEXT,
        owner TEXT,
        metadata TEXT,
        version INTEGER DEFAULT 1
      )`, (err) => {
        if (err && !err.message.includes('already exists')) {
          reject(err);
          return;
        }
        
        db.run(`CREATE TABLE IF NOT EXISTS asset_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          asset_id TEXT,
          change_type TEXT,
          old_value TEXT,
          new_value TEXT,
          changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (asset_id) REFERENCES assets(id)
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(err);
            return;
          }
          
          db.run(`CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT,
            vulnerability_type TEXT,
            severity TEXT,
            description TEXT,
            remediation TEXT,
            discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
          )`, (err) => {
            if (err && !err.message.includes('already exists')) {
              reject(err);
              return;
            }
            resolve();
          });
        });
      });
    });
  }

  async discoverAssets() {
    const discoveredAssets = [];
    
    try {
      const networkAssets = await this.discoverNetworkAssets();
      discoveredAssets.push(...networkAssets);
      
      const cloudAssets = await this.discoverCloudAssets();
      discoveredAssets.push(...cloudAssets);
      
      const systemAssets = await this.discoverSystemAssets();
      discoveredAssets.push(...systemAssets);
      
      for (const asset of discoveredAssets) {
        await this.registerAsset(asset);
      }
      
      logger.info(`Discovered ${discoveredAssets.length} assets`);
      return discoveredAssets;
    } catch (error) {
      logger.error('Asset discovery failed:', error);
      return [];
    }
  }

  async discoverNetworkAssets() {
    const assets = [];
    
    try {
      const { exec } = require('child_process');
      
      return new Promise((resolve) => {
        const isWindows = process.platform === 'win32';
        const command = isWindows ? 'ipconfig /all' : 'ifconfig';
        
        exec(command, (error, stdout) => {
          if (!error) {
            const lines = stdout.split('\n');
            let currentInterface = null;
            
            lines.forEach(line => {
              if (isWindows) {
                if (line.includes('Ethernet') || line.includes('Wi-Fi')) {
                  currentInterface = line.split(':')[0].trim();
                }
                if (line.includes('IPv4 Address') && currentInterface) {
                  const ip = line.split(':')[1].trim();
                  assets.push({
                    id: `net_${ip}`,
                    name: currentInterface,
                    type: 'network_interface',
                    category: 'network',
                    ip_address: ip,
                    criticality: 'high'
                  });
                }
              } else {
                if (line.match(/^\w+:/)) {
                  currentInterface = line.split(':')[0].trim();
                }
                if (line.includes('inet ') && currentInterface) {
                  const parts = line.trim().split(/\s+/);
                  const ip = parts[1];
                  assets.push({
                    id: `net_${ip}`,
                    name: currentInterface,
                    type: 'network_interface',
                    category: 'network',
                    ip_address: ip,
                    criticality: 'high'
                  });
                }
              }
            });
          }
          resolve(assets);
        });
      });
    } catch (error) {
      logger.warn('Network asset discovery failed:', error);
      return assets;
    }
  }

  async discoverCloudAssets() {
    const assets = [];
    
    try {
      if (process.env.AWS_REGION) {
        const awsAssets = await this.discoverAWSAssets();
        assets.push(...awsAssets);
      }
      
      if (process.env.AZURE_SUBSCRIPTION_ID) {
        const azureAssets = await this.discoverAzureAssets();
        assets.push(...azureAssets);
      }
      
      if (process.env.GCP_PROJECT_ID) {
        const gcpAssets = await this.discoverGCPAssets();
        assets.push(...gcpAssets);
      }
    } catch (error) {
      logger.warn('Cloud asset discovery failed:', error);
    }
    
    return assets;
  }

  async discoverAWSAssets() {
    const assets = [];
    try {
      const AWS = require('aws-sdk');
      const ec2 = new AWS.EC2({ region: process.env.AWS_REGION });
      
      const params = {};
      const instances = await ec2.describeInstances(params).promise();
      
      instances.Reservations.forEach(reservation => {
        reservation.Instances.forEach(instance => {
          assets.push({
            id: `aws_${instance.InstanceId}`,
            name: instance.Tags?.find(t => t.Key === 'Name')?.Value || instance.InstanceId,
            type: 'cloud_instance',
            category: 'cloud_compute',
            ip_address: instance.PrivateIpAddress,
            os: instance.Platform || 'linux',
            status: instance.State.Name,
            criticality: 'medium',
            metadata: JSON.stringify({ 
              instanceType: instance.InstanceType,
              launchTime: instance.LaunchTime,
              region: process.env.AWS_REGION
            })
          });
        });
      });
    } catch (error) {
      logger.warn('AWS asset discovery failed:', error.message);
    }
    
    return assets;
  }

  async discoverAzureAssets() {
    const assets = [];
    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { ComputeManagementClient } = require('@azure/arm-compute');
      
      const credential = new DefaultAzureCredential();
      const client = new ComputeManagementClient(credential, process.env.AZURE_SUBSCRIPTION_ID);
      
      const resourceGroupName = process.env.AZURE_RESOURCE_GROUP;
      const vms = await client.virtualMachines.listByResourceGroup(resourceGroupName);
      
      vms.forEach(vm => {
        assets.push({
          id: `azure_${vm.id}`,
          name: vm.name,
          type: 'cloud_instance',
          category: 'cloud_compute',
          os: vm.osProfile?.windowsConfiguration ? 'windows' : 'linux',
          status: 'running',
          criticality: 'medium',
          metadata: JSON.stringify({
            vmSize: vm.hardwareProfile?.vmSize,
            resourceGroup: resourceGroupName
          })
        });
      });
    } catch (error) {
      logger.warn('Azure asset discovery failed:', error.message);
    }
    
    return assets;
  }

  async discoverGCPAssets() {
    const assets = [];
    try {
      const compute = require('@google-cloud/compute');
      const instancesClient = new compute.InstancesClient();
      
      const projectId = process.env.GCP_PROJECT_ID;
      const zone = process.env.GCP_ZONE || 'us-central1-a';
      
      const request = {
        project: projectId,
        zone: zone,
      };
      
      const [instances] = await instancesClient.list(request);
      
      instances.forEach(instance => {
        assets.push({
          id: `gcp_${instance.id}`,
          name: instance.name,
          type: 'cloud_instance',
          category: 'cloud_compute',
          status: instance.status,
          criticality: 'medium',
          metadata: JSON.stringify({
            machineType: instance.machineType,
            zone: zone
          })
        });
      });
    } catch (error) {
      logger.warn('GCP asset discovery failed:', error.message);
    }
    
    return assets;
  }

  async discoverSystemAssets() {
    const assets = [];
    const os = require('os');
    
    try {
      assets.push({
        id: 'sys_local_machine',
        name: os.hostname(),
        type: 'local_system',
        category: 'computing',
        os: os.platform(),
        status: 'active',
        criticality: 'critical',
        metadata: JSON.stringify({
          platform: os.platform(),
          arch: os.arch(),
          cpus: os.cpus().length,
          memory: os.totalmem()
        })
      });
    } catch (error) {
      logger.warn('System asset discovery failed:', error);
    }
    
    return assets;
  }

  async registerAsset(assetData) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      const id = assetData.id || `asset_${Date.now()}`;
      
      const metadata = assetData.metadata ? 
        (typeof assetData.metadata === 'string' ? assetData.metadata : JSON.stringify(assetData.metadata)) : 
        null;
      
      db.get('SELECT * FROM assets WHERE id = ?', [id], async (err, existingAsset) => {
        if (err) {
          reject(err);
          return;
        }
        
        if (existingAsset) {
          await this.trackAssetChanges(id, existingAsset, assetData);
          
          db.run(`UPDATE assets SET 
            name = ?, type = ?, category = ?, os = ?, ip_address = ?, 
            mac_address = ?, hostname = ?, status = ?, last_seen = CURRENT_TIMESTAMP,
            criticality = ?, owner = ?, metadata = ?, version = version + 1
            WHERE id = ?`,
            [
              assetData.name, assetData.type, assetData.category, assetData.os,
              assetData.ip_address, assetData.mac_address, assetData.hostname,
              assetData.status || 'active', assetData.criticality, assetData.owner,
              metadata, id
            ],
            (err) => {
              if (err) reject(err);
              else {
                logger.info(`Asset updated: ${id}`);
                resolve({ id, ...assetData, updated: true });
              }
            }
          );
        } else {
          db.run(`INSERT INTO assets 
            (id, name, type, category, os, ip_address, mac_address, hostname, status, criticality, owner, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              id, assetData.name, assetData.type, assetData.category, assetData.os,
              assetData.ip_address, assetData.mac_address, assetData.hostname,
              assetData.status || 'active', assetData.criticality, assetData.owner, metadata
            ],
            (err) => {
              if (err) reject(err);
              else {
                logger.info(`Asset registered: ${id}`);
                resolve({ id, ...assetData, created: true });
              }
            }
          );
        }
      });
    });
  }

  async trackAssetChanges(assetId, oldAsset, newAsset) {
    const db = getDb();
    const changes = [];
    
    Object.keys(newAsset).forEach(key => {
      if (oldAsset[key] !== newAsset[key]) {
        changes.push({
          changeType: 'update',
          oldValue: oldAsset[key],
          newValue: newAsset[key],
          fieldName: key
        });
      }
    });
    
    for (const change of changes) {
      await new Promise((resolve) => {
        db.run(`INSERT INTO asset_history (asset_id, change_type, old_value, new_value)
          VALUES (?, ?, ?, ?)`,
          [assetId, change.changeType, change.oldValue, change.newValue],
          (err) => {
            if (err) logger.warn('Failed to record asset change:', err);
            resolve();
          }
        );
      });
    }
  }

  async getAllAssets() {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all('SELECT * FROM assets WHERE status = "active" ORDER BY last_seen DESC', (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async getAssetById(assetId) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.get('SELECT * FROM assets WHERE id = ?', [assetId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async getAssetsByCategory(category) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all('SELECT * FROM assets WHERE category = ? AND status = "active"', [category], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async getAssetVulnerabilities(assetId) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all('SELECT * FROM asset_vulnerabilities WHERE asset_id = ? ORDER BY severity DESC', [assetId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async addVulnerability(assetId, vulnerability) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.run(`INSERT INTO asset_vulnerabilities 
        (asset_id, vulnerability_type, severity, description, remediation)
        VALUES (?, ?, ?, ?, ?)`,
        [assetId, vulnerability.type, vulnerability.severity, vulnerability.description, vulnerability.remediation],
        (err) => {
          if (err) reject(err);
          else {
            logger.warn(`Vulnerability recorded for asset ${assetId}: ${vulnerability.type}`);
            resolve();
          }
        }
      );
    });
  }

  async getAssetHistory(assetId) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all('SELECT * FROM asset_history WHERE asset_id = ? ORDER BY changed_at DESC LIMIT 100', [assetId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async getStaleAssets(hoursThreshold = 24) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all(`SELECT * FROM assets WHERE last_seen < datetime('now', '-${hoursThreshold} hours')`, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async markAssetOffline(assetId) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.run('UPDATE assets SET status = "offline", last_seen = CURRENT_TIMESTAMP WHERE id = ?', [assetId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

module.exports = AssetInventoryManager;
