const logger = require('../utils/loggerSetup')('cloud-config-validator');

function getDb() {
  return require('../database/db').getDatabase();
}

class CloudConfigValidator {
  constructor() {
    this.validators = new Map();
    this.misconfigs = [];
    this.initializeValidators();
  }

  initializeValidators() {
    this.validators.set('aws', new AWSConfigValidator());
    this.validators.set('azure', new AzureConfigValidator());
    this.validators.set('gcp', new GCPConfigValidator());
  }

  async validateAllCloudConfigs() {
    const results = [];
    
    try {
      if (process.env.AWS_REGION) {
        const awsResults = await this.validators.get('aws').validate();
        results.push(...awsResults);
      }
      
      if (process.env.AZURE_SUBSCRIPTION_ID) {
        const azureResults = await this.validators.get('azure').validate();
        results.push(...azureResults);
      }
      
      if (process.env.GCP_PROJECT_ID) {
        const gcpResults = await this.validators.get('gcp').validate();
        results.push(...gcpResults);
      }
    } catch (error) {
      logger.error('Cloud config validation failed:', error);
    }
    
    return results;
  }

  async persistMisconfigs(misconfigs) {
    return new Promise((resolve) => {
      const db = getDb();
      
      db.run(`CREATE TABLE IF NOT EXISTS cloud_misconfigs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT,
        resource_id TEXT,
        misconfiguration TEXT,
        severity TEXT,
        remediation TEXT,
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, (err) => {
        if (err && !err.message.includes('already exists')) {
          logger.warn('Failed to create cloud_misconfigs table:', err);
          resolve();
          return;
        }
        
        for (const config of misconfigs) {
          db.run(`INSERT INTO cloud_misconfigs (provider, resource_id, misconfiguration, severity, remediation)
            VALUES (?, ?, ?, ?, ?)`,
            [config.provider, config.resourceId, config.issue, config.severity, config.remediation],
            (err) => {
              if (err) logger.warn('Failed to record misconfig:', err);
            }
          );
        }
        resolve();
      });
    });
  }
}

class AWSConfigValidator {
  async validate() {
    const issues = [];
    
    try {
      issues.push(...await this.validateS3());
      issues.push(...await this.validateSecurityGroups());
      issues.push(...await this.validateIAM());
      issues.push(...await this.validateEncryption());
      issues.push(...await this.validateNetworkACLs());
    } catch (error) {
      logger.error('AWS validation error:', error);
    }
    
    return issues;
  }

  async validateS3() {
    const issues = [];
    
    try {
      const AWS = require('aws-sdk');
      const s3 = new AWS.S3();
      
      const buckets = await s3.listBuckets().promise();
      
      for (const bucket of buckets.Buckets) {
        try {
          const acl = await s3.getBucketAcl({ Bucket: bucket.Name }).promise();
          
          if (acl.Grants.some(g => g.Grantee.Type === 'Group' && 
            g.Grantee.URI && g.Grantee.URI.includes('AllUsers'))) {
            issues.push({
              provider: 'aws',
              resourceId: bucket.Name,
              issue: 'S3 bucket is publicly readable',
              severity: 'critical',
              remediation: 'Remove public access grants from bucket ACL'
            });
          }
          
          const encryption = await s3.getBucketEncryption({ Bucket: bucket.Name }).promise().catch(() => null);
          if (!encryption) {
            issues.push({
              provider: 'aws',
              resourceId: bucket.Name,
              issue: 'S3 bucket does not have encryption enabled',
              severity: 'high',
              remediation: 'Enable default encryption (SSE-S3 or SSE-KMS)'
            });
          }
          
          const versioning = await s3.getBucketVersioning({ Bucket: bucket.Name }).promise();
          if (versioning.Status !== 'Enabled') {
            issues.push({
              provider: 'aws',
              resourceId: bucket.Name,
              issue: 'S3 bucket versioning is not enabled',
              severity: 'medium',
              remediation: 'Enable versioning for data protection'
            });
          }
        } catch (error) {
          logger.warn(`Failed to validate S3 bucket ${bucket.Name}:`, error.message);
        }
      }
    } catch (error) {
      logger.warn('S3 validation failed:', error.message);
    }
    
    return issues;
  }

  async validateSecurityGroups() {
    const issues = [];
    
    try {
      const AWS = require('aws-sdk');
      const ec2 = new AWS.EC2({ region: process.env.AWS_REGION });
      
      const sgs = await ec2.describeSecurityGroups().promise();
      
      for (const sg of sgs.SecurityGroups) {
        sg.IpPermissions.forEach(rule => {
          if (rule.IpRanges?.some(r => r.CidrIp === '0.0.0.0/0')) {
            issues.push({
              provider: 'aws',
              resourceId: sg.GroupId,
              issue: `Security group allows unrestricted inbound access on port ${rule.FromPort}`,
              severity: 'high',
              remediation: 'Restrict inbound rules to specific IP ranges or security groups'
            });
          }
        });
      }
    } catch (error) {
      logger.warn('Security groups validation failed:', error.message);
    }
    
    return issues;
  }

  async validateIAM() {
    const issues = [];
    
    try {
      const AWS = require('aws-sdk');
      const iam = new AWS.IAM();
      
      const users = await iam.listUsers().promise();
      
      for (const user of users.Users) {
        const keys = await iam.listAccessKeys({ UserName: user.UserName }).promise();
        
        if (keys.AccessKeyMetadata.length > 1) {
          issues.push({
            provider: 'aws',
            resourceId: user.UserName,
            issue: 'IAM user has multiple access keys',
            severity: 'medium',
            remediation: 'Deactivate unused access keys and implement key rotation'
          });
        }
        
        for (const key of keys.AccessKeyMetadata) {
          const ageInDays = Math.floor((Date.now() - new Date(key.CreateDate)) / (1000 * 60 * 60 * 24));
          if (ageInDays > 90) {
            issues.push({
              provider: 'aws',
              resourceId: `${user.UserName}/${key.AccessKeyId}`,
              issue: 'Access key is older than 90 days',
              severity: 'medium',
              remediation: 'Rotate old access keys and implement key rotation policy'
            });
          }
        }
      }
    } catch (error) {
      logger.warn('IAM validation failed:', error.message);
    }
    
    return issues;
  }

  async validateEncryption() {
    const issues = [];
    
    try {
      const AWS = require('aws-sdk');
      const rds = new AWS.RDS();
      
      const databases = await rds.describeDBInstances().promise();
      
      for (const db of databases.DBInstances) {
        if (!db.StorageEncrypted) {
          issues.push({
            provider: 'aws',
            resourceId: db.DBInstanceIdentifier,
            issue: 'RDS database encryption is not enabled',
            severity: 'critical',
            remediation: 'Enable encryption at rest for all RDS instances'
          });
        }
      }
    } catch (error) {
      logger.warn('Encryption validation failed:', error.message);
    }
    
    return issues;
  }

  async validateNetworkACLs() {
    const issues = [];
    
    try {
      const AWS = require('aws-sdk');
      const ec2 = new AWS.EC2({ region: process.env.AWS_REGION });
      
      const nacls = await ec2.describeNetworkAcls().promise();
      
      for (const nacl of nacls.NetworkAcls) {
        nacl.Entries.forEach(entry => {
          if (entry.RuleAction === 'allow' && 
            entry.CidrBlock === '0.0.0.0/0' &&
            entry.PortRange?.FromPort === 3306) {
            issues.push({
              provider: 'aws',
              resourceId: nacl.NetworkAclId,
              issue: 'Network ACL allows unrestricted database access',
              severity: 'critical',
              remediation: 'Restrict database port access to specific subnets'
            });
          }
        });
      }
    } catch (error) {
      logger.warn('Network ACL validation failed:', error.message);
    }
    
    return issues;
  }
}

class AzureConfigValidator {
  async validate() {
    const issues = [];
    
    try {
      issues.push(...await this.validateStorageAccounts());
      issues.push(...await this.validateNetworkSecurityGroups());
      issues.push(...await this.validateKeyVault());
    } catch (error) {
      logger.error('Azure validation error:', error);
    }
    
    return issues;
  }

  async validateStorageAccounts() {
    const issues = [];
    
    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { StorageManagementClient } = require('@azure/arm-storage');
      
      const credential = new DefaultAzureCredential();
      const client = new StorageManagementClient(credential, process.env.AZURE_SUBSCRIPTION_ID);
      
      const resourceGroupName = process.env.AZURE_RESOURCE_GROUP;
      const storageAccounts = await client.storageAccounts.listByResourceGroup(resourceGroupName);
      
      for (const account of storageAccounts) {
        if (!account.encryption?.services?.blob?.enabled) {
          issues.push({
            provider: 'azure',
            resourceId: account.name,
            issue: 'Storage account encryption is not enabled',
            severity: 'high',
            remediation: 'Enable encryption for all storage services'
          });
        }
      }
    } catch (error) {
      logger.warn('Azure storage validation failed:', error.message);
    }
    
    return issues;
  }

  async validateNetworkSecurityGroups() {
    const issues = [];
    
    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { NetworkManagementClient } = require('@azure/arm-network');
      
      const credential = new DefaultAzureCredential();
      const client = new NetworkManagementClient(credential, process.env.AZURE_SUBSCRIPTION_ID);
      
      const resourceGroupName = process.env.AZURE_RESOURCE_GROUP;
      const nsgs = await client.networkSecurityGroups.list(resourceGroupName);
      
      for (const nsg of nsgs) {
        nsg.securityRules?.forEach(rule => {
          if (rule.access === 'Allow' && rule.sourceAddressPrefix === '*') {
            issues.push({
              provider: 'azure',
              resourceId: nsg.name,
              issue: `NSG rule allows unrestricted access on port ${rule.destinationPortRange}`,
              severity: 'high',
              remediation: 'Restrict source address prefixes to specific ranges'
            });
          }
        });
      }
    } catch (error) {
      logger.warn('Azure NSG validation failed:', error.message);
    }
    
    return issues;
  }

  async validateKeyVault() {
    const issues = [];
    
    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { KeyVaultManagementClient } = require('@azure/arm-keyvault');
      
      const credential = new DefaultAzureCredential();
      const client = new KeyVaultManagementClient(credential, process.env.AZURE_SUBSCRIPTION_ID);
      
      const resourceGroupName = process.env.AZURE_RESOURCE_GROUP;
      const vaults = await client.vaults.listByResourceGroup(resourceGroupName);
      
      for (const vault of vaults) {
        if (!vault.properties.enablePurgeProtection) {
          issues.push({
            provider: 'azure',
            resourceId: vault.name,
            issue: 'Key Vault purge protection is not enabled',
            severity: 'medium',
            remediation: 'Enable purge protection for accidental deletion prevention'
          });
        }
      }
    } catch (error) {
      logger.warn('Azure Key Vault validation failed:', error.message);
    }
    
    return issues;
  }
}

class GCPConfigValidator {
  async validate() {
    const issues = [];
    
    try {
      issues.push(...await this.validateStorageBuckets());
      issues.push(...await this.validateFirewallRules());
      issues.push(...await this.validateKMS());
    } catch (error) {
      logger.error('GCP validation error:', error);
    }
    
    return issues;
  }

  async validateStorageBuckets() {
    const issues = [];
    
    try {
      const storage = require('@google-cloud/storage');
      const client = new storage.Storage({ projectId: process.env.GCP_PROJECT_ID });
      
      const [buckets] = await client.getBuckets();
      
      for (const bucket of buckets) {
        const [metadata] = await bucket.getMetadata();
        
        if (!metadata.encryption) {
          issues.push({
            provider: 'gcp',
            resourceId: bucket.name,
            issue: 'Storage bucket encryption is not enabled',
            severity: 'high',
            remediation: 'Enable customer-managed or Google-managed encryption'
          });
        }
      }
    } catch (error) {
      logger.warn('GCP storage validation failed:', error.message);
    }
    
    return issues;
  }

  async validateFirewallRules() {
    const issues = [];
    
    try {
      const compute = require('@google-cloud/compute');
      const firewallsClient = new compute.FirewallsClient();
      
      const request = { project: process.env.GCP_PROJECT_ID };
      const [firewalls] = await firewallsClient.list(request);
      
      for (const firewall of firewalls) {
        if (firewall.allowed?.some(a => a.IPProtocol === 'tcp' && 
          (!a.ports || a.ports.includes('3306')))) {
          if (firewall.sourceRanges?.includes('0.0.0.0/0')) {
            issues.push({
              provider: 'gcp',
              resourceId: firewall.name,
              issue: 'Firewall rule allows unrestricted database access',
              severity: 'critical',
              remediation: 'Restrict source ranges to specific networks'
            });
          }
        }
      }
    } catch (error) {
      logger.warn('GCP firewall validation failed:', error.message);
    }
    
    return issues;
  }

  async validateKMS() {
    const issues = [];
    
    try {
      const kms = require('@google-cloud/kms');
      const client = new kms.KeyManagementServiceClient();
      
      const projectId = process.env.GCP_PROJECT_ID;
      const locationId = 'global';
      
      const name = client.locationPath(projectId, locationId);
      const [keyRings] = await client.listKeyRings({ parent: name });
      
      if (!keyRings || keyRings.length === 0) {
        issues.push({
          provider: 'gcp',
          resourceId: projectId,
          issue: 'No KMS key rings found - consider enabling customer-managed encryption',
          severity: 'medium',
          remediation: 'Create and use customer-managed KMS keys for encryption'
        });
      }
    } catch (error) {
      logger.warn('GCP KMS validation failed:', error.message);
    }
    
    return issues;
  }
}

module.exports = CloudConfigValidator;
