const logger = require('../utils/loggerSetup')('cloud-config-validator');

function getDb() {
  return require('../database/db').getDatabase();
}

const CLOUD_PROVIDERS = {
  aws: 'AWS_REGION',
  azure: 'AZURE_SUBSCRIPTION_ID',
  gcp: 'GCP_PROJECT_ID'
};

class BaseValidator {
  async safeValidate(validationMethod) {
    try {
      return await validationMethod();
    } catch (error) {
      logger.warn(`Validation failed: ${error.message}`);
      return [];
    }
  }
}

class CloudConfigValidator {
  constructor() {
    this.validators = new Map();
    this.initializeValidators();
  }

  initializeValidators() {
    this.validators.set('aws', new AWSConfigValidator());
    this.validators.set('azure', new AzureConfigValidator());
    this.validators.set('gcp', new GCPConfigValidator());
  }

  async validateAllCloudConfigs() {
    const results = [];
    
    for (const [provider, envVar] of Object.entries(CLOUD_PROVIDERS)) {
      if (process.env[envVar]) {
        const providerResults = await this.validators.get(provider).validate();
        results.push(...providerResults);
      }
    }
    
    return results;
  }

  async persistMisconfigs(misconfigs) {
    const db = getDb();
    
    await this.createMisconfigTable(db);
    
    for (const config of misconfigs) {
      await this.insertMisconfig(db, config);
    }
  }

  createMisconfigTable(db) {
    return new Promise((resolve) => {
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
        }
        resolve();
      });
    });
  }

  insertMisconfig(db, config) {
    return new Promise((resolve) => {
      db.run(
        `INSERT INTO cloud_misconfigs (provider, resource_id, misconfiguration, severity, remediation)
         VALUES (?, ?, ?, ?, ?)`,
        [config.provider, config.resourceId, config.issue, config.severity, config.remediation],
        (err) => {
          if (err) logger.warn('Failed to record misconfig:', err);
          resolve();
        }
      );
    });
  }
}

class AWSConfigValidator extends BaseValidator {
  constructor() {
    super();
    this.s3 = null;
    this.ec2 = null;
    this.iam = null;
    this.rds = null;
  }

  getAWSModule() {
    try {
      return require('aws-sdk');
    } catch {
      logger.warn('aws-sdk not available');
      return null;
    }
  }

  async validate() {
    const AWS = this.getAWSModule();
    if (!AWS) return [];

    const issues = [];
    issues.push(...await this.safeValidate(() => this.validateS3(AWS)));
    issues.push(...await this.safeValidate(() => this.validateSecurityGroups(AWS)));
    issues.push(...await this.safeValidate(() => this.validateIAM(AWS)));
    issues.push(...await this.safeValidate(() => this.validateEncryption(AWS)));
    issues.push(...await this.safeValidate(() => this.validateNetworkACLs(AWS)));
    
    return issues;
  }

  async validateS3(AWS) {
    const issues = [];
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
        logger.warn(`Failed to validate S3 bucket ${bucket?.Name}:`, error.message);
      }
    }
    
    return issues;
  }

  async validateSecurityGroups(AWS) {
    const issues = [];
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
    
    return issues;
  }

  async validateIAM(AWS) {
    const issues = [];
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
    
    return issues;
  }

  async validateEncryption(AWS) {
    const issues = [];
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
    
    return issues;
  }

  async validateNetworkACLs(AWS) {
    const issues = [];
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
    
    return issues;
  }
}

class AzureConfigValidator extends BaseValidator {
  getAzureModules() {
    try {
      return {
        credential: require('@azure/identity').DefaultAzureCredential,
        storage: require('@azure/arm-storage').StorageManagementClient,
        network: require('@azure/arm-network').NetworkManagementClient,
        keyvault: require('@azure/arm-keyvault').KeyVaultManagementClient
      };
    } catch {
      logger.warn('Azure SDK modules not available');
      return null;
    }
  }

  async validate() {
    const modules = this.getAzureModules();
    if (!modules) return [];

    const issues = [];
    issues.push(...await this.safeValidate(() => this.validateStorageAccounts(modules)));
    issues.push(...await this.safeValidate(() => this.validateNetworkSecurityGroups(modules)));
    issues.push(...await this.safeValidate(() => this.validateKeyVault(modules)));
    
    return issues;
  }

  async validateStorageAccounts(modules) {
    const issues = [];
    const credential = new modules.credential();
    const client = new modules.storage(credential, process.env.AZURE_SUBSCRIPTION_ID);
    const storageAccounts = await client.storageAccounts.listByResourceGroup(process.env.AZURE_RESOURCE_GROUP);
    
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
    
    return issues;
  }

  async validateNetworkSecurityGroups(modules) {
    const issues = [];
    const credential = new modules.credential();
    const client = new modules.network(credential, process.env.AZURE_SUBSCRIPTION_ID);
    const nsgs = await client.networkSecurityGroups.list(process.env.AZURE_RESOURCE_GROUP);
    
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
    
    return issues;
  }

  async validateKeyVault(modules) {
    const issues = [];
    const credential = new modules.credential();
    const client = new modules.keyvault(credential, process.env.AZURE_SUBSCRIPTION_ID);
    const vaults = await client.vaults.listByResourceGroup(process.env.AZURE_RESOURCE_GROUP);
    
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
    
    return issues;
  }
}

class GCPConfigValidator extends BaseValidator {
  getGCPModules() {
    try {
      return {
        storage: require('@google-cloud/storage').Storage,
        compute: require('@google-cloud/compute').FirewallsClient,
        kms: require('@google-cloud/kms').KeyManagementServiceClient
      };
    } catch {
      logger.warn('GCP SDK modules not available');
      return null;
    }
  }

  async validate() {
    const modules = this.getGCPModules();
    if (!modules) return [];

    const issues = [];
    issues.push(...await this.safeValidate(() => this.validateStorageBuckets(modules)));
    issues.push(...await this.safeValidate(() => this.validateFirewallRules(modules)));
    issues.push(...await this.safeValidate(() => this.validateKMS(modules)));
    
    return issues;
  }

  async validateStorageBuckets(modules) {
    const issues = [];
    const client = new modules.storage({ projectId: process.env.GCP_PROJECT_ID });
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
    
    return issues;
  }

  async validateFirewallRules(modules) {
    const issues = [];
    const firewallsClient = new modules.compute();
    const [firewalls] = await firewallsClient.list({ project: process.env.GCP_PROJECT_ID });
    
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
    
    return issues;
  }

  async validateKMS(modules) {
    const issues = [];
    const client = new modules.kms();
    const projectId = process.env.GCP_PROJECT_ID;
    const name = client.locationPath(projectId, 'global');
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
    
    return issues;
  }
}

module.exports = CloudConfigValidator;
