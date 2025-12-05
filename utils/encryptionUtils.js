const crypto = require('crypto');
const logger = require('./loggerSetup')('encryption');

class EncryptionUtils {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.encryptionKey = this.deriveKey(process.env.ENCRYPTION_KEY || 'default-unsafe-key');
  }

  deriveKey(password) {
    return crypto.scryptSync(password, 'salt', 32);
  }

  encrypt(plaintext) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
      
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw error;
    }
  }

  decrypt(ciphertext) {
    try {
      const parts = ciphertext.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid ciphertext format');
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const authTag = Buffer.from(parts[1], 'hex');
      const encrypted = parts[2];
      
      const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw error;
    }
  }

  hashPassword(password) {
    return crypto.scryptSync(password, 'pepper', 64).toString('hex');
  }

  verifyPassword(password, hash) {
    return crypto.scryptSync(password, 'pepper', 64).toString('hex') === hash;
  }

  createHash(data, algorithm = 'sha256') {
    return crypto.createHash(algorithm).update(data).digest('hex');
  }

  verifyHash(data, hash, algorithm = 'sha256') {
    return this.createHash(data, algorithm) === hash;
  }

  generateRandomToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  encryptSensitiveObject(obj) {
    const sensitiveFields = [
      'password', 'api_key', 'secret', 'token', 'credential',
      'credit_card', 'ssn', 'private_key', 'database_url'
    ];

    const encrypted = { ...obj };

    for (const field of sensitiveFields) {
      if (encrypted[field]) {
        encrypted[`${field}_encrypted`] = this.encrypt(String(encrypted[field]));
        delete encrypted[field];
      }
    }

    return encrypted;
  }

  decryptSensitiveObject(obj) {
    const sensitiveFields = [
      'password', 'api_key', 'secret', 'token', 'credential',
      'credit_card', 'ssn', 'private_key', 'database_url'
    ];

    const decrypted = { ...obj };

    for (const field of sensitiveFields) {
      const encryptedField = `${field}_encrypted`;
      if (decrypted[encryptedField]) {
        try {
          decrypted[field] = this.decrypt(decrypted[encryptedField]);
        } catch (error) {
          logger.warn(`Failed to decrypt ${field}:`, error.message);
        }
        delete decrypted[encryptedField];
      }
    }

    return decrypted;
  }

  secureCompare(a, b) {
    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);

    if (bufferA.length !== bufferB.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < bufferA.length; i++) {
      result |= bufferA[i] ^ bufferB[i];
    }

    return result === 0;
  }

  createSignature(data, secret = process.env.SIGNING_KEY || 'default-key') {
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }

  verifySignature(data, signature, secret = process.env.SIGNING_KEY || 'default-key') {
    const expectedSignature = this.createSignature(data, secret);
    return this.secureCompare(signature, expectedSignature);
  }

  obfuscateString(str, showChars = 4) {
    if (str.length <= showChars) {
      return '*'.repeat(str.length);
    }
    const visible = str.substring(str.length - showChars);
    const hidden = '*'.repeat(str.length - showChars);
    return hidden + visible;
  }

  sanitizeSensitiveData(obj, depth = 0, maxDepth = 3) {
    if (depth > maxDepth) return obj;

    const sensitiveKeywords = [
      'password', 'secret', 'key', 'token', 'api', 'auth',
      'credential', 'private', 'ssn', 'credit', 'card'
    ];

    const sanitized = Array.isArray(obj) ? [...obj] : { ...obj };

    for (const key in sanitized) {
      const value = sanitized[key];
      const lowerKey = key.toLowerCase();

      if (sensitiveKeywords.some(keyword => lowerKey.includes(keyword))) {
        if (typeof value === 'string') {
          sanitized[key] = this.obfuscateString(value);
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = '[SENSITIVE_DATA]';
        }
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeSensitiveData(value, depth + 1, maxDepth);
      }
    }

    return sanitized;
  }
}

module.exports = EncryptionUtils;
