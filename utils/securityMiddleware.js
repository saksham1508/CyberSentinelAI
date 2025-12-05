const crypto = require('crypto');
const logger = require('./loggerSetup')('security-middleware');

class SecurityMiddleware {
  constructor() {
    this.apiTokens = new Map();
    this.rateLimits = new Map();
    this.requestLogs = [];
  }

  inputValidation() {
    return (req, res, next) => {
      try {
        if (req.body && typeof req.body === 'object') {
          const sanitized = this.sanitizeObject(req.body);
          req.body = sanitized;
        }
        
        if (req.query && typeof req.query === 'object') {
          const sanitized = this.sanitizeObject(req.query);
          req.query = sanitized;
        }
        
        next();
      } catch (error) {
        logger.error('Input validation failed:', error);
        res.status(400).json({ error: 'Invalid input format' });
      }
    };
  }

  sanitizeObject(obj) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else if (typeof value === 'number') {
        sanitized[key] = value;
      } else if (typeof value === 'boolean') {
        sanitized[key] = value;
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(v => 
          typeof v === 'string' ? this.sanitizeString(v) : v
        );
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeObject(value);
      }
    }
    
    return sanitized;
  }

  sanitizeString(str) {
    if (typeof str !== 'string') return str;
    
    const xssPatterns = [
      /<script[^>]*>[\s\S]*?<\/script>/gi,
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
      /javascript:/gi,
      /vbscript:/gi
    ];
    
    let sanitized = str;
    xssPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });
    
    const sqlPatterns = [
      /(\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/gi
    ];
    
    sqlPatterns.forEach(pattern => {
      if (pattern.test(sanitized)) {
        logger.warn('Potential SQL injection detected:', sanitized.substring(0, 100));
      }
    });
    
    return sanitized.trim();
  }

  rateLimiting(maxRequests = 100, windowMs = 60000) {
    return (req, res, next) => {
      const clientIP = req.ip || req.connection.remoteAddress;
      const key = `${clientIP}:${req.path}`;
      const now = Date.now();
      
      if (!this.rateLimits.has(key)) {
        this.rateLimits.set(key, []);
      }
      
      const requests = this.rateLimits.get(key);
      const recentRequests = requests.filter(time => now - time < windowMs);
      
      if (recentRequests.length >= maxRequests) {
        logger.warn(`Rate limit exceeded for ${clientIP}`);
        return res.status(429).json({ 
          error: 'Too many requests. Please try again later.' 
        });
      }
      
      recentRequests.push(now);
      this.rateLimits.set(key, recentRequests);
      
      next();
    };
  }

  authentication(secretKey = process.env.API_SECRET_KEY) {
    return (req, res, next) => {
      if (!secretKey) {
        logger.warn('No API secret key configured');
        return next();
      }
      
      const authHeader = req.headers.authorization;
      
      if (!authHeader) {
        if (req.path.includes('/public/') || req.path === '/health') {
          return next();
        }
        return res.status(401).json({ error: 'Missing authorization header' });
      }
      
      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
        return res.status(401).json({ error: 'Invalid authorization format' });
      }
      
      const token = parts[1];
      
      try {
        const verified = this.verifyToken(token, secretKey);
        req.user = verified;
        next();
      } catch (error) {
        logger.warn('Token verification failed:', error.message);
        res.status(401).json({ error: 'Invalid or expired token' });
      }
    };
  }

  generateToken(payload, secretKey = process.env.API_SECRET_KEY, expiresIn = '24h') {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    
    const now = Math.floor(Date.now() / 1000);
    const expiresInSeconds = this.parseTimeToSeconds(expiresIn);
    
    const claims = {
      ...payload,
      iat: now,
      exp: now + expiresInSeconds
    };
    
    const headerEncoded = Buffer.from(JSON.stringify(header)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const claimsEncoded = Buffer.from(JSON.stringify(claims)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    
    const signature = this.createSignature(
      `${headerEncoded}.${claimsEncoded}`,
      secretKey
    );
    
    return `${headerEncoded}.${claimsEncoded}.${signature}`;
  }

  verifyToken(token, secretKey = process.env.API_SECRET_KEY) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }
    
    const [headerEncoded, claimsEncoded, signatureReceived] = parts;
    
    const signature = this.createSignature(
      `${headerEncoded}.${claimsEncoded}`,
      secretKey
    );
    
    if (signature !== signatureReceived) {
      throw new Error('Invalid token signature');
    }
    
    const claims = JSON.parse(
      Buffer.from(claimsEncoded + '==', 'base64').toString('utf8')
    );
    
    if (claims.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    return claims;
  }

  createSignature(message, secretKey) {
    return crypto
      .createHmac('sha256', secretKey)
      .update(message)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  parseTimeToSeconds(timeStr) {
    const units = { s: 1, m: 60, h: 3600, d: 86400 };
    const match = timeStr.match(/^(\d+)([smhd])$/);
    if (!match) return 86400;
    return parseInt(match[1]) * units[match[2]];
  }

  requestLogging() {
    return (req, res, next) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        const log = {
          timestamp: new Date().toISOString(),
          method: req.method,
          path: req.path,
          status: res.statusCode,
          duration,
          clientIP: req.ip,
          userAgent: req.get('user-agent')
        };
        
        this.requestLogs.push(log);
        
        if (this.requestLogs.length > 1000) {
          this.requestLogs.shift();
        }
        
        if (res.statusCode >= 400) {
          logger.warn(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
        }
      });
      
      next();
    };
  }

  corsHeaders() {
    return (req, res, next) => {
      const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
      const origin = req.get('origin');
      
      if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        res.set('Access-Control-Allow-Origin', origin || '*');
        res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.set('Access-Control-Allow-Credentials', 'true');
      }
      
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      
      next();
    };
  }

  securityHeaders() {
    return (req, res, next) => {
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('X-Frame-Options', 'DENY');
      res.set('X-XSS-Protection', '1; mode=block');
      res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.set('Content-Security-Policy', "default-src 'self'");
      
      next();
    };
  }

  getRequestLogs(limit = 100) {
    return this.requestLogs.slice(-limit);
  }

  clearOldRateLimits() {
    const now = Date.now();
    const windowMs = 60000;
    
    for (const [key, requests] of this.rateLimits.entries()) {
      const active = requests.filter(time => now - time < windowMs);
      if (active.length === 0) {
        this.rateLimits.delete(key);
      } else {
        this.rateLimits.set(key, active);
      }
    }
  }
}

module.exports = SecurityMiddleware;
