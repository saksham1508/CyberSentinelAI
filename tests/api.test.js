const request = require('supertest');
const express = require('express');
const API = require('../core/api');

const mockDb = {
  all: jest.fn(),
  get: jest.fn(),
  run: jest.fn(function(sql, params, callback) {
    if (typeof callback === 'function') {
      callback.call({ lastID: 1, changes: 1 });
    }
  })
};

// Mock the database
jest.mock('../database/db', () => ({
  getDatabase: () => mockDb,
  initDatabase: jest.fn().mockResolvedValue(undefined),
  closeDatabase: jest.fn().mockResolvedValue(undefined)
}));

// Mock the threat detector
jest.mock('../core/threatDetector');

describe('API', () => {
  let app;
  let api;
  let mockThreatDetector;

  beforeEach(() => {
    jest.clearAllMocks();

    mockThreatDetector = {
      run: jest.fn().mockResolvedValue([
        { type: 'Test Threat', severity: 'High', description: 'Test threat' }
      ])
    };

    api = new API(mockThreatDetector);
    app = express();
    app.use(express.json());
    app.use('/api', api.router);
  });

  describe('GET /api/threats', () => {
    test('should return threats with default pagination', async () => {
      const mockThreats = [
        { id: 1, type: 'Test', severity: 'High', description: 'Test threat' }
      ];

      mockDb.all.mockImplementation((query, params, callback) => {
        callback(null, mockThreats);
      });

      const response = await request(app)
        .get('/api/threats')
        .expect(200);

      expect(response.body).toEqual(mockThreats);
      expect(mockDb.all).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM threats WHERE 1=1'),
        expect.any(Array),
        expect.any(Function)
      );
    });

    test('should filter threats by severity', async () => {
      mockDb.all.mockImplementation((query, params, callback) => {
        callback(null, []);
      });

      await request(app)
        .get('/api/threats?severity=High')
        .expect(200);

      expect(mockDb.all).toHaveBeenCalledWith(
        expect.stringContaining('severity = ?'),
        expect.arrayContaining(['High']),
        expect.any(Function)
      );
    });
  });

  describe('GET /api/threats/:id', () => {
    test('should return threat by id', async () => {
      const mockThreat = { id: 1, type: 'Test', severity: 'High' };

      mockDb.get.mockImplementation((query, params, callback) => {
        callback(null, mockThreat);
      });

      const response = await request(app)
        .get('/api/threats/1')
        .expect(200);

      expect(response.body).toEqual(mockThreat);
    });

    test('should return 404 for non-existent threat', async () => {
      mockDb.get.mockImplementation((query, params, callback) => {
        callback(null, null);
      });

      await request(app)
        .get('/api/threats/999')
        .expect(404);
    });
  });

  describe('POST /api/threats/scan', () => {
    test('should run threat scan', async () => {
      const response = await request(app)
        .post('/api/threats/scan')
        .expect(200);

      expect(mockThreatDetector.run).toHaveBeenCalledTimes(1);
      expect(response.body).toHaveProperty('threats');
      expect(response.body).toHaveProperty('scanTime');
      expect(response.body).toHaveProperty('totalFound');
    });
  });

  describe('GET /api/status', () => {
    test('should return system status', async () => {
      // Mock the stats query
      mockDb.get
        .mockImplementationOnce((query, callback) => callback(null, { count: 5 }))
        .mockImplementationOnce((query, callback) => callback(null, { count: 2 }))
        .mockImplementationOnce((query, callback) => callback(null, { count: 10 }))
        .mockImplementationOnce((query, callback) => callback(null, { count: 1 }));

      const response = await request(app)
        .get('/api/status')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'running');
      expect(response.body).toHaveProperty('version', '1.0.0');
      expect(response.body).toHaveProperty('stats');
      expect(response.body.stats).toHaveProperty('totalThreats', 5);
      expect(response.body.stats).toHaveProperty('activeIncidents', 2);
    });
  });

  describe('GET /api/config', () => {
    test('should return configuration with defaults when database is empty', async () => {
      mockDb.all.mockImplementation((query, callback) => {
        callback(null, null);
      });

      const response = await request(app)
        .get('/api/config')
        .expect(200);

      expect(response.body).toHaveProperty('monitoring_enabled', true);
      expect(response.body).toHaveProperty('ai_enabled', true);
      expect(response.body).toHaveProperty('monitoring_interval_minutes', 5);
    });

    test('should override defaults with database values', async () => {
      const mockConfig = [
        { key: 'monitoring_enabled', value: 'false' },
        { key: 'ai_enabled', value: 'true' },
        { key: 'monitoring_interval_minutes', value: '10' }
      ];

      mockDb.all.mockImplementation((query, callback) => {
        callback(null, mockConfig);
      });

      const response = await request(app)
        .get('/api/config')
        .expect(200);

      expect(response.body).toHaveProperty('monitoring_enabled', false);
      expect(response.body).toHaveProperty('ai_enabled', true);
      expect(response.body).toHaveProperty('monitoring_interval_minutes', 10);
    });
  });
});