const ThreatDetector = require('../core/threatDetector');
const NetworkMonitor = require('../core/networkMonitor');
const LogAnalyzer = require('../core/logAnalyzer');

// Mock the dependencies
jest.mock('../core/networkMonitor');
jest.mock('../core/logAnalyzer');
jest.mock('../ai/anomalyDetector');

describe('ThreatDetector', () => {
  let threatDetector;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup mock implementations
    NetworkMonitor.mockImplementation(() => ({
      run: jest.fn().mockResolvedValue({ threats: [], connections: [] })
    }));

    LogAnalyzer.mockImplementation(() => ({
      run: jest.fn().mockResolvedValue([])
    }));

    threatDetector = new ThreatDetector();
  });

  test('should initialize with required components', () => {
    expect(threatDetector.networkMonitor).toBeDefined();
    expect(threatDetector.logAnalyzer).toBeDefined();
    expect(threatDetector.anomalyDetector).toBeDefined();
  });

  test('should detect threats from network and logs', async () => {
    const mockNetworkThreats = [
      { type: 'Suspicious Connection', severity: 'High', description: 'Test threat' }
    ];
    const mockLogThreats = [
      { type: 'Log Anomaly', severity: 'Medium', description: 'Log threat' }
    ];

    threatDetector.networkMonitor.run.mockResolvedValue({
      threats: mockNetworkThreats,
      connections: []
    });
    threatDetector.logAnalyzer.run.mockResolvedValue(mockLogThreats);

    const threats = await threatDetector.detectThreats();

    expect(threats).toHaveLength(2);
    expect(threats).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'Suspicious Connection' }),
      expect.objectContaining({ type: 'Log Anomaly' })
    ]));
  });

  test('should classify threats with AI enhancement', async () => {
    const mockThreats = [
      { type: 'Test Threat', severity: 'Low', description: 'Test' }
    ];

    threatDetector.anomalyDetector.analyzeThreats.mockResolvedValue([
      { ...mockThreats[0], aiAnomaly: true }
    ]);

    const classified = await threatDetector.classifyThreats(mockThreats);

    expect(classified[0].aiAnomaly).toBe(true);
    expect(classified[0].severity).toBe('Medium'); // Should be upgraded due to AI anomaly
    expect(classified[0].aiPrediction).toBe('AI-Detected Anomaly');
  });

  test('should run threat detection successfully', async () => {
    threatDetector.networkMonitor.run.mockResolvedValue({
      threats: [],
      connections: []
    });
    threatDetector.logAnalyzer.run.mockResolvedValue([]);

    const result = await threatDetector.run();

    expect(result).toEqual([]);
    expect(threatDetector.networkMonitor.run).toHaveBeenCalledTimes(1);
    expect(threatDetector.logAnalyzer.run).toHaveBeenCalledTimes(1);
  });

  test('should handle errors gracefully', async () => {
    threatDetector.networkMonitor.run.mockRejectedValue(new Error('Network error'));

    const result = await threatDetector.run();

    expect(result).toEqual([]);
  });
});