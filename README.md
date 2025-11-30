# CyberSentinel AI - AI-Powered Cybersecurity Monitoring System

A comprehensive cybersecurity monitoring and threat detection system powered by artificial intelligence, featuring real-time network monitoring, log analysis, anomaly detection, and an interactive web-based dashboard.

## Features

- **Real-Time Threat Detection**: Monitors network connections and system logs for suspicious activities
- **AI-Powered Anomaly Detection**: Uses TensorFlow.js for machine learning-based threat classification
- **Network Monitoring**: Tracks active connections, detects suspicious ports and activities
- **Log Analysis**: Analyzes system logs for security-related keywords and patterns
- **Incident Management**: Automatically creates and tracks security incidents
- **Web Dashboard**: Interactive GUI for monitoring threats, incidents, and system metrics
- **REST API**: Full REST API for programmatic access to security data
- **Configuration Management**: Flexible configuration system with database and file persistence
- **Cross-Platform Support**: Works on Windows, macOS, and Linux
- **Automated Monitoring**: Configurable interval-based threat scanning

## Project Structure

```
CyberSentinelAI/
├── ai/
│   └── anomalyDetector.js          # AI-based anomaly detection
├── core/
│   ├── api.js                       # REST API implementation
│   ├── threatDetector.js            # Main threat detection orchestrator
│   ├── networkMonitor.js            # Network connection monitoring
│   ├── logAnalyzer.js               # System log analysis
│   └── configManager.js             # Configuration management
├── database/
│   └── db.js                        # SQLite database setup and management
├── utils/
│   ├── loggerSetup.js               # Winston logger configuration
│   ├── platformHelper.js            # Cross-platform utilities
│   └── dbHelper.js                  # Database helper utilities
├── ui/
│   ├── index.html                   # Dashboard UI
│   ├── styles.css                   # Dashboard styling
│   └── app.js                       # Dashboard JavaScript
├── tests/
│   ├── api.test.js                  # API endpoint tests
│   └── threatDetector.test.js       # Threat detector tests
├── logs/
│   ├── combined.log                 # Combined application logs
│   └── error.log                    # Error-only logs
├── config.json                      # Configuration file
├── index.js                         # Main application entry point
├── package.json                     # Dependencies and scripts
└── jest.config.js                   # Jest testing configuration
```

## Installation

### Prerequisites

- Node.js 18+ and npm
- Windows, macOS, or Linux

### Setup

1. **Clone or download the project**:
   ```bash
   cd CyberSentinelAI
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Verify installation**:
   ```bash
   npm test
   ```

## Running the Application

### Start the Server

```bash
npm start
```

or with a custom port:

```bash
node index.js start --port 8080
```

The application will start on `http://localhost:3000` by default.

### Run Manual Scan

```bash
npm run scan
```

### Development Mode

```bash
npm run dev
```

### Run Tests

```bash
npm test              # Run all tests
npm run test:watch    # Run tests in watch mode
npm run test:coverage # Generate coverage report
```

## Web Dashboard

Access the web-based dashboard at `http://localhost:3000`

### Dashboard Features

- **System Status**: Real-time system health indicators
- **Threat Statistics**: Overview of detected threats by type and severity
- **Analytics**: Charts showing threat trends and distributions
- **Threat Management**: View, filter, and manage detected threats
- **Incident Tracking**: Monitor security incidents and their status
- **System Logs**: Review application and system logs
- **Configuration**: Adjust system settings and monitoring parameters
- **Manual Scanning**: Trigger immediate threat scans

### Navigation

- **Dashboard**: Main overview with key metrics and charts
- **Threats**: Detailed list of all detected threats with filtering options
- **Incidents**: Security incidents and their current status
- **Logs**: System and application logs with level filtering
- **Settings**: Configuration management

## API Reference

### Base URL
`http://localhost:3000/api`

### Threat Endpoints

- **GET /threats** - List all threats
  - Query parameters: `limit`, `offset`, `severity`, `type`
  - Example: `/threats?severity=High&limit=10`

- **GET /threats/:id** - Get specific threat details

- **POST /threats/scan** - Run a manual threat scan

- **DELETE /threats/:id** - Delete a threat record

### Incident Endpoints

- **GET /incidents** - List all incidents
  - Query parameters: `status`, `limit`, `offset`

- **GET /incidents/:id** - Get specific incident details

- **POST /incidents** - Create a new incident

- **PUT /incidents/:id/status** - Update incident status

### Log Endpoints

- **GET /logs** - List system logs
  - Query parameters: `limit`, `offset`, `level`, `source`

- **GET /logs/recent** - Get recent logs
  - Query parameters: `hours` (default: 1)

- **POST /logs** - Create a new log entry

### Analytics Endpoints

- **GET /analytics/threats-by-type** - Threats grouped by type

- **GET /analytics/threats-by-severity** - Threats grouped by severity

- **GET /analytics/threats-timeline** - Threat data over time
  - Query parameters: `days` (default: 7)

### Configuration Endpoints

- **GET /config** - Get all configuration values

- **PUT /config** - Update configuration values

### System Endpoints

- **GET /status** - System status and statistics

- **GET /health** - Health check endpoint

## Configuration

Edit `config.json` or use the Settings tab in the dashboard to configure:

```json
{
  "monitoring_interval_minutes": 5,
  "monitoring_enabled": true,
  "alert_on_high_severity": true,
  "alert_on_medium_severity": false,
  "ai_enabled": true,
  "ai_confidence_threshold": 0.7,
  "log_level": "info",
  "network_monitoring_enabled": true,
  "suspicious_ports": "22,23,3389,5900",
  "log_analysis_enabled": true,
  "max_concurrent_scans": 3,
  "scan_timeout_seconds": 30
}
```

## Architecture

### Components

1. **Threat Detector** - Main orchestrator that combines multiple detection methods
2. **Network Monitor** - Monitors active network connections for suspicious activity
3. **Log Analyzer** - Analyzes system logs using NLP for security threats
4. **Anomaly Detector** - Uses TensorFlow.js for ML-based anomaly detection
5. **API Server** - Express.js REST API for data access and management
6. **Database** - SQLite for persistent storage of threats, incidents, and logs
7. **Config Manager** - Manages system configuration with persistence
8. **Logger** - Winston-based logging system

### Data Flow

```
Network/Logs → Monitors → Threat Detector → AI Analyzer → Database → API → Dashboard
```

### Database Schema

- **threats**: Detected security threats
- **incidents**: Security incidents linked to threats
- **logs**: System and application logs
- **configs**: Configuration key-value pairs

## Security Features

- **AI-Based Classification**: Threats are classified using machine learning
- **Severity Escalation**: AI anomalies automatically increase threat severity
- **Incident Auto-Creation**: High-severity threats automatically create incidents
- **Cross-Platform Support**: Monitors system-specific security indicators
- **Configurable Alerts**: Alert thresholds customizable by severity
- **Comprehensive Logging**: All operations logged for audit trails

## Performance

- **Efficient Database Queries**: Indexed queries for fast data retrieval
- **Async/Await Architecture**: Non-blocking I/O for responsiveness
- **Configurable Intervals**: Adjust monitoring frequency for system load
- **Batch Operations**: Efficient batch processing of multiple threats
- **Smart Caching**: Dashboard caches data to minimize API calls

## Troubleshooting

### Application won't start
- Verify Node.js is installed: `node --version`
- Clear node_modules and reinstall: `rm -rf node_modules && npm install`
- Check if port 3000 is available

### Tests failing
- Ensure all dependencies are installed: `npm install`
- Clear Jest cache: `npx jest --clearCache`
- Run tests with verbose output: `npm test -- --verbose`

### Network monitoring not working
- On Windows: Run as administrator
- On macOS/Linux: May require sudo for some operations
- Check platform compatibility in `utils/platformHelper.js`

### Database issues
- Delete `cybersentinel.db` to reset database
- Check logs for database errors: `cat logs/error.log`

## Development

### Adding New Threat Detection

1. Create a new detector in the `core/` directory
2. Implement a `run()` method that returns threats
3. Integrate with `threatDetector.js`
4. Add tests in `tests/` directory

### Extending the Dashboard

1. Add new HTML sections in `ui/index.html`
2. Add CSS styles in `ui/styles.css`
3. Add JavaScript functions in `ui/app.js`
4. Call new API endpoints as needed

### Contributing

- Follow existing code style and conventions
- Add tests for new features
- Update documentation
- Ensure all tests pass before committing

## Dependencies

- **express**: Web framework for REST API
- **sqlite3**: Lightweight database
- **mongoose**: (Optional) For MongoDB support
- **@tensorflow/tfjs**: Machine learning library
- **natural**: NLP library for text processing
- **winston**: Logging framework
- **commander**: CLI argument parsing
- **axios**: HTTP client
- **jest**: Testing framework
- **supertest**: HTTP assertion library

## Performance Metrics

- Response time: < 500ms for most API endpoints
- Scan time: 1-5 seconds depending on system load
- Memory usage: ~100-200MB baseline
- Database queries: Optimized with indexes
- Dashboard update interval: 30 seconds default

## Logging

Logs are stored in the `logs/` directory:

- **combined.log**: All application logs
- **error.log**: Error-level logs only

Configure log level in `config.json`:
```json
"log_level": "info"  // error, warn, info, debug
```

## Future Enhancements

- Email/SMS notifications for critical threats
- Machine learning model training and improvement
- Advanced firewall rule suggestions
- Threat correlation across multiple systems
- Historical threat analysis and reporting
- Integration with external security services

## License

ISC License - Feel free to use and modify

## Support

For issues or questions, check the logs and test output for detailed error messages.

## Version

1.0.0 - Initial Release

---

**CyberSentinel AI** - Your intelligent cybersecurity guardian
