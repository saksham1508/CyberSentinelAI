const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, '..', 'cybersentinel.db');
let db = null;

function initDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        reject(new Error(`Failed to connect to database: ${err.message}`));
        return;
      }

      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          source TEXT,
          level TEXT,
          message TEXT,
          ip TEXT,
          user_agent TEXT
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(new Error(`Failed to create logs table: ${err.message}`));
          }
        });

        db.run(`CREATE TABLE IF NOT EXISTS threats (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          type TEXT,
          severity TEXT,
          description TEXT,
          source_ip TEXT,
          destination_ip TEXT,
          protocol TEXT,
          port INTEGER
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(new Error(`Failed to create threats table: ${err.message}`));
          }
        });

        db.run(`CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          threat_id INTEGER,
          status TEXT,
          response TEXT,
          FOREIGN KEY (threat_id) REFERENCES threats(id)
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(new Error(`Failed to create incidents table: ${err.message}`));
          }
        });

        db.run(`CREATE TABLE IF NOT EXISTS configs (
          key TEXT PRIMARY KEY,
          value TEXT
        )`, (err) => {
          if (err && !err.message.includes('already exists')) {
            reject(new Error(`Failed to create configs table: ${err.message}`));
          } else {
            resolve();
          }
        });
      });
    });
  });
}

function getDatabase() {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return db;
}

function closeDatabase() {
  if (db) {
    return new Promise((resolve, reject) => {
      db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

module.exports = { getDatabase, initDatabase, closeDatabase, dbPath, db: null };
Object.defineProperty(module.exports, 'db', {
  get() {
    return getDatabase();
  }
});