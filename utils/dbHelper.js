const { db: getDb } = require('../database/db');

class DatabaseHelper {
  static getDb() {
    return getDb();
  }

  static run(sql, params = []) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  }

  static get(sql, params = []) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  static all(sql, params = []) {
    return new Promise((resolve, reject) => {
      const db = getDb();
      db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  static serialize(callback) {
    const db = getDb();
    db.serialize(callback);
  }
}

module.exports = DatabaseHelper;
