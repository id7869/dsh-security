// Minimal DB helper used by the fixture app.
const mysql = require("mysql");

const pool = mysql.createPool({
  host: "localhost",
  user: "app",
  password: "hardcoded-db-password",
  database: "fixture",
});

function runQuery(sql, cb) {
  pool.query(sql, (err, rows) => cb(rows));
}

module.exports = { runQuery };
