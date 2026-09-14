const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { runQuery } = require("./db");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded production credential (fixture only)
const ADMIN_API_KEY = "sk-live-9f2a1b3c4d5e6f708192a3b4c5d6e7f";

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // VULN: SQL injection via string concatenation
  const q = `SELECT * FROM users WHERE name = '${username}' AND pass = '${password}'`;
  runQuery(q, (rows) => res.json(rows));
});

app.get("/search", (req, res) => {
  const q = req.query.q;
  // VULN: reflected XSS (unsanitized into HTML)
  res.send(`<h1>Results for ${q}</h1>`);
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  // VULN: command injection
  exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
});

app.get("/file", (req, res) => {
  const name = req.query.name;
  // VULN: path traversal
  const p = path.join("/var/www/uploads", name);
  fs.readFile(p, (err, data) => res.send(data));
});

app.listen(3000, () => console.log("fixture up"));
