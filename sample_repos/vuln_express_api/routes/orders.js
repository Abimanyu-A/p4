// Sample vulnerable Express routes used as a scan target for the SAST engine demo.
// Every finding here is labeled in sample_repos/ANSWER_KEY.json.
// DO NOT deploy this app anywhere real — it is deliberately insecure.

const express = require("express");
const { exec } = require("child_process");
const axios = require("axios");
const router = express.Router();

// fake db client standing in for a real driver
const db = {
  query: (sql, cb) => cb(null, [{ ok: true, sql }]),
};

// --- EXPRESS-SQLI-1 (true positive: injection) --------------------------------
router.get("/orders/search", (req, res) => {
  const customer = req.query.customer;
  // user input concatenated directly into SQL
  const sql = "SELECT id, item, total FROM orders WHERE customer = '" + customer + "'";
  db.query(sql, (err, rows) => res.json({ rows }));
});

// --- EXPRESS-CMDI-1 (true positive: injection) --------------------------------
router.get("/reports/generate", (req, res) => {
  const reportName = req.query.name;
  // untrusted input baked into a shell command string
  exec("wkhtmltopdf /tmp/reports/" + reportName + ".html /tmp/out.pdf", (err) => {
    res.json({ status: err ? "failed" : "queued" });
  });
});

// --- EXPRESS-SSRF-1 (true positive: SSRF — same class as FLASK-SSRF-1) -------
router.get("/webhooks/preview", async (req, res) => {
  const targetUrl = req.query.url;
  // attacker-controlled URL fetched server-side, no allowlist
  const resp = await axios.get(targetUrl, { timeout: 5000 });
  res.json({ status: resp.status, body: String(resp.data).slice(0, 200) });
});

// --- EXPRESS-CMDI-FP-1 (false-positive trap: fixed argv, no shell) ----------
router.get("/jobs/cleanup", (req, res) => {
  // execFile with a hardcoded argument array never touches a shell and takes
  // no request input, so it is not exploitable despite "exec"-like naming.
  const { execFile } = require("child_process");
  execFile("rm", ["-rf", "/tmp/worker-cache/"], () => {
    res.json({ status: "cleaned" });
  });
});

module.exports = router;
