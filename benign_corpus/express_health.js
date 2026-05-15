// Express health endpoint — no user input, no external calls beyond DB ping.
const express = require("express");
const router = express.Router();

router.get("/health", async (req, res) => {
  const checks = { app: "ok" };
  try {
    await req.app.locals.db.query("SELECT 1");
    checks.db = "ok";
  } catch (err) {
    checks.db = "error";
    res.status(503);
  }
  res.json({ status: res.statusCode === 503 ? "degraded" : "ok", checks });
});

module.exports = router;
