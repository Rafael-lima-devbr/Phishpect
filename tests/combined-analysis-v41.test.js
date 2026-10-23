const assert = require("node:assert/strict");
const { analyzeUrlV41 } = require("../analysis-v41.js");
const { combineV41Evidence } = require("../combined-analysis-v41.js");

const unavailable = { available: false, listed: false, source: null, matchType: null };
function page(signals = {}, groups = []) {
  return { version: "4.0", level: "safe", score: 10, reasons: [], signals, evidence_groups: groups, relationships: [] };
}

assert.equal(combineV41Evidence(
  analyzeUrlV41("http://example.test/"),
  page({ password_fields: true }, ["credentials"]), unavailable
).finalClassification, "suspicious", "HTTP + password deve ser corroborado entre camadas");

assert.equal(combineV41Evidence(
  analyzeUrlV41("https://accounts.example.test/login"),
  page({ password_fields: true, credential_bundle: true }, ["credentials"]), unavailable
).finalClassification, "safe", "login HTTPS normal não deve ser alertado");

assert.equal(combineV41Evidence(
  analyzeUrlV41("https://tenant.pages.dev/login"),
  page({ password_fields: true, credential_bundle: true }, ["credentials"]), unavailable
).finalClassification, "safe", "shared hosting + login normal não deve ser alertado");

console.log("Fusão contextual V4.1: OK");
