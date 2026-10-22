const assert = require("node:assert/strict");
const {
  WARNING_STATE_TTL_MS,
  validWarningToken,
  createWarningState,
  normalizeWarningState
} = require("../warning-state.js");

const token = "123e4567-e89b-12d3-a456-426614174000";
assert.equal(validWarningToken(token), true);
assert.equal(validWarningToken("short"), false);
assert.equal(validWarningToken("../state-token-that-is-not-valid"), false);

const now = 1_000;
const state = createWarningState("https://example.test/login#fragment", {
  finalClassification: "suspicious",
  score: 63,
  reasons: ["motivo"],
  INTEGRATION: { grouped_reasons: { url: ["URL suspeita"], page: [], reputation: [], integration: ["relação"] } },
  externalReputation: { listed: false, available: true, source: "Phishing.Database", matchType: null }
}, now);
assert.equal(state.url, "https://example.test/login#fragment");
assert.equal(state.expiresAt, now + WARNING_STATE_TTL_MS);
assert.equal(normalizeWarningState(state, now + 1).level, "suspicious");
assert.equal(normalizeWarningState(state, state.expiresAt), null);
assert.equal(normalizeWarningState({ ...state, url: "javascript:alert(1)" }, now + 1), null);

const blocked = createWarningState("https://example.test/", {
  finalClassification: "blocked",
  score: 500,
  reasons: new Array(120).fill("x"),
  externalReputation: { listed: true, available: true, source: "source", matchType: "domain" }
}, now);
assert.equal(blocked.level, "blocked");
assert.equal(blocked.score, 100);
assert.equal(blocked.reasons.length, 100);

console.log("Estado opaco de aviso: OK");
