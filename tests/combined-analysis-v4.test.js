const assert = require("assert");
const { combineV4Evidence } = require("../combined-analysis-v4.js");

const safeUrl = {
  version: "4.0", level: "safe", score: 0, reasons: [],
  signals: {}, evidence_groups: [], relationships: []
};
const safePage = {
  version: "4.0", level: "safe", score: 0, reasons: [],
  signals: {}, evidence_groups: [], relationships: []
};
const unavailable = { listed: false, available: false, source: "Phishing.Database", matchType: null };

const safe = combineV4Evidence(safeUrl, safePage, unavailable);
assert.strictEqual(safe.finalClassification, "safe");
assert.ok(safe.INTEGRATION.grouped_reasons.reputation[0].includes("indisponível"));

const unavailableIsNotListed = combineV4Evidence(safeUrl, safePage, {
  listed: false, available: true, source: "Phishing.Database", matchType: null
});
assert.strictEqual(unavailableIsNotListed.finalClassification, "safe");
assert.deepStrictEqual(unavailableIsNotListed.INTEGRATION.grouped_reasons.reputation, []);

const reputationBlock = combineV4Evidence(safeUrl, safePage, {
  listed: true, available: true, source: "Phishing.Database", matchType: "domain"
});
assert.strictEqual(reputationBlock.finalClassification, "blocked");
assert.strictEqual(reputationBlock.INTEGRATION.decision_basis, "listed-reputation");

const crossLayer = combineV4Evidence({
  ...safeUrl,
  score: 18,
  signals: { brand_mismatch: true, uses_shared_hosting: true },
  evidence_groups: ["identity", "infrastructure"]
}, {
  ...safePage,
  score: 10,
  signals: { credential_bundle: true, password_fields: true },
  evidence_groups: ["credentials"]
}, unavailable);
assert.strictEqual(crossLayer.finalClassification, "suspicious");
assert.ok(crossLayer.INTEGRATION.relationships.some((item) => item.code === "identity_collection"));

const sharedHostingAlone = combineV4Evidence({
  ...safeUrl,
  score: 9,
  signals: { uses_shared_hosting: true },
  evidence_groups: ["infrastructure"]
}, {
  ...safePage,
  score: 10,
  signals: { credential_bundle: true, password_fields: true },
  evidence_groups: ["credentials"]
}, unavailable);
assert.strictEqual(sharedHostingAlone.finalClassification, "safe");

const critical = combineV4Evidence({
  ...safeUrl,
  signals: { brand_mismatch: true },
  evidence_groups: ["identity"]
}, {
  ...safePage,
  signals: {
    credential_bundle: true,
    password_fields: true,
    credential_external: true,
    brand_mismatch: true
  },
  evidence_groups: ["credentials", "form_destination", "identity"]
}, unavailable);
assert.strictEqual(critical.finalClassification, "blocked");

const malformed = combineV4Evidence(null, "bad", []);
assert.strictEqual(malformed.finalClassification, "safe");

console.log("Fusão integrada V4: OK");
