const assert = require("node:assert/strict");
const { combineAnalyses } = require("../combined-analysis.js");

function urlAnalysis(level = "safe", overrides = {}) {
  return {
    finalClassification: level,
    score: level === "safe" ? 0 : 30,
    reasons: [],
    externalReputation: { listed: level === "blocked" },
    localAnalysis: {
      level,
      evidence_categories: [],
      signals: {},
      ...overrides
    }
  };
}

function pageAnalysis(level = "safe", signals = {}) {
  return { level, score: level === "safe" ? 10 : 24, reasons: [], signals };
}

const safe = combineAnalyses(urlAnalysis(), pageAnalysis());
assert.equal(safe.finalClassification, "safe");
assert.equal(safe.COMBINED_ANALYSIS.page_added_risk, false);

const pageEscalation = combineAnalyses(urlAnalysis(), pageAnalysis("suspicious", { credential_external: true }));
assert.equal(pageEscalation.finalClassification, "suspicious");
assert.equal(pageEscalation.COMBINED_ANALYSIS.page_added_risk, true);

const crossLayer = combineAnalyses(
  urlAnalysis("safe", {
    evidence_categories: ["infrastructure"],
    signals: { uses_shared_hosting: true }
  }),
  pageAnalysis("safe", { credential_bundle: true })
);
assert.equal(crossLayer.finalClassification, "suspicious");
assert.equal(crossLayer.COMBINED_ANALYSIS.cross_layer_suspicious, true);

const identityCombination = combineAnalyses(
  urlAnalysis("safe", { evidence_categories: ["identity"], signals: { punycode: true } }),
  pageAnalysis("safe", { credential_bundle: true })
);
assert.equal(identityCombination.finalClassification, "suspicious");

const blocked = combineAnalyses(urlAnalysis("blocked"), pageAnalysis("suspicious", { credential_external: true }));
assert.equal(blocked.finalClassification, "blocked");

const urlOnlySuspicious = combineAnalyses(urlAnalysis("suspicious"), pageAnalysis());
assert.equal(urlOnlySuspicious.finalClassification, "suspicious");
assert.equal(urlOnlySuspicious.COMBINED_ANALYSIS.page_added_risk, false);

console.log("Combinação URL + página: OK");
