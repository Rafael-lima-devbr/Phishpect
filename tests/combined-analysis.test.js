const assert = require("node:assert/strict");
const { combineAnalyses } = require("../combined-analysis.js");
const { analyzeUrl } = require("../analysis.js");

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
assert.equal(crossLayer.finalClassification, "safe");
assert.equal(crossLayer.COMBINED_ANALYSIS.cross_layer_suspicious, false);

const normalAuthenticationSubdomain = combineAnalyses(
  urlAnalysis("safe", {
    evidence_categories: ["authentication"],
    signals: { authentication_in_hostname: true }
  }),
  pageAnalysis("safe", { credential_bundle: true })
);
assert.equal(normalAuthenticationSubdomain.finalClassification, "safe");

function evaluatedUrl(url) {
  const localAnalysis = analyzeUrl(url);
  return {
    finalClassification: localAnalysis.level,
    score: localAnalysis.score,
    reasons: localAnalysis.reasons,
    externalReputation: { listed: false, available: true },
    localAnalysis
  };
}

for (const url of ["https://login.example.com/", "https://app.vercel.app/"]) {
  const normalLogin = combineAnalyses(evaluatedUrl(url), pageAnalysis("safe", { credential_bundle: true }));
  assert.equal(normalLogin.finalClassification, "safe", `${url} não deve escalar um login normal sozinho`);
}

const diverseAuthenticationContext = combineAnalyses(
  urlAnalysis("safe", {
    evidence_categories: ["authentication", "structure"],
    signals: { authentication_in_hostname: true }
  }),
  pageAnalysis("safe", { credential_bundle: true })
);
assert.equal(diverseAuthenticationContext.finalClassification, "suspicious");
assert.equal(diverseAuthenticationContext.COMBINED_ANALYSIS.cross_layer_suspicious, true);

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

const malformed = combineAnalyses({ score: "not-a-number", reasons: ["ok", 42], localAnalysis: [] }, {
  level: "blocked",
  score: Infinity,
  reasons: "invalid",
  signals: []
});
assert.equal(malformed.finalClassification, "safe");
assert.equal(malformed.score, 0);
assert.deepEqual(malformed.reasons, ["[URL] ok"]);

const falseLikeStrings = combineAnalyses(
  urlAnalysis("safe", { evidence_categories: ["identity"], signals: { brand_mismatch: "false" } }),
  pageAnalysis("safe", { credential_bundle: "false" })
);
assert.equal(falseLikeStrings.finalClassification, "safe");

console.log("Combinação URL + página: OK");
