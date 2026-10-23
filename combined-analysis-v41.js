const PHISHPECT_COMBINED_V41_VERSION = "4.1";

function v41CombinedBase() {
  if (typeof combineV4Evidence === "function") return combineV4Evidence;
  if (typeof require === "function") return require("./combined-analysis-v4.js").combineV4Evidence;
  throw new Error("Fusão contextual da V4 indisponível");
}

function combineV41Evidence(urlValue, pageValue, reputationValue) {
  const base = v41CombinedBase()(urlValue, pageValue, reputationValue);
  const url = base.URL || {};
  const page = base.PAGE || {};
  const urlSignals = url.signals || {};
  const pageSignals = page.signals || {};
  const relationships = [...(base.INTEGRATION?.relationships || [])];
  const groupedReasons = {
    url: [...(base.INTEGRATION?.grouped_reasons?.url || [])],
    page: [...(base.INTEGRATION?.grouped_reasons?.page || [])],
    reputation: [...(base.INTEGRATION?.grouped_reasons?.reputation || [])],
    integration: [...(base.INTEGRATION?.grouped_reasons?.integration || [])]
  };

  if (url.features?.protocol === "http" && pageSignals.password_fields === true) {
    const relation = {
      code: "insecure_password_collection",
      groups: ["url.transport", "page.credentials"],
      reason: "Página servida por HTTP solicita senha",
      strength: "strong"
    };
    relationships.push(relation);
    groupedReasons.integration.push(relation.reason);
  }

  let finalClassification = base.finalClassification;
  let decisionBasis = base.INTEGRATION?.decision_basis || "insufficient-context";
  if (finalClassification === "safe" && relationships.length > 0) {
    finalClassification = "suspicious";
    decisionBasis = "v4.1-contextual-cross-layer-evidence";
  }

  const reasons = [
    ...groupedReasons.url.map((reason) => `[URL] ${reason}`),
    ...groupedReasons.page.map((reason) => `[Página] ${reason}`),
    ...groupedReasons.reputation.map((reason) => `[Reputação] ${reason}`),
    ...groupedReasons.integration.map((reason) => `[Integração] ${reason}`)
  ];

  return {
    ...base,
    version: PHISHPECT_COMBINED_V41_VERSION,
    finalClassification,
    score: Math.max(Number(base.score) || 0, relationships.some((item) => item.code === "insecure_password_collection") ? 60 : 0),
    reasons: [...new Set(reasons)],
    INTEGRATION: {
      ...base.INTEGRATION,
      relationships,
      grouped_reasons: groupedReasons,
      evidence_groups: [...new Set([...(base.INTEGRATION?.evidence_groups || []),
        ...(relationships.some((item) => item.code === "insecure_password_collection") ? ["url.transport", "page.credentials"] : [])])],
      decision_basis: decisionBasis
    }
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { PHISHPECT_COMBINED_V41_VERSION, combineV41Evidence };
}
