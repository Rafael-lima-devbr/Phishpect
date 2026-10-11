function combineAnalyses(urlAnalysis, pageAnalysis) {
  const urlClassification = urlAnalysis?.finalClassification || urlAnalysis?.localAnalysis?.level || "safe";
  const urlLocal = urlAnalysis?.localAnalysis || {};
  const page = pageAnalysis || { level: "safe", score: 0, reasons: [], signals: {} };
  const combinationReasons = [];

  const urlSignals = urlLocal.signals || {};
  const urlCategories = new Set(urlLocal.evidence_categories || []);
  const pageSignals = page.signals || {};
  const hasPageCollection = pageSignals.credential_bundle || pageSignals.sensitive_data;
  const strongIdentityContext = urlSignals.brand_mismatch || urlSignals.punycode || urlSignals.uses_userinfo || urlSignals.uses_ip;
  const infrastructureContext = urlSignals.uses_shared_hosting || urlSignals.uses_shortener || urlCategories.has("infrastructure");
  const authenticationContext = urlCategories.has("authentication") || urlSignals.authentication_in_hostname;

  let crossLayerSuspicious = false;
  if (hasPageCollection && strongIdentityContext) {
    crossLayerSuspicious = true;
    combinationReasons.push("Sinais de identidade da URL combinados com coleta de credenciais ou dados sensíveis na página");
  } else if (pageSignals.credential_bundle && (infrastructureContext || authenticationContext)) {
    crossLayerSuspicious = true;
    combinationReasons.push("Contexto da URL combinado com formulário completo de autenticação na página");
  }

  let finalClassification = urlClassification;
  if (urlClassification !== "blocked" && (urlClassification === "suspicious" || page.level === "suspicious" || crossLayerSuspicious)) {
    finalClassification = "suspicious";
  }

  const reasons = [
    ...(urlAnalysis?.reasons || []).map((reason) => `[URL] ${reason}`),
    ...(page.reasons || []).map((reason) => `[Página] ${reason}`),
    ...combinationReasons.map((reason) => `[Combinação] ${reason}`)
  ];

  return {
    URL_ANALYSIS: urlAnalysis,
    PAGE_ANALYSIS: page,
    COMBINED_ANALYSIS: {
      finalClassification,
      score: Math.max(Number(urlAnalysis?.score) || 0, Number(page.score) || 0),
      reasons,
      cross_layer_suspicious: crossLayerSuspicious,
      page_added_risk: page.level === "suspicious" || crossLayerSuspicious
    },
    finalClassification,
    score: Math.max(Number(urlAnalysis?.score) || 0, Number(page.score) || 0),
    reasons,
    externalReputation: urlAnalysis?.externalReputation || { listed: false }
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { combineAnalyses };
}
