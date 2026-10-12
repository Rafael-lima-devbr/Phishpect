const URL_LEVELS = new Set(["safe", "suspicious", "blocked"]);
const PAGE_LEVELS = new Set(["safe", "suspicious"]);

function safeScore(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
}

function stringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string").slice(0, 100) : [];
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizeUrlAnalysis(value) {
  const input = plainObject(value);
  const localInput = plainObject(input.localAnalysis);
  const localLevel = PAGE_LEVELS.has(localInput.level) ? localInput.level : "safe";
  const finalClassification = URL_LEVELS.has(input.finalClassification)
    ? input.finalClassification
    : localLevel;
  return {
    ...input,
    finalClassification,
    score: safeScore(input.score ?? localInput.score),
    reasons: stringArray(input.reasons),
    localAnalysis: {
      ...localInput,
      level: localLevel,
      score: safeScore(localInput.score),
      reasons: stringArray(localInput.reasons),
      signals: plainObject(localInput.signals),
      evidence_categories: stringArray(localInput.evidence_categories)
    },
    externalReputation: plainObject(input.externalReputation)
  };
}

function normalizePageAnalysis(value) {
  const input = plainObject(value);
  return {
    ...input,
    level: PAGE_LEVELS.has(input.level) ? input.level : "safe",
    score: safeScore(input.score),
    reasons: stringArray(input.reasons),
    signals: plainObject(input.signals),
    evidence_categories: stringArray(input.evidence_categories)
  };
}

function combineAnalyses(urlAnalysis, pageAnalysis) {
  const normalizedUrl = normalizeUrlAnalysis(urlAnalysis);
  const urlClassification = normalizedUrl.finalClassification;
  const urlLocal = normalizedUrl.localAnalysis;
  const page = normalizePageAnalysis(pageAnalysis);
  const combinationReasons = [];

  const urlSignals = urlLocal.signals || {};
  const urlCategories = new Set(urlLocal.evidence_categories || []);
  const pageSignals = page.signals || {};
  const hasPageCollection = pageSignals.credential_bundle === true || pageSignals.sensitive_data === true;
  const strongIdentityContext = urlSignals.brand_mismatch === true || urlSignals.punycode === true ||
    urlSignals.uses_userinfo === true || urlSignals.uses_ip === true;
  const infrastructureContext = urlSignals.uses_shared_hosting === true || urlSignals.uses_shortener === true || urlCategories.has("infrastructure");
  const authenticationContext = urlCategories.has("authentication") || urlSignals.authentication_in_hostname === true;

  let crossLayerSuspicious = false;
  if (hasPageCollection && strongIdentityContext) {
    crossLayerSuspicious = true;
    combinationReasons.push("Sinais de identidade da URL combinados com coleta de credenciais ou dados sensíveis na página");
  } else if (pageSignals.credential_bundle === true && urlCategories.size >= 2 && (infrastructureContext || authenticationContext)) {
    crossLayerSuspicious = true;
    combinationReasons.push("Contexto da URL combinado com formulário completo de autenticação na página");
  }

  let finalClassification = urlClassification;
  if (urlClassification !== "blocked" && (urlClassification === "suspicious" || page.level === "suspicious" || crossLayerSuspicious)) {
    finalClassification = "suspicious";
  }

  const reasons = [
    ...normalizedUrl.reasons.map((reason) => `[URL] ${reason}`),
    ...(page.reasons || []).map((reason) => `[Página] ${reason}`),
    ...combinationReasons.map((reason) => `[Combinação] ${reason}`)
  ];

  return {
    URL_ANALYSIS: normalizedUrl,
    PAGE_ANALYSIS: page,
    COMBINED_ANALYSIS: {
      finalClassification,
      score: Math.max(normalizedUrl.score, page.score),
      reasons,
      cross_layer_suspicious: crossLayerSuspicious,
      page_added_risk: page.level === "suspicious" || crossLayerSuspicious
    },
    finalClassification,
    score: Math.max(normalizedUrl.score, page.score),
    reasons,
    externalReputation: normalizedUrl.externalReputation
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { combineAnalyses, normalizeUrlAnalysis, normalizePageAnalysis };
}
