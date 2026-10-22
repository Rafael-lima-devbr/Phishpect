const PHISHPECT_COMBINED_V4_VERSION = "4.0";
const V4_FINAL_LEVELS = new Set(["safe", "suspicious", "blocked"]);

function v4PlainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function v4Strings(value, maximum = 100) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string").slice(0, maximum) : [];
}

function v4Score(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
}

function normalizeV4UrlResult(value) {
  const outer = v4PlainObject(value);
  const local = v4PlainObject(outer.localAnalysis && outer.localAnalysis.version === "4.0" ? outer.localAnalysis : outer);
  const level = V4_FINAL_LEVELS.has(local.level) ? local.level : "safe";
  return {
    ...local,
    level,
    score: v4Score(local.score),
    reasons: v4Strings(local.reasons),
    signals: v4PlainObject(local.signals),
    evidence_groups: v4Strings(local.evidence_groups || local.evidence_categories),
    relationships: Array.isArray(local.relationships) ? local.relationships.slice(0, 50) : []
  };
}

function normalizeV4PageResult(value) {
  const page = v4PlainObject(value);
  return {
    ...page,
    level: page.level === "suspicious" ? "suspicious" : "safe",
    score: v4Score(page.score),
    reasons: v4Strings(page.reasons),
    signals: v4PlainObject(page.signals),
    evidence_groups: v4Strings(page.evidence_groups || page.evidence_categories),
    relationships: Array.isArray(page.relationships) ? page.relationships.slice(0, 50) : []
  };
}

function normalizeV4Reputation(value) {
  const reputation = v4PlainObject(value);
  return {
    listed: reputation.listed === true,
    available: reputation.available === true,
    source: typeof reputation.source === "string" ? reputation.source.slice(0, 100) : null,
    matchType: ["exact-url", "domain"].includes(reputation.matchType) ? reputation.matchType : null
  };
}

function combineV4Evidence(urlValue, pageValue, reputationValue) {
  const url = normalizeV4UrlResult(urlValue);
  const page = normalizeV4PageResult(pageValue);
  const reputation = normalizeV4Reputation(reputationValue);
  const urlGroups = new Set(url.evidence_groups);
  const pageSignals = page.signals;
  const urlSignals = url.signals;
  const relationships = [];
  const add = (code, groups, reason, strength = "strong") => relationships.push({ code, groups, reason, strength });

  const pageCollectsCredentials = pageSignals.credential_bundle === true || pageSignals.password_fields === true;
  const pageCollectsSensitive = pageSignals.sensitive_data === true;
  const strongUrlIdentity = urlSignals.brand_mismatch === true || urlSignals.uses_userinfo === true ||
    urlSignals.multiple_at === true || urlSignals.uses_ip === true ||
    (urlSignals.punycode === true && url.relationships.some((item) => item.code === "punycode_brand"));

  if (strongUrlIdentity && (pageCollectsCredentials || pageCollectsSensitive)) {
    add("identity_collection", ["url.identity", "page.collection"], "Identidade suspeita na URL coincide com coleta de credenciais ou dados na página");
  }
  if (urlGroups.has("authentication") && pageSignals.credential_bundle === true &&
      (urlGroups.has("infrastructure") || urlGroups.has("transport") || urlGroups.has("identity"))) {
    add("authentication_alignment", ["url.authentication", "page.credentials"], "Contexto de autenticação da URL coincide com formulário completo de acesso");
  }
  if (urlSignals.uses_shared_hosting === true &&
      (pageSignals.credential_external === true || pageSignals.brand_mismatch === true)) {
    add("shared_hosting_exfiltration", ["url.infrastructure", "page.destination"], "Hospedagem compartilhada coincide com identidade incompatível ou envio externo de credenciais");
  }
  if (pageSignals.credential_external === true && pageSignals.brand_mismatch === true) {
    add("identity_exfiltration", ["page.identity", "page.credentials", "page.destination"], "A página apresenta identidade incompatível e envia credenciais para outro domínio", "critical");
  }
  if (pageSignals.high_risk_sensitive_external === true && strongUrlIdentity) {
    add("sensitive_exfiltration", ["url.identity", "page.sensitive_data", "page.destination"], "Identidade suspeita coincide com envio externo de dados financeiros ou documentos", "critical");
  }

  let finalClassification = "safe";
  let decisionBasis = "insufficient-context";
  if (reputation.listed) {
    finalClassification = "blocked";
    decisionBasis = "listed-reputation";
  } else if (url.level === "blocked") {
    finalClassification = "blocked";
    decisionBasis = "confirmed-local-threat";
  } else if (relationships.some((item) => item.strength === "critical") &&
      relationships.filter((item) => ["strong", "critical"].includes(item.strength)).length >= 2) {
    finalClassification = "blocked";
    decisionBasis = "corroborated-critical-cross-layer-evidence";
  } else if (url.level === "suspicious" || page.level === "suspicious" || relationships.length > 0) {
    finalClassification = "suspicious";
    decisionBasis = relationships.length ? "contextual-cross-layer-evidence" :
      (url.level === "suspicious" ? "url-module" : "page-module");
  }

  const groupedReasons = {
    url: url.reasons,
    page: page.reasons,
    reputation: reputation.listed
      ? ["Correspondência encontrada na base local de reputação"]
      : (reputation.available ? [] : ["Base de reputação indisponível; ausência de correspondência não implica segurança"]),
    integration: relationships.map((item) => item.reason)
  };
  const reasons = [
    ...groupedReasons.url.map((reason) => `[URL] ${reason}`),
    ...groupedReasons.page.map((reason) => `[Página] ${reason}`),
    ...groupedReasons.reputation.map((reason) => `[Reputação] ${reason}`),
    ...groupedReasons.integration.map((reason) => `[Integração] ${reason}`)
  ];
  const integratedScore = Math.max(url.score, page.score,
    relationships.some((item) => item.strength === "critical") ? 80 : 0,
    relationships.some((item) => item.strength === "strong") ? 60 : 0,
    reputation.listed ? 100 : 0);

  return {
    version: PHISHPECT_COMBINED_V4_VERSION,
    URL: url,
    PAGE: page,
    REPUTATION: reputation,
    INTEGRATION: {
      relationships,
      evidence_groups: [...new Set([
        ...url.evidence_groups.map((group) => `url.${group}`),
        ...page.evidence_groups.map((group) => `page.${group}`),
        ...(reputation.listed ? ["reputation.listed"] : [])
      ])],
      grouped_reasons: groupedReasons,
      decision_basis: decisionBasis
    },
    finalClassification,
    score: integratedScore,
    reasons,
    externalReputation: reputation
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    PHISHPECT_COMBINED_V4_VERSION,
    combineV4Evidence,
    normalizeV4UrlResult,
    normalizeV4PageResult,
    normalizeV4Reputation
  };
}
