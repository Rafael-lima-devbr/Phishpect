const PHISHPECT_V41_VERSION = "4.1";
const V41_CONTEXTUAL_THRESHOLD = 24;

function v41UrlBaseAnalyzer() {
  if (typeof analyzeUrlV4 === "function") return analyzeUrlV4;
  if (typeof require === "function") return require("./analysis-v4.js").analyzeUrlV4;
  throw new Error("Módulo de URL da V4 indisponível");
}

function v41Unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function analyzeUrlV41(value) {
  const base = v41UrlBaseAnalyzer()(value);
  if (!base?.features) return { ...base, version: PHISHPECT_V41_VERSION };

  const categoryScores = { ...(base.category_scores || {}) };
  const signals = { ...(base.signals || {}) };
  const contributions = Array.isArray(base.contributions) ? base.contributions : [];
  const contributionCodes = new Set(contributions.map((item) => item.code));
  const relationships = Array.isArray(base.relationships) ? [...base.relationships] : [];
  const reasons = [...(base.reasons || [])];
  const http = base.features.protocol === "http";
  const sharedHosting = signals.uses_shared_hosting === true;
  const authHostname = signals.authentication_in_hostname === true;
  const authPath = signals.authentication_in_pathname === true;
  const moderateStructure = Number(categoryScores.structure) >= 5;
  const hostingLexicalAnomaly = contributionCodes.has("high_entropy") || contributionCodes.has("many_hyphens");

  const add = (code, groups, reason, strength = "moderate") => {
    if (relationships.some((item) => item.code === code)) return;
    relationships.push({ code, groups, reason, strength });
    reasons.push(reason);
  };

  if (http && sharedHosting) {
    add("insecure_shared_hosting", ["transport", "infrastructure"],
      "Transporte HTTP coincide com hospedagem compartilhada");
  }
  if (http && moderateStructure) {
    add("insecure_moderate_structure", ["transport", "structure"],
      "Transporte HTTP coincide com estrutura anormal do hostname");
  }
  if (sharedHosting && hostingLexicalAnomaly) {
    add("lexically_anomalous_shared_hosting", ["infrastructure", "structure"],
      "Hospedagem compartilhada coincide com anomalia lexical do hostname");
  }
  if (authHostname && (http || sharedHosting || moderateStructure)) {
    add("hostname_authentication_context", ["authentication", http ? "transport" : (sharedHosting ? "infrastructure" : "structure")],
      "Autenticação no hostname é corroborada por transporte ou infraestrutura", "strong");
  }
  if (http && authPath) {
    add("insecure_path_authentication", ["transport", "path_query"],
      "Caminho de autenticação é servido por HTTP");
  }

  const v41Codes = new Set(relationships.map((item) => item.code));
  const contextualEligible =
    (v41Codes.has("insecure_shared_hosting") && base.score >= V41_CONTEXTUAL_THRESHOLD) ||
    (v41Codes.has("insecure_moderate_structure") && base.score >= 20) ||
    (v41Codes.has("lexically_anomalous_shared_hosting") && base.score >= V41_CONTEXTUAL_THRESHOLD) ||
    (v41Codes.has("hostname_authentication_context") && base.score >= V41_CONTEXTUAL_THRESHOLD) ||
    (v41Codes.has("insecure_path_authentication") && base.score >= 20);
  const confirmedThreat = signals.confirmed_threat === true;
  const level = confirmedThreat ? "blocked" :
    (base.level === "suspicious" || contextualEligible ? "suspicious" : "safe");

  return {
    ...base,
    version: PHISHPECT_V41_VERSION,
    level,
    reasons: v41Unique(reasons),
    relationships,
    decision_basis: confirmedThreat ? "confirmed-local-threat" :
      (base.level === "suspicious" ? base.decision_basis : (contextualEligible ? "v4.1-contextual-relationship" : "insufficient-context")),
    signals: {
      ...signals,
      v41_http_shared_hosting: http && sharedHosting,
      v41_http_moderate_structure: http && moderateStructure,
      v41_lexically_anomalous_shared_hosting: sharedHosting && hostingLexicalAnomaly,
      v41_contextual_eligible: contextualEligible
    },
    features: {
      ...base.features,
      v41_contextual_threshold: V41_CONTEXTUAL_THRESHOLD,
      v41_contribution_codes: [...contributionCodes]
    }
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { PHISHPECT_V41_VERSION, V41_CONTEXTUAL_THRESHOLD, analyzeUrlV41 };
}
