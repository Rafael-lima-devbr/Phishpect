const PHISHPECT_V4_VERSION = "4.0";
const V4_URL_SUSPICIOUS_THRESHOLD = 24;

const V4_REDIRECT_PARAMETER_NAMES = new Set([
  "continue", "destination", "next", "redirect", "redirect_to", "redirect_uri",
  "return", "return_to", "returnurl", "target", "url"
]);

const V4_AUTH_PARAMETER_NAMES = new Set([
  "account", "auth", "credential", "email", "login", "password", "signin", "user", "username"
]);

function v4BaseAnalyzer() {
  if (typeof analyzeUrl === "function") return analyzeUrl;
  if (typeof require === "function") return require("./analysis.js").analyzeUrl;
  throw new Error("Analisador V3.1 de referência indisponível");
}

function v4Unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function v4Decode(value, rounds = 2) {
  let decoded = String(value || "");
  for (let index = 0; index < rounds; index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function v4NestedUrls(parsedUrl) {
  const nested = [];
  for (const [name, value] of parsedUrl.searchParams.entries()) {
    const decoded = v4Decode(value).trim();
    if (!/^https?:\/\//i.test(decoded)) continue;
    try {
      const parsed = new URL(decoded);
      nested.push({
        parameter: name.toLowerCase(),
        protocol: parsed.protocol,
        hostname: parsed.hostname.toLowerCase(),
        href: parsed.href.slice(0, 2048)
      });
    } catch {
      // Texto parecido com URL, mas sintaticamente inválido, não vira evidência.
    }
  }
  return nested.slice(0, 8);
}

function v4RawAuthority(value) {
  const match = String(value || "").match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i);
  return match ? match[1] : "";
}

function v4DefaultPort(protocol, port) {
  return !port || (protocol === "http:" && port === "80") || (protocol === "https:" && port === "443");
}

function v4Contribution(category, points, code, reason, strength = "weak") {
  return { category, points, code, reason, strength };
}

function analyzeUrlV4(value) {
  const base = v4BaseAnalyzer()(value);
  if (!base?.features) {
    return {
      ...base,
      version: PHISHPECT_V4_VERSION,
      module: "url",
      evidence_groups: [],
      relationships: [],
      decision_basis: "invalid-or-unsupported-url"
    };
  }

  const parsed = new URL(value);
  const contributions = (base.contributions || []).map((item) => ({
    ...item,
    strength: ["brand_mismatch", "userinfo", "brand_in_userinfo", "direct_ip"].includes(item.code)
      ? "strong"
      : (["brand_typo", "punycode", "hostname_auth_terms", "shortener"].includes(item.code) ? "moderate" : "weak")
  }));
  const reasons = [...(base.reasons || []).filter((reason) => !String(reason).startsWith("Diversidade de evidências:"))];
  const nestedUrls = v4NestedUrls(parsed);
  const redirectParameters = v4Unique([...parsed.searchParams.keys()]
    .map((name) => name.toLowerCase())
    .filter((name) => V4_REDIRECT_PARAMETER_NAMES.has(name)));
  const authParameters = v4Unique([...parsed.searchParams.keys()]
    .map((name) => name.toLowerCase())
    .filter((name) => V4_AUTH_PARAMETER_NAMES.has(name)));
  const rawAuthority = v4RawAuthority(value);
  const atCount = (rawAuthority.match(/@/g) || []).length;
  const unusualPort = !v4DefaultPort(parsed.protocol, parsed.port);

  const add = (entry) => {
    contributions.push(entry);
    reasons.push(entry.reason);
  };

  if (nestedUrls.length) {
    add(v4Contribution("path_query", 7, "nested_url", "Parâmetro contém outra URL completa", "moderate"));
  }
  if (nestedUrls.length && redirectParameters.length) {
    add(v4Contribution("path_query", 3, "redirect_target", "URL aninhada aparece em parâmetro de redirecionamento", "moderate"));
  }
  if (unusualPort) {
    add(v4Contribution("infrastructure", 5, "unusual_port", `Destino usa a porta não padrão ${parsed.port}`, "weak"));
  }
  if (atCount > 1) {
    add(v4Contribution("identity", 12, "multiple_at", "Autoridade da URL contém múltiplos sinais @", "strong"));
  }
  if (authParameters.length >= 2) {
    add(v4Contribution("authentication", 4, "multiple_auth_parameters", "Query combina múltiplos parâmetros de autenticação", "weak"));
  }

  const caps = {
    identity: 30,
    authentication: 12,
    structure: 15,
    transport: 6,
    path_query: 14,
    infrastructure: 12
  };
  const categoryScores = Object.fromEntries(Object.keys(caps).map((category) => [category, 0]));
  for (const item of contributions) {
    if (Object.hasOwn(categoryScores, item.category)) categoryScores[item.category] += Number(item.points) || 0;
  }
  for (const [category, cap] of Object.entries(caps)) categoryScores[category] = Math.min(categoryScores[category], cap);

  const evidenceGroups = Object.entries(categoryScores).filter(([, score]) => score > 0).map(([category]) => category);
  const codes = new Set(contributions.map((item) => item.code));
  const relationships = [];
  const relationship = (code, groups, reason, strength = "strong") => {
    relationships.push({ code, groups, reason, strength });
  };

  if ((codes.has("brand_mismatch") || codes.has("brand_typo")) &&
      (categoryScores.authentication > 0 || codes.has("nested_url") || parsed.protocol === "http:")) {
    relationship("identity_auth_context", ["identity", "authentication"], "Identidade incompatível aparece junto de contexto de autenticação ou transporte inseguro");
  }
  if (codes.has("direct_ip") && (categoryScores.authentication > 0 || authParameters.length > 0 || base.signals?.authentication_in_pathname === true)) {
    relationship("ip_auth_context", ["identity", "authentication"], "Endereço IP é combinado com contexto de autenticação");
  }
  if (codes.has("userinfo") || codes.has("multiple_at")) {
    relationship("authority_spoofing", ["identity"], "A autoridade da URL pode ocultar o hostname real");
  }
  if (codes.has("punycode") && (codes.has("brand_mismatch") || codes.has("brand_typo"))) {
    relationship("punycode_brand", ["identity"], "Punycode aparece junto de possível imitação de marca");
  }
  if (codes.has("nested_url") && (codes.has("brand_in_path") || codes.has("brand_mismatch") || categoryScores.authentication > 0)) {
    relationship("nested_identity", ["path_query", "identity"], "URL aninhada aparece junto de identidade ou autenticação");
  }
  if (codes.has("shared_hosting") && (codes.has("brand_mismatch") || codes.has("brand_typo") || categoryScores.authentication > 0)) {
    relationship("shared_hosting_context", ["infrastructure", "identity"], "Hospedagem compartilhada aparece com identidade ou autenticação incompatível", "moderate");
  }

  const structuralSignals = ["long_hostname", "many_subdomains", "many_hyphens", "high_digit_ratio", "high_entropy"]
    .filter((code) => codes.has(code));
  const weakDiversityEligible = evidenceGroups.length >= 3 && structuralSignals.length >= 1 &&
    (categoryScores.transport > 0 || categoryScores.path_query > 0) && categoryScores.infrastructure > 0;
  const relationshipEligible = relationships.some((item) => item.strength === "strong") ||
    relationships.filter((item) => item.strength === "moderate").length >= 2;
  const score = Math.min(100, Object.values(categoryScores).reduce((sum, number) => sum + number, 0));
  const confirmedThreat = base.signals?.confirmed_threat === true;
  const level = confirmedThreat ? "blocked" :
    (score >= V4_URL_SUSPICIOUS_THRESHOLD && (relationshipEligible || weakDiversityEligible) ? "suspicious" : "safe");

  if (weakDiversityEligible && level === "suspicious") {
    reasons.push(`Diversidade independente de evidências: ${evidenceGroups.join(", ")}`);
  }
  for (const item of relationships) reasons.push(item.reason);

  return {
    ...base,
    version: PHISHPECT_V4_VERSION,
    module: "url",
    score,
    level,
    reasons: v4Unique(reasons),
    contributions,
    category_scores: categoryScores,
    evidence_categories: evidenceGroups,
    evidence_groups: evidenceGroups,
    relationships,
    decision_basis: confirmedThreat ? "confirmed-local-threat" :
      (relationshipEligible ? "contextual-relationship" : (weakDiversityEligible ? "independent-diversity" : "insufficient-context")),
    signals: {
      ...(base.signals || {}),
      nested_url: nestedUrls.length > 0,
      redirect_parameter: redirectParameters.length > 0,
      unusual_port: unusualPort,
      multiple_at: atCount > 1,
      authentication_parameters: authParameters.length > 0
    },
    features: {
      ...base.features,
      port: parsed.port || null,
      nested_urls: nestedUrls,
      redirect_parameters: redirectParameters,
      authentication_parameters: authParameters,
      authority_at_count: atCount
    }
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    PHISHPECT_V4_VERSION,
    V4_URL_SUSPICIOUS_THRESHOLD,
    analyzeUrlV4,
    v4NestedUrls
  };
}
