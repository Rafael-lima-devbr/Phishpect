const V3_1_SUSPICIOUS_THRESHOLD = 24;

const V3_1_CONFIRMED_MALICIOUS_DOMAINS = new Set([
  "phishing-test.invalid",
  "malware-test.invalid"
]);

const V3_1_AUTHENTICATION_TERMS = new Set([
  "login", "verify", "verification", "account", "password", "senha",
  "secure", "signin", "bank", "banco", "pix", "auth", "oauth",
  "oauth2", "kyc", "credential", "credentials", "recover", "recovery"
]);

const V3_1_KNOWN_BRANDS = [
  { name: "roblox", officialDomains: ["roblox.com"] },
  { name: "amazon", officialDomains: ["amazon.com"] },
  { name: "netflix", officialDomains: ["netflix.com"] },
  { name: "instagram", officialDomains: ["instagram.com"] },
  { name: "microsoft", officialDomains: ["microsoft.com"] },
  { name: "outlook", officialDomains: ["outlook.com", "live.com"] },
  { name: "apple", officialDomains: ["apple.com"] },
  { name: "whatsapp", officialDomains: ["whatsapp.com"] },
  { name: "airbnb", officialDomains: ["airbnb.com"] },
  { name: "google", officialDomains: ["google.com"] },
  { name: "paypal", officialDomains: ["paypal.com"] },
  { name: "facebook", officialDomains: ["facebook.com"] },
  { name: "discord", officialDomains: ["discord.com", "discord.gg"] },
  { name: "ledger", officialDomains: ["ledger.com"] },
  { name: "metamask", officialDomains: ["metamask.io"] },
  { name: "docusign", officialDomains: ["docusign.com"] },
  { name: "yahoo", officialDomains: ["yahoo.com"] }
];

const V3_1_SHARED_HOSTING_DOMAINS = [
  "github.io", "vercel.app", "pages.dev", "blogspot.com",
  "weebly.com", "netlify.app", "replit.app", "gitbook.io",
  "godaddysites.com", "zapier.app", "workers.dev", "duckdns.org",
  "amplifyapp.com", "edgeone.dev"
];

const V3_1_BRAND_CONTEXT_TERMS = new Set([
  "login", "verify", "verification", "account", "secure", "signin",
  "notify", "notification", "support", "suporte", "soporte", "recovery"
]);

const V3_1_URL_SHORTENER_DOMAINS = new Set(["u.to", "surl.li", "1url.at"]);

const V3_1_CATEGORY_CAPS = {
  identity: 30,
  authentication: 12,
  structure: 15,
  transport: 6,
  path_query: 10,
  infrastructure: 10
};

function getDomainParser() {
  if (typeof globalThis !== "undefined" && globalThis.tldts?.parse) return globalThis.tldts;
  if (typeof require === "function") return require("tldts");
  throw new Error("Parser de domínio registrável indisponível");
}

/**
 * V3.1: score limitado por categoria e decisão condicionada à diversidade.
 * Sinais equivalentes na mesma categoria não contam como evidências independentes.
 */
function analyzeUrl(url) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return invalidUrlResult();
  }
  if (!["http:", "https:"].includes(parsedUrl.protocol)) return invalidUrlResult();

  const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
  const domainParts = getDomainParser().parse(hostname, { allowPrivateDomains: true });
  const registrableDomain = domainParts.domain || hostname;
  const subdomain = domainParts.subdomain || "";
  const hostnameTokens = tokenize(hostname);
  const registrableTokens = tokenize(registrableDomain);
  const subdomainTokens = tokenize(subdomain);
  const brandCandidateTokens = unique([
    ...subdomainTokens,
    ...tokenize(domainParts.domainWithoutSuffix || registrableDomain)
  ]);
  const pathnameText = decodeURIComponentSafe(parsedUrl.pathname).toLowerCase();
  const queryText = decodeURIComponentSafe(parsedUrl.search).toLowerCase();
  const pathnameTokens = tokenize(pathnameText);
  const pathnameTerms = findTerms(pathnameText);
  const queryTerms = findTerms(queryText);
  const hostnameTerms = unique(hostnameTokens.filter((token) => V3_1_AUTHENTICATION_TERMS.has(token)));
  const pathnameBrand = findExactBrand(pathnameTokens);
  const brandEvidence = findBrandEvidence(hostname, registrableDomain, brandCandidateTokens);
  const userInfoBrand = findExactBrand(tokenize(decodeURIComponentSafe(parsedUrl.username || "").toLowerCase()));
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.includes(":");
  const isIpAddress = isIpv4 || isIpv6 || domainParts.isIp === true;
  const usesPunycode = hostname.includes("xn--");
  const usesSharedHosting = V3_1_SHARED_HOSTING_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
  const usesShortener = V3_1_URL_SHORTENER_DOMAINS.has(hostname);
  const isConfirmedThreat = [...V3_1_CONFIRMED_MALICIOUS_DOMAINS].some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );

  const digitCount = (hostname.match(/\d/g) || []).length;
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const structuralHyphenCount = hostname.split(".")
    .map((label) => label.replace(/^xn--/, ""))
    .reduce((total, label) => total + (label.match(/-/g) || []).length, 0);
  const hostnameWithoutDots = hostname.replaceAll(".", "");
  const searchParams = [...parsedUrl.searchParams.keys()];
  const features = {
    protocol: parsedUrl.protocol.slice(0, -1),
    hostname,
    registrable_domain: registrableDomain,
    public_suffix: domainParts.publicSuffix || "",
    subdomains: subdomain ? subdomain.split(".") : [],
    pathname: parsedUrl.pathname,
    query_string: parsedUrl.search,
    url_length: url.length,
    hostname_length: hostname.length,
    pathname_length: parsedUrl.pathname.length,
    parameter_count: searchParams.length,
    subdomain_count: subdomain ? subdomain.split(".").length : 0,
    hyphen_count: hyphenCount,
    structural_hyphen_count: structuralHyphenCount,
    digit_count: digitCount,
    hostname_digit_ratio: hostnameWithoutDots.length ? digitCount / hostnameWithoutDots.length : 0,
    special_character_count: (
      `${hostname}${parsedUrl.pathname}${parsedUrl.search}`.match(/[^a-zA-Z0-9./?=&_-]/g) || []
    ).length,
    hostname_entropy: shannonEntropy(registrableTokens.join("")),
    hostname_authentication_terms: hostnameTerms,
    pathname_authentication_terms: pathnameTerms,
    query_authentication_terms: queryTerms,
    pathname_brand: pathnameBrand
  };

  const signals = {
    brand_mismatch: Boolean(brandEvidence),
    brand: brandEvidence?.brand || null,
    brand_match_type: brandEvidence?.matchType || null,
    brand_in_pathname: pathnameBrand,
    authentication_in_hostname: hostnameTerms.length > 0,
    authentication_in_pathname: pathnameTerms.length > 0,
    confirmed_threat: isConfirmedThreat,
    punycode: usesPunycode,
    uses_ip: isIpAddress,
    uses_shared_hosting: usesSharedHosting,
    uses_shortener: usesShortener,
    uses_userinfo: Boolean(parsedUrl.username || parsedUrl.password)
  };

  if (isConfirmedThreat) {
    return {
      score: 100,
      level: "blocked",
      reasons: ["Domínio presente na lista local de testes maliciosos"],
      contributions: [],
      category_scores: { identity: 100 },
      evidence_categories: ["identity"],
      diversity_bonus: 0,
      signals,
      features
    };
  }

  const reasons = [];
  const contributions = [];
  const addEvidence = (category, points, code, reason) => {
    reasons.push(reason);
    contributions.push({ category, code, points, reason });
  };

  if (parsedUrl.protocol === "http:") {
    addEvidence("transport", 6, "http", "URL utiliza HTTP; o sinal só ganha força com outra categoria");
  }
  if (url.length > 150) addEvidence("path_query", 5, "long_url", "URL possui mais de 150 caracteres");
  if (parsedUrl.pathname.length > 80) addEvidence("path_query", 4, "long_path", "Caminho da URL é muito longo");
  if (features.parameter_count >= 5) addEvidence("path_query", 4, "many_parameters", "URL possui cinco ou mais parâmetros");
  if (pathnameTerms.length > 0) {
    addEvidence("path_query", 4, "path_auth_terms", `Caminho contém termos de autenticação: ${pathnameTerms.join(", ")}`);
  }
  if (queryTerms.length > 0) {
    addEvidence("path_query", 3, "query_auth_terms", `Parâmetros contêm termos de autenticação: ${queryTerms.join(", ")}`);
  }
  if (pathnameBrand) {
    addEvidence("path_query", 8, "brand_in_path", `Marca ${pathnameBrand} aparece apenas no caminho da URL`);
  }

  if (hostname.length > 60) addEvidence("structure", 5, "long_hostname", "Hostname é excessivamente longo");
  if (!isIpAddress && features.subdomain_count >= 3) {
    addEvidence("structure", 5, "many_subdomains", "Hostname possui três ou mais níveis de subdomínio");
  }
  if (structuralHyphenCount >= 3) addEvidence("structure", 5, "many_hyphens", "Hostname contém três ou mais hífens fora do prefixo Punycode");
  if (digitCount >= 4 && features.hostname_digit_ratio >= 0.2) {
    addEvidence("structure", 5, "high_digit_ratio", "Hostname combina vários dígitos com alta proporção numérica");
  }
  if (features.hostname_entropy >= 3.8 && registrableTokens.join("").length >= 12) {
    addEvidence("structure", 5, "high_entropy", "Domínio registrável apresenta alta entropia lexical");
  }

  if (hostnameTerms.length > 0) {
    addEvidence("authentication", 8, "hostname_auth_terms", `Hostname contém termos de autenticação: ${hostnameTerms.join(", ")}`);
  }
  if (hostnameTerms.length >= 2) {
    addEvidence("authentication", 4, "multiple_hostname_auth_terms", "Múltiplos termos de autenticação aparecem no hostname");
  }

  if (isIpAddress) addEvidence("identity", 18, "direct_ip", "Destino utiliza endereço IP no lugar de domínio registrável");
  if (usesPunycode) addEvidence("identity", 16, "punycode", "Hostname utiliza Punycode");
  if (parsedUrl.username || parsedUrl.password) {
    addEvidence("identity", 20, "userinfo", "URL contém credenciais antes do hostname real");
  }
  if (userInfoBrand) {
    addEvidence("identity", 10, "brand_in_userinfo", `Marca ${userInfoBrand} aparece antes do hostname real`);
  }
  if (brandEvidence) {
    const position = subdomainTokens.includes(brandEvidence.token) ? "em subdomínio" : "no hostname";
    const description = brandEvidence.matchType === "typo"
      ? `possível imitação da marca ${brandEvidence.brand} (${brandEvidence.token})`
      : `marca ${brandEvidence.brand}`;
    addEvidence(
      "identity",
      brandEvidence.matchType === "typo" ? 18 : 24,
      brandEvidence.matchType === "typo" ? "brand_typo" : "brand_mismatch",
      `${description} aparece ${position}, mas o domínio registrável é ${registrableDomain}`
    );
  }

  if (usesSharedHosting) {
    addEvidence("infrastructure", 9, "shared_hosting", "URL usa hospedagem compartilhada; isoladamente isso não indica phishing");
  }
  if (usesShortener) {
    addEvidence("infrastructure", 10, "shortener", "URL utiliza um encurtador conhecido");
  }

  const categoryScores = Object.fromEntries(Object.keys(V3_1_CATEGORY_CAPS).map((category) => [category, 0]));
  for (const contribution of contributions) {
    categoryScores[contribution.category] += contribution.points;
  }
  for (const [category, cap] of Object.entries(V3_1_CATEGORY_CAPS)) {
    categoryScores[category] = Math.min(categoryScores[category], cap);
  }

  const evidenceCategories = Object.entries(categoryScores)
    .filter(([, points]) => points > 0)
    .map(([category]) => category);
  const categoryCount = evidenceCategories.length;
  const diversityBonus = categoryCount >= 4 ? 18 : categoryCount === 3 ? 14 : categoryCount === 2 ? 10 : 0;
  if (diversityBonus > 0) {
    reasons.push(`Diversidade de evidências: ${evidenceCategories.join(", ")}`);
  }

  const hasExactBrandMismatch = brandEvidence?.matchType === "exact";
  const hasBrandContextCompound = brandEvidence?.matchType === "compound";
  const hasBrandAuthentication = Boolean(brandEvidence && hostnameTerms.length > 0);
  const hasPunycodeBrand = Boolean(brandEvidence && usesPunycode);
  const hasUserInfoBrand = Boolean(userInfoBrand && (parsedUrl.username || parsedUrl.password));
  const hasContextCategory = evidenceCategories.some((category) =>
    ["identity", "authentication", "infrastructure"].includes(category)
  );
  const hasTransportStructureCombination = evidenceCategories.includes("transport") &&
    evidenceCategories.includes("structure") && categoryScores.structure >= 8;
  const hasPathBrandCombination = Boolean(pathnameBrand && categoryCount >= 2);
  const evidenceEligible = hasExactBrandMismatch || hasBrandContextCompound || hasBrandAuthentication || hasPunycodeBrand ||
    hasUserInfoBrand || (categoryCount >= 2 && hasContextCategory) ||
    hasTransportStructureCombination || hasPathBrandCombination || categoryCount >= 3;

  const score = Math.min(
    Object.values(categoryScores).reduce((total, points) => total + points, 0) + diversityBonus,
    100
  );

  return {
    score,
    level: score >= V3_1_SUSPICIOUS_THRESHOLD && evidenceEligible ? "suspicious" : "safe",
    reasons,
    contributions,
    category_scores: categoryScores,
    evidence_categories: evidenceCategories,
    diversity_bonus: diversityBonus,
    signals,
    features
  };
}

function invalidUrlResult() {
  return {
    score: 100,
    level: "blocked",
    reasons: ["URL inválida, não HTTP(S) ou impossível de interpretar"],
    contributions: [{ category: "identity", code: "invalid_url", points: 100, reason: "URL inválida" }],
    category_scores: { identity: 100 },
    evidence_categories: ["identity"],
    diversity_bonus: 0,
    signals: { brand_mismatch: false },
    features: null
  };
}

function findBrandEvidence(hostname, registrableDomain, tokens) {
  for (const brand of V3_1_KNOWN_BRANDS) {
    const official = brand.officialDomains.some(
      (officialDomain) => hostname === officialDomain || hostname.endsWith(`.${officialDomain}`)
    );
    if (official) continue;
    const exactToken = tokens.find((token) => token === brand.name);
    if (exactToken) return { brand: brand.name, token: exactToken, matchType: "exact", registrableDomain };
    const compoundToken = tokens.find((token) => isBrandContextCompound(token, brand.name));
    if (compoundToken) return { brand: brand.name, token: compoundToken, matchType: "compound", registrableDomain };
    const typoToken = tokens.find((token) => isConservativeBrandTypo(token, brand.name));
    if (typoToken) return { brand: brand.name, token: typoToken, matchType: "typo", registrableDomain };
  }
  return null;
}

function isBrandContextCompound(token, brand) {
  if (!token.includes(brand) || token === brand) return false;
  const remainder = token.startsWith(brand)
    ? token.slice(brand.length)
    : token.endsWith(brand)
      ? token.slice(0, -brand.length)
      : "";
  return V3_1_BRAND_CONTEXT_TERMS.has(remainder);
}

function findExactBrand(tokens) {
  return V3_1_KNOWN_BRANDS.find(({ name }) => tokens.includes(name))?.name || null;
}

function isConservativeBrandTypo(token, brand) {
  if (token.length < 4 || brand.length < 5 || Math.abs(token.length - brand.length) > 1) return false;
  if (V3_1_AUTHENTICATION_TERMS.has(token) || token === "www") return false;
  return limitedLevenshtein(token, brand, 1) === 1;
}

function limitedLevenshtein(left, right, limit) {
  if (Math.abs(left.length - right.length) > limit) return limit + 1;
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    const current = [leftIndex];
    let rowMinimum = current[0];
    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const substitutionCost = left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1;
      current[rightIndex] = Math.min(
        previous[rightIndex] + 1,
        current[rightIndex - 1] + 1,
        previous[rightIndex - 1] + substitutionCost
      );
      rowMinimum = Math.min(rowMinimum, current[rightIndex]);
    }
    if (rowMinimum > limit) return limit + 1;
    previous = current;
  }
  return previous[right.length];
}

function tokenize(value) {
  return value.split(/[^a-z0-9]+/).filter(Boolean);
}

function findTerms(value) {
  return unique(tokenize(value).filter((token) => V3_1_AUTHENTICATION_TERMS.has(token)));
}

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const character of value) counts.set(character, (counts.get(character) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function unique(values) {
  return [...new Set(values)];
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

if (typeof module !== "undefined") {
  module.exports = { analyzeUrl, limitedLevenshtein, V3_1_SUSPICIOUS_THRESHOLD };
}
