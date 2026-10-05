const V3_SUSPICIOUS_THRESHOLD = 30;

const V3_CONFIRMED_MALICIOUS_DOMAINS = new Set([
  "phishing-test.invalid",
  "malware-test.invalid"
]);

const V3_AUTHENTICATION_TERMS = new Set([
  "login", "verify", "verification", "account", "password", "senha",
  "secure", "signin", "bank", "banco", "pix"
]);

const V3_KNOWN_BRANDS = [
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
  { name: "paypal", officialDomains: ["paypal.com"] }
];

const V3_SHARED_HOSTING_DOMAINS = [
  "github.io", "vercel.app", "pages.dev", "blogspot.com",
  "weebly.com", "netlify.app", "replit.app"
];

const V3_URL_SHORTENER_DOMAINS = new Set(["u.to", "surl.li", "1url.at"]);

function getDomainParser() {
  if (typeof globalThis !== "undefined" && globalThis.tldts?.parse) {
    return globalThis.tldts;
  }
  if (typeof require === "function") {
    return require("tldts");
  }
  throw new Error("Parser de domínio registrável indisponível");
}

/**
 * V3: análise lexical explicável baseada principalmente na identidade do hostname.
 * Sinais fracos contribuem para o score, mas não atingem o threshold isoladamente.
 */
function analyzeUrl(url) {
  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return invalidUrlResult();
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return invalidUrlResult();
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
  const domainParts = getDomainParser().parse(hostname, { allowPrivateDomains: true });
  const registrableDomain = domainParts.domain || hostname;
  const subdomain = domainParts.subdomain || "";
  const hostnameTokens = tokenizeHostname(hostname);
  const registrableTokens = tokenizeHostname(registrableDomain);
  const subdomainTokens = tokenizeHostname(subdomain);
  const brandCandidateTokens = unique([
    ...subdomainTokens,
    ...tokenizeHostname(domainParts.domainWithoutSuffix || registrableDomain)
  ]);
  const pathnameText = decodeURIComponentSafe(parsedUrl.pathname).toLowerCase();
  const queryText = decodeURIComponentSafe(parsedUrl.search).toLowerCase();
  const pathnameTerms = findTerms(pathnameText);
  const queryTerms = findTerms(queryText);
  const hostnameTerms = hostnameTokens.filter((token) => V3_AUTHENTICATION_TERMS.has(token));
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.includes(":");
  const isIpAddress = isIpv4 || isIpv6 || domainParts.isIp === true;
  const brandEvidence = findBrandEvidence(hostname, registrableDomain, brandCandidateTokens);
  const userInfoBrand = findBrandInUserInfo(parsedUrl.username);
  const isConfirmedThreat = [...V3_CONFIRMED_MALICIOUS_DOMAINS].some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
  const usesSharedHosting = V3_SHARED_HOSTING_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );

  const searchParams = [...parsedUrl.searchParams.keys()];
  const hostnameWithoutDots = hostname.replaceAll(".", "");
  const digitCount = (hostname.match(/\d/g) || []).length;
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const specialCharacterCount = (
    `${hostname}${parsedUrl.pathname}${parsedUrl.search}`.match(/[^a-zA-Z0-9./?=&_-]/g) || []
  ).length;
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
    digit_count: digitCount,
    hostname_digit_ratio: hostnameWithoutDots.length
      ? digitCount / hostnameWithoutDots.length
      : 0,
    special_character_count: specialCharacterCount,
    hostname_entropy: shannonEntropy(registrableTokens.join("")),
    hostname_authentication_terms: unique(hostnameTerms),
    pathname_authentication_terms: pathnameTerms,
    query_authentication_terms: queryTerms
  };

  if (isConfirmedThreat) {
    return {
      score: 100,
      level: "blocked",
      reasons: ["Domínio presente na lista local de testes maliciosos"],
      signals: buildSignals(brandEvidence, hostnameTerms, pathnameTerms, true),
      features
    };
  }

  let score = 0;
  const reasons = [];
  const contributions = [];
  const addRisk = (points, code, reason) => {
    score += points;
    reasons.push(reason);
    contributions.push({ code, points, reason });
  };

  // Sinais fracos: informativos, mas deliberadamente abaixo do threshold quando isolados.
  if (parsedUrl.protocol === "http:") {
    addRisk(4, "http", "URL utiliza HTTP; isoladamente isso não indica phishing");
  }
  if (url.length > 150) {
    addRisk(5, "long_url", "URL possui mais de 150 caracteres");
  }
  if (parsedUrl.pathname.length > 80) {
    addRisk(4, "long_path", "Caminho da URL é muito longo");
  }
  if (features.parameter_count >= 5) {
    addRisk(4, "many_parameters", "URL possui cinco ou mais parâmetros");
  }
  if (hostname.length > 60) {
    addRisk(5, "long_hostname", "Hostname é excessivamente longo");
  }
  if (!isIpAddress && features.subdomain_count >= 3) {
    addRisk(5, "many_subdomains", "Hostname possui três ou mais níveis de subdomínio");
  }
  if (hyphenCount >= 3) {
    addRisk(4, "many_hyphens", "Hostname contém três ou mais hífens");
  }
  if (digitCount >= 4 && features.hostname_digit_ratio >= 0.2) {
    addRisk(5, "high_digit_ratio", "Hostname combina vários dígitos com alta proporção numérica");
  }
  if (features.hostname_entropy >= 3.8 && registrableTokens.join("").length >= 12) {
    addRisk(5, "high_entropy", "Domínio registrável apresenta alta entropia lexical");
  }
  if (pathnameTerms.length > 0) {
    addRisk(4, "path_auth_terms", `Caminho contém termos de autenticação: ${pathnameTerms.join(", ")}`);
  }
  if (queryTerms.length > 0) {
    addRisk(3, "query_auth_terms", `Parâmetros contêm termos de autenticação: ${queryTerms.join(", ")}`);
  }
  if (hostnameTerms.length > 0) {
    addRisk(8, "hostname_auth_terms", `Hostname contém termos de autenticação: ${unique(hostnameTerms).join(", ")}`);
  }

  // Sinais moderados e fortes ligados à identidade real do destino.
  if (isIpAddress) {
    addRisk(18, "direct_ip", "Destino utiliza endereço IP no lugar de um domínio registrável");
  }
  if (hostname.includes("xn--")) {
    addRisk(16, "punycode", "Hostname utiliza Punycode");
  }
  if (parsedUrl.username || parsedUrl.password) {
    addRisk(20, "userinfo", "URL contém credenciais antes do hostname real");
  }
  if (userInfoBrand) {
    addRisk(20, "brand_in_userinfo", `Marca ${userInfoBrand} aparece antes do hostname real`);
  }
  if (V3_URL_SHORTENER_DOMAINS.has(hostname)) {
    addRisk(10, "shortener", "URL utiliza um encurtador conhecido");
  }
  if (brandEvidence) {
    const position = subdomainTokens.includes(brandEvidence.token)
      ? "em subdomínio"
      : "no hostname";
    const matchDescription = brandEvidence.matchType === "typo"
      ? `possível imitação da marca ${brandEvidence.brand} (${brandEvidence.token})`
      : `marca ${brandEvidence.brand}`;
    addRisk(
      brandEvidence.matchType === "typo" ? 22 : 30,
      "brand_mismatch",
      `${matchDescription} aparece ${position}, mas o domínio registrável é ${registrableDomain}`
    );
  }

  const weakStructuralCodes = new Set([
    "long_url", "long_path", "many_parameters", "long_hostname",
    "many_subdomains", "many_hyphens", "high_digit_ratio", "high_entropy"
  ]);
  const structuralSignalCount = contributions.filter(({ code }) => weakStructuralCodes.has(code)).length;
  const hostnameStructuralCodes = new Set([
    "long_hostname", "many_subdomains", "many_hyphens", "high_digit_ratio", "high_entropy"
  ]);
  const hostnameStructuralCount = contributions.filter(({ code }) => hostnameStructuralCodes.has(code)).length;
  if (structuralSignalCount >= 3) {
    addRisk(6, "structural_cluster", "Três ou mais anomalias estruturais aparecem em conjunto");
  }
  if (parsedUrl.protocol === "http:" && structuralSignalCount >= 3) {
    addRisk(8, "http_structural_combination", "HTTP aparece combinado com várias anomalias estruturais");
  }
  if (hostnameStructuralCount >= 3) {
    addRisk(17, "hostname_structural_cluster", "Três ou mais anomalias se concentram no hostname");
  } else if (parsedUrl.protocol === "http:" && hostnameStructuralCount >= 2) {
    addRisk(17, "http_hostname_structure", "HTTP aparece combinado com múltiplas anomalias no hostname");
  }

  const contributionCodes = new Set(contributions.map(({ code }) => code));
  const hasRandomizedHostnamePattern = contributionCodes.has("high_entropy") && (
    contributionCodes.has("many_hyphens") || contributionCodes.has("high_digit_ratio")
  );
  if (hasRandomizedHostnamePattern && usesSharedHosting) {
    addRisk(21, "shared_hosting_randomized_hostname", "Hospedagem compartilhada combina alta entropia com hostname segmentado ou numérico");
  } else if (hasRandomizedHostnamePattern && parsedUrl.protocol === "http:") {
    addRisk(17, "http_randomized_hostname", "HTTP combina alta entropia com hostname segmentado ou numérico");
  }

  if (unique(hostnameTerms).length >= 2) {
    addRisk(8, "multiple_hostname_auth_terms", "Múltiplos termos de autenticação aparecem no hostname");
  }

  if (brandEvidence && hostnameTerms.length > 0) {
    addRisk(15, "brand_auth_combination", "Imitação de marca e autenticação aparecem juntas no hostname");
  }
  if (brandEvidence && hostname.includes("xn--")) {
    addRisk(15, "punycode_brand_combination", "Punycode aparece combinado com possível imitação de marca");
  }
  if (userInfoBrand && (parsedUrl.username || parsedUrl.password)) {
    addRisk(10, "userinfo_brand_combination", "Marca é usada como credencial para ocultar o hostname real");
  }
  if (isIpAddress && (hostnameTerms.length > 0 || pathnameTerms.length > 0)) {
    addRisk(10, "ip_auth_combination", "Endereço IP aparece combinado com contexto de autenticação");
  }

  if (usesSharedHosting && (brandEvidence || hostnameTerms.length > 0)) {
    addRisk(6, "shared_hosting_context", "Hospedagem compartilhada aparece combinada com marca ou autenticação no hostname");
  }
  if (usesSharedHosting && unique(hostnameTerms).length >= 2) {
    addRisk(12, "shared_hosting_auth_combination", "Hospedagem compartilhada combina múltiplos termos de autenticação no hostname");
  }

  score = Math.min(score, 100);
  return {
    score,
    level: score >= V3_SUSPICIOUS_THRESHOLD ? "suspicious" : "safe",
    reasons,
    contributions,
    signals: buildSignals(brandEvidence, hostnameTerms, pathnameTerms, false, {
      punycode: hostname.includes("xn--"),
      uses_ip: isIpAddress,
      uses_shared_hosting: usesSharedHosting
    }),
    features
  };
}

function invalidUrlResult() {
  return {
    score: 100,
    level: "blocked",
    reasons: ["URL inválida, não HTTP(S) ou impossível de interpretar"],
    contributions: [{
      code: "invalid_url",
      points: 100,
      reason: "URL inválida, não HTTP(S) ou impossível de interpretar"
    }],
    signals: { brand_mismatch: false },
    features: null
  };
}

function buildSignals(brandEvidence, hostnameTerms, pathnameTerms, confirmedThreat, extra = {}) {
  return {
    brand_mismatch: Boolean(brandEvidence),
    brand: brandEvidence?.brand || null,
    brand_match_type: brandEvidence?.matchType || null,
    authentication_in_hostname: hostnameTerms.length > 0,
    authentication_in_pathname: pathnameTerms.length > 0,
    confirmed_threat: confirmedThreat,
    ...extra
  };
}

function findBrandEvidence(hostname, registrableDomain, hostnameTokens) {
  for (const brand of V3_KNOWN_BRANDS) {
    const belongsToBrand = brand.officialDomains.some(
      (officialDomain) => hostname === officialDomain || hostname.endsWith(`.${officialDomain}`)
    );
    if (belongsToBrand) continue;

    const exactToken = hostnameTokens.find((token) => token === brand.name);
    if (exactToken) {
      return { brand: brand.name, token: exactToken, matchType: "exact", registrableDomain };
    }

    const typoToken = hostnameTokens.find((token) => isConservativeBrandTypo(token, brand.name));
    if (typoToken) {
      return { brand: brand.name, token: typoToken, matchType: "typo", registrableDomain };
    }
  }
  return null;
}

function findBrandInUserInfo(username) {
  const tokens = tokenizeHostname(decodeURIComponentSafe(username || "").toLowerCase());
  return V3_KNOWN_BRANDS.find(({ name }) => tokens.includes(name))?.name || null;
}

function isConservativeBrandTypo(token, brand) {
  if (token.length < 4 || brand.length < 5 || Math.abs(token.length - brand.length) > 1) return false;
  if (V3_AUTHENTICATION_TERMS.has(token) || token === "www") return false;
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

function tokenizeHostname(value) {
  return value.split(/[^a-z0-9]+/).filter(Boolean);
}

function findTerms(value) {
  const tokens = value.split(/[^a-z0-9]+/).filter(Boolean);
  return unique(tokens.filter((token) => V3_AUTHENTICATION_TERMS.has(token)));
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
  module.exports = {
    analyzeUrl,
    limitedLevenshtein,
    V3_SUSPICIOUS_THRESHOLD
  };
}
