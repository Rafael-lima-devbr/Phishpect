const CONFIRMED_MALICIOUS_DOMAINS = new Set([
  "phishing-test.invalid",
  "malware-test.invalid"
]);

const SUSPICIOUS_TERMS = [
  "login", "verify", "account", "password", "senha",
  "secure", "signin", "bank", "banco", "pix"
];

const AUTHENTICATION_TERMS = [
  "login", "verify", "account", "password", "secure", "signin"
];

const KNOWN_BRANDS = {
  roblox: "roblox.com",
  amazon: "amazon.com",
  netflix: "netflix.com",
  instagram: "instagram.com",
  microsoft: "microsoft.com",
  outlook: "outlook.com",
  apple: "apple.com",
  whatsapp: "whatsapp.com",
  airbnb: "airbnb.com"
};

const SHARED_HOSTING_DOMAINS = [
  "github.io", "vercel.app", "pages.dev", "blogspot.com",
  "weebly.com", "netlify.app", "replit.app"
];

const URL_SHORTENER_DOMAINS = new Set(["u.to", "surl.li", "1url.at"]);

/**
 * Calcula o risco usando pesos e limite provisórios para o MVP.
 * Esses valores devem ser calibrados posteriormente com dados experimentais.
 */
function analyzeUrl(url) {
  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return {
      score: 100,
      level: "blocked",
      reasons: ["URL inválida ou impossível de interpretar"],
      signals: { brand_mismatch: false }
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const hostnameTokens = hostname.split(/[^a-z0-9]+/).filter(Boolean);
  const brandMismatch = Object.entries(KNOWN_BRANDS).some(([brand, officialDomain]) => {
    const brandAppears = hostnameTokens.includes(brand);
    const belongsToBrand = hostname === officialDomain || hostname.endsWith(`.${officialDomain}`);
    return brandAppears && !belongsToBrand;
  });
  const isConfirmedThreat = [...CONFIRMED_MALICIOUS_DOMAINS].some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );

  if (isConfirmedThreat) {
    return {
      score: 100,
      level: "blocked",
      reasons: ["Domínio presente na lista local de testes maliciosos"],
      signals: { brand_mismatch: brandMismatch }
    };
  }

  let score = 0;
  const reasons = [];
  const addRisk = (points, reason) => {
    score += points;
    reasons.push(reason);
  };

  if (parsedUrl.protocol === "http:") {
    addRisk(20, "URL utiliza HTTP em vez de HTTPS");
  }

  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.includes(":");
  if (isIpv4 || isIpv6) {
    addRisk(30, "Domínio utiliza um endereço IP diretamente");
  }

  if (hostname.includes("xn--")) {
    addRisk(25, "Domínio utiliza Punycode");
  }
  if (url.length > 150) {
    addRisk(20, "URL é excessivamente longa");
  }
  if (hostname.length > 60) {
    addRisk(15, "Domínio é excessivamente longo");
  }
  if (!isIpv4 && !isIpv6 && hostname.split(".").length > 4) {
    addRisk(15, "Domínio possui muitos níveis de subdomínio");
  }
  if (url.includes("@")) {
    addRisk(25, "URL contém o caractere @");
  }

  const searchableUrl = decodeURIComponentSafe(
    `${hostname}${parsedUrl.pathname}${parsedUrl.search}`
  ).toLowerCase();
  const foundTerms = SUSPICIOUS_TERMS.filter((term) => searchableUrl.includes(term));
  const foundAuthenticationTerms = AUTHENTICATION_TERMS.filter((term) => searchableUrl.includes(term));
  if (foundTerms.length > 0) {
    addRisk(20, `URL contém termos sensíveis: ${foundTerms.join(", ")}`);
  }

  if (brandMismatch) {
    addRisk(20, "Nome de marca conhecido aparece fora do domínio oficial");
  }

  const usesSharedHosting = SHARED_HOSTING_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
  if (usesSharedHosting && (brandMismatch || foundAuthenticationTerms.length > 0)) {
    addRisk(10, "Hospedagem compartilhada combinada com marca ou autenticação");
  }

  if (URL_SHORTENER_DOMAINS.has(hostname)) {
    addRisk(10, "URL utiliza um encurtador conhecido");
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    addRisk(5, "Hostname contém dois ou mais hífens");
  }

  const digitCount = (hostname.match(/\d/g) || []).length;
  if (digitCount >= 4) {
    addRisk(5, "Hostname contém quatro ou mais dígitos");
  }

  if (parsedUrl.pathname.length > 60) {
    addRisk(5, "Caminho da URL é muito longo");
  }

  score = Math.min(score, 100);
  return {
    score,
    level: score >= 20 ? "suspicious" : "safe",
    reasons,
    signals: { brand_mismatch: brandMismatch }
  };
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

if (typeof module !== "undefined") {
  module.exports = { analyzeUrl };
}
