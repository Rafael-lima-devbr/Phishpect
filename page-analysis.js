const PAGE_ANALYSIS_VERSION = "1.0";
const PAGE_SUSPICIOUS_THRESHOLD = 18;

const PAGE_CATEGORY_CAPS = {
  credentials: 10,
  sensitive_data: 12,
  form_destination: 14,
  identity: 12,
  page_structure: 6
};

const PAGE_KNOWN_BRANDS = [
  { name: "roblox", officialDomains: ["roblox.com"] },
  { name: "amazon", officialDomains: ["amazon.com"] },
  { name: "netflix", officialDomains: ["netflix.com"] },
  { name: "instagram", officialDomains: ["instagram.com"] },
  { name: "microsoft", officialDomains: ["microsoft.com", "live.com", "outlook.com"] },
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

const PAGE_FIELD_TERMS = {
  username: ["user", "username", "usuario", "login", "signin", "account"],
  email: ["email", "e-mail"],
  card: ["card", "cardnumber", "creditcard", "cartao", "cvv", "cvc", "expiry", "expiration"],
  phone: ["phone", "telefone", "telephone", "celular", "mobile"],
  document: ["cpf", "cnpj", "document", "documento", "taxid"],
  banking: ["bank", "banco", "pix", "iban", "routing", "accountnumber", "agencia"],
  address: ["address", "endereco", "street", "postal", "postcode", "cep"]
};

function getPageDomainParser() {
  if (typeof globalThis !== "undefined" && globalThis.tldts?.parse) return globalThis.tldts;
  if (typeof require === "function") return require("tldts");
  throw new Error("Parser de domínio registrável indisponível");
}

function truncateText(value, maximumLength = 240) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, maximumLength);
}

function normalizeAttribute(element, attribute) {
  return truncateText(element?.getAttribute?.(attribute), 120).toLowerCase();
}

function collectFieldMetadata(field) {
  const tag = String(field?.tagName || "").toLowerCase();
  return {
    tag,
    type: tag === "input" ? (normalizeAttribute(field, "type") || "text") : tag,
    name: normalizeAttribute(field, "name"),
    id: normalizeAttribute(field, "id"),
    autocomplete: normalizeAttribute(field, "autocomplete")
  };
}

function collectPageSnapshot(documentObject, pageUrl) {
  if (!documentObject?.querySelectorAll) throw new Error("Documento indisponível para análise");

  const forms = [...documentObject.querySelectorAll("form")].slice(0, 30).map((form) => ({
    method: (normalizeAttribute(form, "method") || "get").toUpperCase(),
    action: truncateText(form.getAttribute?.("action"), 2048),
    fields: [...form.querySelectorAll("input, textarea, select")]
      .slice(0, 80)
      .map(collectFieldMetadata)
  }));

  return {
    page_url: String(pageUrl || ""),
    title: truncateText(documentObject.title),
    headings: [...documentObject.querySelectorAll("h1, h2")]
      .slice(0, 12)
      .map((heading) => truncateText(heading.textContent))
      .filter(Boolean),
    image_alts: [...documentObject.querySelectorAll("img[alt]")]
      .slice(0, 20)
      .map((image) => truncateText(image.getAttribute("alt")))
      .filter(Boolean),
    forms
  };
}

function parsePageLocation(url) {
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    const domainParts = getPageDomainParser().parse(parsed.hostname, { allowPrivateDomains: true });
    return {
      url: parsed.href,
      protocol: parsed.protocol,
      hostname: parsed.hostname.toLowerCase(),
      registrable_domain: domainParts.domain || parsed.hostname.toLowerCase()
    };
  } catch {
    return null;
  }
}

function parseFormDestination(rawAction, pageLocation) {
  const action = String(rawAction || "").trim();
  const action_kind = !action
    ? "missing"
    : (/^[a-z][a-z\d+.-]*:/i.test(action) || action.startsWith("//") ? "absolute" : "relative");

  let parsed;
  try {
    parsed = new URL(action || pageLocation.url, pageLocation.url);
  } catch {
    return { action_kind, valid: false, external: false, downgrade: false };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { action_kind, valid: false, protocol: parsed.protocol, external: false, downgrade: false };
  }

  const domainParts = getPageDomainParser().parse(parsed.hostname, { allowPrivateDomains: true });
  const registrableDomain = domainParts.domain || parsed.hostname.toLowerCase();
  return {
    action_kind,
    valid: true,
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    registrable_domain: registrableDomain,
    external: registrableDomain !== pageLocation.registrable_domain,
    downgrade: pageLocation.protocol === "https:" && parsed.protocol === "http:"
  };
}

function attributeText(field) {
  return `${field.name || ""} ${field.id || ""} ${field.autocomplete || ""}`.toLowerCase();
}

function includesTerm(text, terms) {
  return terms.some((term) => text.includes(term));
}

function classifyField(field) {
  const text = attributeText(field);
  const autocomplete = String(field.autocomplete || "").toLowerCase();
  const type = String(field.type || "").toLowerCase();
  const kinds = new Set();

  if (type === "password" || autocomplete.includes("password")) kinds.add("password");
  if (autocomplete === "username" || includesTerm(text, PAGE_FIELD_TERMS.username)) kinds.add("username");
  if (type === "email" || autocomplete === "email" || includesTerm(text, PAGE_FIELD_TERMS.email)) kinds.add("email");
  if (autocomplete.startsWith("cc-") || includesTerm(text, PAGE_FIELD_TERMS.card)) kinds.add("card");
  if (type === "tel" || autocomplete.startsWith("tel") || includesTerm(text, PAGE_FIELD_TERMS.phone)) kinds.add("phone");
  if (includesTerm(text, PAGE_FIELD_TERMS.document)) kinds.add("document");
  if (includesTerm(text, PAGE_FIELD_TERMS.banking)) kinds.add("banking");
  if (["street-address", "postal-code"].includes(autocomplete) || autocomplete.startsWith("address-line") || includesTerm(text, PAGE_FIELD_TERMS.address)) {
    kinds.add("address");
  }
  return [...kinds];
}

function findPageBrand(snapshot) {
  const text = [snapshot.title, ...(snapshot.headings || []), ...(snapshot.image_alts || [])]
    .join(" ")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, " ");
  return PAGE_KNOWN_BRANDS.find((brand) => new RegExp(`(^|[^a-z0-9])${brand.name}([^a-z0-9]|$)`, "i").test(text)) || null;
}

function isOfficialBrandDomain(brand, registrableDomain) {
  return brand.officialDomains.some(
    (domain) => registrableDomain === domain || registrableDomain.endsWith(`.${domain}`)
  );
}

function analyzePage(snapshot) {
  const pageLocation = parsePageLocation(snapshot?.page_url);
  if (!pageLocation) return invalidPageResult();

  const forms = Array.isArray(snapshot.forms) ? snapshot.forms.slice(0, 30) : [];
  const formFeatures = forms.map((form) => {
    const fieldKinds = (Array.isArray(form.fields) ? form.fields : [])
      .slice(0, 80)
      .flatMap(classifyField);
    const kindCounts = Object.fromEntries(
      [...new Set(fieldKinds)].map((kind) => [kind, fieldKinds.filter((candidate) => candidate === kind).length])
    );
    const destination = parseFormDestination(form.action, pageLocation);
    const hasPassword = Boolean(kindCounts.password);
    const hasIdentifier = Boolean(kindCounts.username || kindCounts.email);
    const sensitiveKinds = ["card", "phone", "document", "banking", "address"].filter((kind) => kindCounts[kind]);
    return {
      method: String(form.method || "GET").toUpperCase() === "POST" ? "POST" : "GET",
      field_count: Array.isArray(form.fields) ? form.fields.length : 0,
      field_kind_counts: kindCounts,
      has_password: hasPassword,
      has_identifier: hasIdentifier,
      credential_bundle: hasPassword && hasIdentifier,
      sensitive_kinds: sensitiveKinds,
      destination
    };
  });

  const counts = {
    forms: formFeatures.length,
    get_forms: formFeatures.filter((form) => form.method === "GET").length,
    post_forms: formFeatures.filter((form) => form.method === "POST").length,
    password_fields: formFeatures.reduce((total, form) => total + (form.field_kind_counts.password || 0), 0),
    identifier_fields: formFeatures.reduce((total, form) => total + (form.field_kind_counts.username || 0) + (form.field_kind_counts.email || 0), 0),
    external_forms: formFeatures.filter((form) => form.destination.external).length,
    downgrade_forms: formFeatures.filter((form) => form.destination.downgrade).length
  };
  const credentialBundle = formFeatures.some((form) => form.credential_bundle);
  const sensitiveKinds = [...new Set(formFeatures.flatMap((form) => form.sensitive_kinds))];
  const sensitiveExternal = formFeatures.some((form) => form.sensitive_kinds.length > 0 && form.destination.external);
  const credentialExternal = formFeatures.some((form) => form.has_password && form.destination.external);
  const insecureCredentialPage = pageLocation.protocol === "http:" && formFeatures.some((form) => form.has_password);
  const brand = findPageBrand(snapshot || {});
  const brandMismatch = Boolean(
    brand && (counts.password_fields > 0 || sensitiveKinds.length > 0) &&
    !isOfficialBrandDomain(brand, pageLocation.registrable_domain)
  );

  const contributions = [];
  const add = (category, points, code, reason) => contributions.push({ category, points, code, reason });
  if (counts.password_fields > 0) add("credentials", 4, "password_field", "Página contém campo de senha");
  if (counts.identifier_fields > 0) add("credentials", 3, "identifier_field", "Página solicita identificador de acesso");
  if (credentialBundle) add("credentials", 3, "credential_bundle", "Um formulário combina identificador e senha");

  for (const kind of sensitiveKinds) {
    const labels = {
      card: "dados de cartão", phone: "telefone", document: "documento pessoal",
      banking: "dados bancários", address: "endereço"
    };
    add("sensitive_data", kind === "card" || kind === "banking" ? 5 : 3, `sensitive_${kind}`, `Página solicita ${labels[kind]}`);
  }

  if (counts.external_forms > 0) add("form_destination", 4, "external_form", "Formulário envia dados para outro domínio registrável");
  if (credentialExternal) add("form_destination", 6, "external_credentials", "Formulário de credenciais envia dados para outro domínio");
  if (sensitiveExternal) add("form_destination", 6, "external_sensitive_data", "Formulário de dados sensíveis envia dados para outro domínio");
  if (counts.downgrade_forms > 0) add("form_destination", 7, "https_downgrade", "Formulário HTTPS envia dados para um destino HTTP");
  if (insecureCredentialPage) add("form_destination", 8, "http_credentials", "Página HTTP solicita senha");

  if (brandMismatch) {
    add("identity", 12, "brand_domain_mismatch", `A página apresenta a marca ${brand.name}, mas está em ${pageLocation.registrable_domain}`);
  }
  if (forms.length >= 4) add("page_structure", 2, "many_forms", "Página contém quatro ou mais formulários");
  if (formFeatures.some((form) => form.field_count >= 15)) add("page_structure", 2, "large_form", "Página contém formulário com muitos campos");

  const categoryScores = Object.fromEntries(Object.keys(PAGE_CATEGORY_CAPS).map((category) => [category, 0]));
  for (const contribution of contributions) categoryScores[contribution.category] += contribution.points;
  for (const [category, cap] of Object.entries(PAGE_CATEGORY_CAPS)) {
    categoryScores[category] = Math.min(categoryScores[category], cap);
  }
  const evidenceCategories = Object.entries(categoryScores)
    .filter(([, score]) => score > 0)
    .map(([category]) => category);
  const diversityBonus = evidenceCategories.length >= 3 ? 10 : evidenceCategories.length === 2 ? 6 : 0;
  const score = Math.min(Object.values(categoryScores).reduce((total, value) => total + value, 0) + diversityBonus, 100);

  const contextualCombination = credentialExternal || sensitiveExternal || insecureCredentialPage ||
    (brandMismatch && (counts.password_fields > 0 || sensitiveKinds.length > 0)) ||
    (counts.downgrade_forms > 0 && (counts.password_fields > 0 || sensitiveKinds.length > 0));
  const level = score >= PAGE_SUSPICIOUS_THRESHOLD && contextualCombination ? "suspicious" : "safe";
  const reasons = contributions.map((contribution) => contribution.reason);
  if (diversityBonus > 0) reasons.push(`Diversidade de evidências da página: ${evidenceCategories.join(", ")}`);

  return {
    version: PAGE_ANALYSIS_VERSION,
    score,
    level,
    reasons,
    contributions,
    category_scores: categoryScores,
    evidence_categories: evidenceCategories,
    diversity_bonus: diversityBonus,
    signals: {
      credential_bundle: credentialBundle,
      password_fields: counts.password_fields > 0,
      sensitive_data: sensitiveKinds.length > 0,
      sensitive_kinds: sensitiveKinds,
      external_form: counts.external_forms > 0,
      credential_external: credentialExternal,
      sensitive_external: sensitiveExternal,
      https_downgrade: counts.downgrade_forms > 0,
      insecure_credentials: insecureCredentialPage,
      brand_mismatch: brandMismatch,
      brand: brand?.name || null
    },
    features: {
      page_url: pageLocation.url,
      hostname: pageLocation.hostname,
      registrable_domain: pageLocation.registrable_domain,
      protocol: pageLocation.protocol.slice(0, -1),
      counts,
      forms: formFeatures
    }
  };
}

function invalidPageResult() {
  return {
    version: PAGE_ANALYSIS_VERSION,
    score: 0,
    level: "safe",
    reasons: [],
    contributions: [],
    category_scores: Object.fromEntries(Object.keys(PAGE_CATEGORY_CAPS).map((category) => [category, 0])),
    evidence_categories: [],
    diversity_bonus: 0,
    signals: {},
    features: null
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    PAGE_ANALYSIS_VERSION,
    PAGE_SUSPICIOUS_THRESHOLD,
    collectPageSnapshot,
    analyzePage,
    parseFormDestination
  };
}
