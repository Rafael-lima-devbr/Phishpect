const PAGE_ANALYSIS_VERSION = "2.0";
const PAGE_SNAPSHOT_VERSION = 2;
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

const AUXILIARY_REGIONS = new Set(["footer", "nav", "aside"]);
const AUTHENTICATION_TERMS = new Set([
  "authenticate", "authentication", "entrar", "login", "logon",
  "signin", "signon", "senha", "password", "verify", "verification", "verificar"
]);

function getPageDomainParser() {
  if (typeof globalThis !== "undefined" && globalThis.tldts?.parse) return globalThis.tldts;
  if (typeof require === "function") return require("tldts");
  throw new Error("Parser de domínio registrável indisponível");
}

function truncateText(value, maximumLength = 240) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, maximumLength);
}

function readAttribute(element, attribute, maximumLength = 120) {
  return truncateText(element?.getAttribute?.(attribute), maximumLength);
}

function normalizeAttribute(element, attribute) {
  return readAttribute(element, attribute).toLowerCase();
}

function normalizeText(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function tokenizeIdentifier(value) {
  return normalizeText(String(value || "").replace(/([a-z\d])([A-Z])/g, "$1 $2"))
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function compactIdentifier(value) {
  return normalizeText(value).replace(/[^a-z0-9]+/g, "");
}

function elementRegion(element) {
  if (!element?.closest) return "other";
  for (const [selector, region] of [
    ["footer", "footer"], ["nav", "nav"], ["aside", "aside"],
    ["header", "header"], ["main", "main"]
  ]) {
    if (element.closest(selector)) return region;
  }
  return "other";
}

function looksAuxiliaryText(value) {
  const text = normalizeText(value);
  const storeBadge = /\b(download|baixar|obtenha|get it|available on)\b/.test(text) &&
    /\b(app store|google play)\b/.test(text);
  const socialLink = /\b(opens? in (a )?new window|follow us|siga-nos|social (link|media))\b/.test(text);
  return storeBadge || socialLink;
}

function looksLogoLike(element) {
  const metadata = [
    readAttribute(element, "class"), readAttribute(element, "id"),
    readAttribute(element, "role"), readAttribute(element, "itemprop")
  ].join(" ");
  return /(^|[^a-z])(logo|brand|identity)([^a-z]|$)/i.test(metadata);
}

function identityEvidence(text, source, options = {}) {
  const cleaned = truncateText(text, 200);
  if (!cleaned) return null;
  const region = options.region || "other";
  return {
    text: cleaned,
    source,
    tag: options.tag || null,
    region,
    logo_like: options.logo_like === true,
    auxiliary: options.auxiliary === true || AUXILIARY_REGIONS.has(region) || looksAuxiliaryText(cleaned)
  };
}

function collectFieldMetadata(field) {
  const tag = String(field?.tagName || "").toLowerCase();
  return {
    tag,
    type: tag === "input" ? (normalizeAttribute(field, "type") || "text") : tag,
    name: readAttribute(field, "name"),
    id: readAttribute(field, "id"),
    autocomplete: normalizeAttribute(field, "autocomplete"),
    placeholder: readAttribute(field, "placeholder"),
    aria_label: readAttribute(field, "aria-label")
  };
}

function contextSource(node, prefix = "form") {
  const tag = String(node?.tagName || "").toLowerCase();
  if (tag === "img") return `${prefix}_image_alt`;
  if (/^h[1-3]$/.test(tag)) return `${prefix}_heading`;
  if (tag === "legend") return `${prefix}_legend`;
  if (tag === "label") return `${prefix}_label`;
  return `${prefix}_button`;
}

function contextNodeText(node) {
  if (String(node?.tagName || "").toLowerCase() === "img") return readAttribute(node, "alt", 200);
  return truncateText(node?.textContent, 200);
}

function collectContextEvidence(container, prefix, maximum = 12) {
  if (!container?.querySelectorAll) return [];
  return [...container.querySelectorAll("h1, h2, h3, legend, label, button, [role='button'], img[alt]")]
    .slice(0, maximum)
    .map((node) => identityEvidence(contextNodeText(node), contextSource(node, prefix), {
      tag: String(node?.tagName || "").toLowerCase() || null,
      region: elementRegion(node),
      logo_like: looksLogoLike(node)
    }))
    .filter(Boolean);
}

function nearestFormSection(form) {
  return form?.closest?.("section, article, fieldset, [role='form'], [role='dialog']") || null;
}

function collectFormSnapshot(form) {
  const ownContext = collectContextEvidence(form, "form", 12);
  const section = nearestFormSection(form);
  const sectionContext = section && section !== form ? collectContextEvidence(section, "section", 8) : [];
  const seen = new Set();
  const context = [...ownContext, ...sectionContext].filter((item) => {
    const key = `${item.source}\0${item.text}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 16);
  return {
    method: (normalizeAttribute(form, "method") || "get").toUpperCase(),
    action: readAttribute(form, "action", 2048),
    region: elementRegion(form),
    context,
    fields: [...form.querySelectorAll("input, textarea, select")]
      .slice(0, 80)
      .map(collectFieldMetadata)
  };
}

function collectPageSnapshot(documentObject, pageUrl) {
  if (!documentObject?.querySelectorAll) throw new Error("Documento indisponível para análise");

  const title = truncateText(documentObject.title);
  const headings = [...documentObject.querySelectorAll("h1, h2")].slice(0, 16);
  const images = [...documentObject.querySelectorAll("img[alt]")].slice(0, 30);
  const identity = [
    identityEvidence(title, "title", { region: "document" }),
    ...headings.map((heading) => identityEvidence(heading.textContent, "heading", {
      tag: String(heading.tagName || "").toLowerCase() || null,
      region: elementRegion(heading)
    })),
    ...images.map((image) => identityEvidence(readAttribute(image, "alt", 200), "image_alt", {
      tag: "img",
      region: elementRegion(image),
      logo_like: looksLogoLike(image)
    }))
  ].filter(Boolean);

  const forms = [...documentObject.querySelectorAll("form")].slice(0, 30).map(collectFormSnapshot);
  const allFields = [...documentObject.querySelectorAll("input, textarea, select")];
  const orphanContainers = new Map();
  const orphanFields = allFields
    .filter((field) => !field.closest?.("form"))
    .slice(0, 80)
    .map((field) => {
      const container = field.closest?.("section, article, fieldset, [role='form'], [role='dialog']") || field.parentElement || field;
      if (!orphanContainers.has(container)) orphanContainers.set(container, `group-${orphanContainers.size + 1}`);
      return { ...collectFieldMetadata(field), region: elementRegion(field), group_id: orphanContainers.get(container) };
    });

  return {
    schema_version: PAGE_SNAPSHOT_VERSION,
    page_url: String(pageUrl || ""),
    title,
    identity_evidence: identity,
    forms,
    orphan_fields: orphanFields
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

function fieldTokens(field) {
  return new Set([
    ...tokenizeIdentifier(field.name), ...tokenizeIdentifier(field.id),
    ...tokenizeIdentifier(field.placeholder), ...tokenizeIdentifier(field.aria_label)
  ]);
}

function classifyField(field) {
  const autocomplete = String(field.autocomplete || "").toLowerCase();
  const autocompleteTokens = new Set(autocomplete.split(/\s+/).filter(Boolean));
  const type = String(field.type || "").toLowerCase();
  const tokens = fieldTokens(field);
  const compactValues = [field.name, field.id, field.placeholder, field.aria_label]
    .map(compactIdentifier)
    .filter(Boolean);
  const hasToken = (...terms) => terms.some((term) => tokens.has(term));
  const hasCompact = (...terms) => terms.some((term) => compactValues.includes(term));
  const kinds = new Set();
  if (type === "password" || autocompleteTokens.has("current-password") || autocompleteTokens.has("new-password") || hasToken("password", "senha")) kinds.add("password");
  if (autocompleteTokens.has("username") || hasToken("user", "username", "usuario", "login", "signin") || hasCompact("account")) kinds.add("username");
  if (type === "email" || autocompleteTokens.has("email") || hasToken("email")) kinds.add("email");
  if ([...autocompleteTokens].some((value) => value.startsWith("cc-")) || hasToken("card", "cartao", "cvv", "cvc", "expiry", "expiration") || hasCompact("cardnumber", "creditcard")) kinds.add("card");
  if (type === "tel" || [...autocompleteTokens].some((value) => value === "tel" || value.startsWith("tel-")) || hasToken("phone", "telefone", "telephone", "celular", "mobile")) kinds.add("phone");
  if (hasToken("cpf", "cnpj", "document", "documento", "taxid") || hasCompact("taxid")) kinds.add("document");
  if (hasToken("bank", "banco", "pix", "iban", "routing", "agencia") || hasCompact("accountnumber", "bankaccount", "routingnumber")) kinds.add("banking");
  const addressAutocomplete = [...autocompleteTokens].some((value) => ["street-address", "postal-code"].includes(value) || value.startsWith("address-line"));
  if (addressAutocomplete || (!kinds.has("email") && hasToken("address", "endereco", "street", "postal", "postcode", "cep"))) kinds.add("address");
  return [...kinds];
}

function normalizeFormMethod(value) {
  const raw = String(value || "GET").trim().toUpperCase() || "GET";
  if (["GET", "POST", "DIALOG"].includes(raw)) return { method: raw, method_raw: raw };
  return { method: "OTHER", method_raw: raw.slice(0, 32) };
}

function brandMatches(value) {
  const text = normalizeText(value);
  return PAGE_KNOWN_BRANDS.filter((brand) => new RegExp(`(^|[^a-z0-9])${brand.name}([^a-z0-9]|$)`, "i").test(text));
}

function hasAuthenticationLanguage(value) {
  const text = normalizeText(value);
  return /\b(?:sign|log)[\s-]+in\b/.test(text) ||
    tokenizeIdentifier(text).some((token) => AUTHENTICATION_TERMS.has(token));
}

function normalizedIdentityEvidence(snapshot) {
  if (Array.isArray(snapshot.identity_evidence)) {
    return snapshot.identity_evidence.slice(0, 80).map((item) => ({
      text: truncateText(item?.text, 200),
      source: String(item?.source || "unknown"),
      tag: item?.tag ? String(item.tag).toLowerCase() : null,
      region: String(item?.region || "other"),
      logo_like: item?.logo_like === true,
      auxiliary: item?.auxiliary === true || AUXILIARY_REGIONS.has(String(item?.region || "other")) || looksAuxiliaryText(item?.text)
    })).filter((item) => item.text);
  }
  const title = identityEvidence(snapshot.title, "title", { region: "document" });
  const headings = (Array.isArray(snapshot.headings) ? snapshot.headings : []).slice(0, 12)
    .map((text, index) => identityEvidence(text, "heading", { tag: index === 0 ? "h1" : "h2", region: "other" }));
  const images = (Array.isArray(snapshot.image_alts) ? snapshot.image_alts : []).slice(0, 20)
    .map((text) => identityEvidence(text, "image_alt", { region: "other", auxiliary: true }));
  return [title, ...headings, ...images].filter(Boolean);
}

function presentedBrands(evidence) {
  const byBrand = new Map();
  for (const item of evidence) {
    for (const brand of brandMatches(item.text)) {
      if (!byBrand.has(brand.name)) byBrand.set(brand.name, { brand, evidence: [] });
      byBrand.get(brand.name).evidence.push(item);
    }
  }
  const presented = [];
  for (const record of byBrand.values()) {
    const primary = record.evidence.filter((item) => !item.auxiliary);
    const authenticationPresentation = primary.some((item) =>
      ["title", "heading", "form_heading", "form_legend", "section_heading"].includes(item.source) &&
      hasAuthenticationLanguage(item.text)
    );
    const sourceKinds = new Set(primary.filter((item) =>
      item.source === "title" || item.source.includes("heading") || item.source.includes("legend") || item.logo_like
    ).map((item) => item.logo_like ? "logo" : item.source));
    const corroborated = sourceKinds.size >= 2;
    const localLogo = primary.some((item) => item.logo_like && item.source.startsWith("form_"));
    if (authenticationPresentation || corroborated || localLogo) {
      presented.push({ ...record, reason: authenticationPresentation ? "authentication_identity" : "corroborated_identity" });
    }
  }
  return presented;
}

function isOfficialBrandDomain(brand, registrableDomain) {
  return brand.officialDomains.some((domain) => registrableDomain === domain || registrableDomain.endsWith(`.${domain}`));
}

function formIdentity(form, pagePresented, pageLocation) {
  const localEvidence = Array.isArray(form.context) ? form.context : [];
  const localPresented = presentedBrands(localEvidence);
  const candidates = localPresented.length ? localPresented : pagePresented;
  const mismatch = candidates.find((item) => !isOfficialBrandDomain(item.brand, pageLocation.registrable_domain));
  return {
    presented_brand: candidates[0]?.brand.name || null,
    presented_brand_scope: localPresented.length ? "form" : (candidates.length ? "page" : null),
    brand_mismatch: Boolean(mismatch),
    mismatched_brand: mismatch?.brand.name || null
  };
}

function featureCounts(kinds) {
  return Object.fromEntries([...new Set(kinds)].map((kind) => [kind, kinds.filter((candidate) => candidate === kind).length]));
}

function analyzeForm(form, pageLocation, pagePresented) {
  const fields = (Array.isArray(form.fields) ? form.fields : []).slice(0, 80);
  const kindCounts = featureCounts(fields.flatMap(classifyField));
  const destination = parseFormDestination(form.action, pageLocation);
  const hasPassword = Boolean(kindCounts.password);
  const hasIdentifier = Boolean(kindCounts.username || kindCounts.email);
  const sensitiveKinds = ["card", "phone", "document", "banking", "address"].filter((kind) => kindCounts[kind]);
  const identity = formIdentity(form, pagePresented, pageLocation);
  const method = normalizeFormMethod(form.method);
  return {
    ...method,
    region: String(form.region || "other"),
    field_count: fields.length,
    hidden_field_count: fields.filter((field) => String(field.type || "").toLowerCase() === "hidden").length,
    field_kind_counts: kindCounts,
    has_password: hasPassword,
    has_identifier: hasIdentifier,
    credential_bundle: hasPassword && hasIdentifier,
    sensitive_kinds: sensitiveKinds,
    destination,
    identity
  };
}

function scoreContext(form, pageLocation, structureSignals = {}) {
  const contributions = [];
  const add = (category, points, code, reason) => contributions.push({ category, points, code, reason });
  if (form.has_password) add("credentials", 4, "password_field", "Formulário contém campo de senha");
  if (form.has_identifier) add("credentials", 3, "identifier_field", "Formulário solicita identificador de acesso");
  if (form.credential_bundle) add("credentials", 3, "credential_bundle", "O mesmo formulário combina identificador e senha");
  const labels = { card: "dados de cartão", phone: "telefone", document: "documento pessoal", banking: "dados bancários", address: "endereço" };
  for (const kind of form.sensitive_kinds) {
    add("sensitive_data", kind === "card" || kind === "banking" ? 5 : 3, `sensitive_${kind}`, `Formulário solicita ${labels[kind]}`);
  }
  if (form.destination.external) add("form_destination", 2, "external_form", "Formulário envia dados para outro domínio registrável");
  if (form.has_password && form.destination.external) add("form_destination", 6, "external_credentials", "Formulário com senha envia dados para outro domínio");
  if (form.sensitive_kinds.length && form.destination.external) add("form_destination", 6, "external_sensitive_data", "Formulário de dados sensíveis envia dados para outro domínio");
  if (form.destination.downgrade) add("form_destination", 7, "https_downgrade", "Formulário HTTPS envia dados para um destino HTTP");
  if (pageLocation.protocol === "http:" && form.has_password) add("form_destination", 8, "http_credentials", "Página HTTP solicita senha");
  const identityRelevant = form.has_password || form.sensitive_kinds.some((kind) => ["card", "document", "banking"].includes(kind));
  if (form.identity.brand_mismatch && identityRelevant) {
    add("identity", 12, "brand_domain_mismatch", `O contexto do formulário apresenta a marca ${form.identity.mismatched_brand}, mas a página está em ${pageLocation.registrable_domain}`);
  }
  if (structureSignals.manyForms) add("page_structure", 2, "many_forms", "Página contém quatro ou mais formulários");
  if (form.field_count >= 15) add("page_structure", 2, "large_form", "Formulário contém muitos campos");
  if (structureSignals.multipleCredentialForms) add("page_structure", 2, "multiple_credential_forms", "Página contém múltiplos formulários de autenticação");
  return finalizeContext(contributions, {
    contextual: (form.has_password && form.destination.external) ||
      (form.destination.external && form.sensitive_kinds.some((kind) => ["card", "document", "banking"].includes(kind))) ||
      (pageLocation.protocol === "http:" && form.has_password) ||
      (form.destination.downgrade && (form.has_password || form.sensitive_kinds.length > 0)) ||
      (form.identity.brand_mismatch && identityRelevant)
  });
}

function finalizeContext(contributions, options = {}) {
  const categoryScores = Object.fromEntries(Object.keys(PAGE_CATEGORY_CAPS).map((category) => [category, 0]));
  for (const contribution of contributions) categoryScores[contribution.category] += contribution.points;
  for (const [category, cap] of Object.entries(PAGE_CATEGORY_CAPS)) categoryScores[category] = Math.min(categoryScores[category], cap);
  const evidenceCategories = Object.entries(categoryScores).filter(([, score]) => score > 0).map(([category]) => category);
  const diversityBonus = evidenceCategories.length >= 3 ? 10 : evidenceCategories.length === 2 ? 6 : 0;
  const score = Math.min(Object.values(categoryScores).reduce((total, value) => total + value, 0) + diversityBonus, 100);
  return { contributions, category_scores: categoryScores, evidence_categories: evidenceCategories, diversity_bonus: diversityBonus, score, contextual: options.contextual === true };
}

function orphanContext(orphanFields, pagePresented, pageLocation) {
  const kinds = orphanFields.flatMap(classifyField);
  const kindCounts = featureCounts(kinds);
  const hasPassword = Boolean(kindCounts.password);
  const hasIdentifier = Boolean(kindCounts.username || kindCounts.email);
  const credentialBundle = hasPassword && hasIdentifier;
  const mismatch = pagePresented.find((item) => !isOfficialBrandDomain(item.brand, pageLocation.registrable_domain));
  const contributions = [];
  const add = (category, points, code, reason) => contributions.push({ category, points, code, reason });
  if (hasPassword) add("credentials", 4, "orphan_password_field", "Página contém campo de senha fora de um formulário");
  if (hasIdentifier) add("credentials", 3, "orphan_identifier_field", "Página contém identificador de acesso fora de um formulário");
  if (credentialBundle) add("credentials", 3, "orphan_credential_bundle", "A mesma página combina identificador e senha fora de formulários HTML");
  if (mismatch && credentialBundle) add("identity", 12, "orphan_brand_domain_mismatch", `A página apresenta a marca ${mismatch.brand.name} com campos de credenciais, mas está em ${pageLocation.registrable_domain}`);
  return {
    ...finalizeContext(contributions, { contextual: Boolean(mismatch && credentialBundle) }),
    kind_counts: kindCounts,
    credential_bundle: credentialBundle,
    brand_mismatch: Boolean(mismatch && credentialBundle),
    brand: mismatch?.brand.name || null
  };
}

function analyzePage(snapshot) {
  const pageLocation = parsePageLocation(snapshot?.page_url);
  if (!pageLocation) return invalidPageResult();
  const identity = normalizedIdentityEvidence(snapshot || {});
  const pagePresented = presentedBrands(identity.filter((item) => !item.source.startsWith("form_") && !item.source.startsWith("section_")));
  const mentions = [...new Set(identity.flatMap((item) => brandMatches(item.text).map((brand) => brand.name)))];
  const auxiliaryMentions = [...new Set(identity.filter((item) => item.auxiliary).flatMap((item) => brandMatches(item.text).map((brand) => brand.name)))];
  const formsInput = Array.isArray(snapshot.forms) ? snapshot.forms.slice(0, 30) : [];
  const preliminaryForms = formsInput.map((form) => analyzeForm(form, pageLocation, pagePresented));
  const structureSignals = {
    manyForms: preliminaryForms.length >= 4,
    multipleCredentialForms: preliminaryForms.filter((form) => form.credential_bundle).length >= 2
  };
  const formContexts = preliminaryForms.map((form, index) => ({ index, ...scoreContext(form, pageLocation, structureSignals) }));
  const orphanFields = (Array.isArray(snapshot.orphan_fields) ? snapshot.orphan_fields : []).slice(0, 80);
  const orphanGroups = new Map();
  orphanFields.forEach((field, index) => {
    const groupId = field?.group_id ? String(field.group_id) : `ungrouped-${index}`;
    if (!orphanGroups.has(groupId)) orphanGroups.set(groupId, []);
    orphanGroups.get(groupId).push(field);
  });
  const orphanContexts = [...orphanGroups.entries()].map(([groupId, fields]) => ({
    index: `orphan:${groupId}`,
    ...orphanContext(fields, pagePresented, pageLocation)
  }));
  const candidates = [...formContexts, ...orphanContexts];
  const selected = candidates.sort((left, right) => Number(right.contextual) - Number(left.contextual) || right.score - left.score)[0] || finalizeContext([]);
  const level = selected.contextual && selected.score >= PAGE_SUSPICIOUS_THRESHOLD ? "suspicious" : "safe";
  const reasons = selected.contributions.map((contribution) => contribution.reason);
  if (selected.diversity_bonus > 0) reasons.push(`Diversidade de evidências relacionadas: ${selected.evidence_categories.join(", ")}`);
  const sensitiveKinds = [...new Set(preliminaryForms.flatMap((form) => form.sensitive_kinds))];
  const brandMismatchForms = preliminaryForms.filter((form) => form.identity.brand_mismatch && (form.has_password || form.sensitive_kinds.some((kind) => ["card", "document", "banking"].includes(kind))));
  const orphanCredentialContext = orphanContexts.find((context) => context.credential_bundle);
  const orphanBrandContext = orphanContexts.find((context) => context.brand_mismatch);
  const counts = {
    forms: preliminaryForms.length,
    get_forms: preliminaryForms.filter((form) => form.method === "GET").length,
    post_forms: preliminaryForms.filter((form) => form.method === "POST").length,
    dialog_forms: preliminaryForms.filter((form) => form.method === "DIALOG").length,
    other_method_forms: preliminaryForms.filter((form) => form.method === "OTHER").length,
    password_fields: preliminaryForms.reduce((total, form) => total + (form.field_kind_counts.password || 0), 0),
    identifier_fields: preliminaryForms.reduce((total, form) => total + (form.field_kind_counts.username || 0) + (form.field_kind_counts.email || 0), 0),
    external_forms: preliminaryForms.filter((form) => form.destination.external).length,
    downgrade_forms: preliminaryForms.filter((form) => form.destination.downgrade).length,
    orphan_fields: orphanFields.length,
    hidden_fields: preliminaryForms.reduce((total, form) => total + form.hidden_field_count, 0)
  };
  const credentialExternal = preliminaryForms.some((form) => form.has_password && form.destination.external);
  const sensitiveExternal = preliminaryForms.some((form) => form.sensitive_kinds.length > 0 && form.destination.external);
  const highRiskSensitiveExternal = preliminaryForms.some((form) => form.destination.external && form.sensitive_kinds.some((kind) => ["card", "document", "banking"].includes(kind)));
  const insecureCredentialPage = pageLocation.protocol === "http:" && preliminaryForms.some((form) => form.has_password);
  return {
    version: PAGE_ANALYSIS_VERSION,
    score: selected.score,
    level,
    reasons,
    contributions: selected.contributions,
    category_scores: selected.category_scores,
    evidence_categories: selected.evidence_categories,
    diversity_bonus: selected.diversity_bonus,
    signals: {
      credential_bundle: preliminaryForms.some((form) => form.credential_bundle),
      password_fields: counts.password_fields > 0,
      sensitive_data: sensitiveKinds.length > 0,
      sensitive_kinds: sensitiveKinds,
      external_form: counts.external_forms > 0,
      credential_external: credentialExternal,
      sensitive_external: sensitiveExternal,
      high_risk_sensitive_external: highRiskSensitiveExternal,
      https_downgrade: counts.downgrade_forms > 0,
      insecure_credentials: insecureCredentialPage,
      brand_mismatch: brandMismatchForms.length > 0 || Boolean(orphanBrandContext),
      brand: brandMismatchForms[0]?.identity.mismatched_brand || orphanBrandContext?.brand || null,
      presented_brands: pagePresented.map((item) => item.brand.name),
      brand_mentions: mentions,
      auxiliary_brand_mentions: auxiliaryMentions,
      orphan_credential_bundle: Boolean(orphanCredentialContext),
      multiple_credential_forms: structureSignals.multipleCredentialForms,
      evidence_localized: true
    },
    features: {
      snapshot_schema_version: Number(snapshot.schema_version) || 1,
      page_url: pageLocation.url,
      hostname: pageLocation.hostname,
      registrable_domain: pageLocation.registrable_domain,
      protocol: pageLocation.protocol.slice(0, -1),
      counts,
      selected_context: selected.index,
      forms: preliminaryForms,
      orphan_field_groups: orphanContexts.map((context) => ({
        group_id: String(context.index).replace(/^orphan:/, ""),
        field_kind_counts: context.kind_counts,
        credential_bundle: context.credential_bundle
      })),
      identity_evidence: identity
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
    PAGE_SNAPSHOT_VERSION,
    PAGE_SUSPICIOUS_THRESHOLD,
    collectPageSnapshot,
    analyzePage,
    parseFormDestination,
    classifyField
  };
}
