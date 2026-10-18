const assert = require("node:assert/strict");
const previous = require("../page-analysis.js");
const { PAGE_ANALYSIS_VERSION, analyzePage, parseFormDestination } = require("../page-analysis-v2.js");

function field(attributes = {}) {
  return {
    tag: attributes.tag || "input",
    type: attributes.type || "text",
    name: attributes.name || "",
    id: attributes.id || "",
    autocomplete: attributes.autocomplete || "",
    placeholder: attributes.placeholder || "",
    aria_label: attributes.aria_label || "",
    group_id: attributes.group_id
  };
}

function form(attributes = {}, fields = [], context = []) {
  return {
    action: attributes.action || "",
    method: attributes.method || "POST",
    region: attributes.region || "main",
    fields,
    context
  };
}

function evidence(text, source, attributes = {}) {
  return {
    text,
    source,
    tag: attributes.tag || null,
    region: attributes.region || "main",
    auxiliary: attributes.auxiliary === true,
    logo_like: attributes.logo_like === true
  };
}

function inspect(pageUrl, attributes = {}) {
  return analyzePage({
    schema_version: 2,
    page_url: pageUrl,
    identity_evidence: attributes.identity || [],
    forms: attributes.forms || [],
    orphan_fields: attributes.orphan_fields || []
  });
}

assert.equal(previous.PAGE_ANALYSIS_VERSION, "1.0");
assert.equal(PAGE_ANALYSIS_VERSION, "2.0");
assert.equal(inspect("https://example.com/article").level, "safe");

const legitimateLogin = inspect("https://accounts.example.com/signin", {
  identity: [evidence("Área do cliente", "title", { region: "document" })],
  forms: [form({ action: "/session" }, [
    field({ type: "email", name: "email" }),
    field({ type: "password", name: "password" })
  ])]
});
assert.equal(legitimateLogin.level, "safe");
assert.equal(legitimateLogin.signals.credential_bundle, true);

const socialMention = inspect("https://example.com/account", {
  identity: [
    evidence("Conta do cliente", "title", { region: "document" }),
    evidence("Instagram, opens in a new window", "image_alt", { region: "footer", auxiliary: true })
  ],
  forms: [form({ action: "/session" }, [field({ type: "password" })])]
});
assert.equal(socialMention.level, "safe");
assert.deepEqual(socialMention.signals.presented_brands, []);
assert.deepEqual(socialMention.signals.auxiliary_brand_mentions, ["instagram"]);

const socialAccountHeading = inspect("https://example.com/profile", {
  identity: [evidence("Official Instagram Account", "heading", { tag: "h2" })],
  forms: [form({ action: "/preferences" }, [field({ type: "password" })])]
});
assert.equal(socialAccountHeading.level, "safe");
assert.deepEqual(socialAccountHeading.signals.presented_brands, []);

const storeBadges = inspect("https://example.com/download", {
  identity: [
    evidence("Download on Google Play", "image_alt", { auxiliary: true }),
    evidence("Download on Apple App Store", "image_alt", { auxiliary: true })
  ],
  forms: [form({ action: "https://forms.vendor.test/lead" }, [
    field({ type: "email", name: "email" }), field({ type: "tel", name: "phone" })
  ])]
});
assert.equal(storeBadges.level, "safe");
assert.equal(storeBadges.signals.brand_mismatch, false);

const crmContact = inspect("https://company.example/contact", {
  forms: [form({ action: "https://forms.crm.test/lead" }, [
    field({ type: "text", name: "first_name" }),
    field({ type: "email", autocomplete: "email" }),
    field({ type: "tel", autocomplete: "tel" })
  ])]
});
assert.equal(crmContact.level, "safe");
assert.equal(crmContact.signals.external_form, true);
assert.equal(crmContact.signals.sensitive_external, true);
assert.equal(crmContact.signals.high_risk_sensitive_external, false);

const incompatibleIdentity = inspect("https://secure.example.net/session", {
  identity: [evidence("Microsoft account sign in", "title", { region: "document" })],
  forms: [form({ action: "/session" }, [
    field({ type: "email", name: "email" }), field({ type: "password", name: "password" })
  ])]
});
assert.equal(incompatibleIdentity.level, "suspicious");
assert.equal(incompatibleIdentity.signals.brand_mismatch, true);

const officialIdentity = inspect("https://login.microsoft.com/session", {
  identity: [evidence("Microsoft account sign in", "title", { region: "document" })],
  forms: [form({ action: "/session" }, [field({ type: "password" })])]
});
assert.equal(officialIdentity.level, "safe");

const externalPassword = inspect("https://portal.example.com/login", {
  forms: [form({ action: "https://collector.example.net/session" }, [
    field({ autocomplete: "username" }), field({ type: "password" })
  ])]
});
assert.equal(externalPassword.level, "suspicious");
assert.equal(externalPassword.signals.credential_external, true);

const separatedSignals = inspect("https://example.com/complex", {
  identity: [evidence("Instagram, opens in a new window", "image_alt", { region: "footer", auxiliary: true })],
  forms: [
    form({ action: "https://crm.example.net/contact" }, [field({ type: "email" }), field({ type: "tel" })]),
    form({ action: "/preferences" }, [field({ type: "password" })])
  ]
});
assert.equal(separatedSignals.level, "safe");
assert.equal(separatedSignals.signals.password_fields, true);
assert.equal(separatedSignals.signals.external_form, true);

const relatedSignals = inspect("https://account.example.net/verify", {
  forms: [form({ action: "/submit" }, [
    field({ type: "email" }), field({ type: "password" })
  ], [evidence("PayPal verification", "form_heading", { tag: "h1" })])]
});
assert.equal(relatedSignals.level, "suspicious");
assert.equal(relatedSignals.features.forms[0].identity.presented_brand_scope, "form");

const multipleOrdinaryForms = inspect("https://example.com/forms", {
  forms: [
    form({ action: "/search", method: "GET" }, [field({ type: "search", name: "q" })]),
    form({ action: "/newsletter" }, [field({ type: "email" })]),
    form({ action: "/login" }, [field({ type: "email" }), field({ type: "password" })]),
    form({ action: "/contact" }, [field({ type: "tel" })])
  ]
});
assert.equal(multipleOrdinaryForms.level, "safe");

const orphanCredentials = inspect("https://auth.example.net/", {
  identity: [evidence("Facebook login", "title", { region: "document" })],
  orphan_fields: [field({ type: "email", group_id: "auth" }), field({ type: "password", group_id: "auth" })]
});
assert.equal(orphanCredentials.level, "suspicious");
assert.equal(orphanCredentials.signals.orphan_credential_bundle, true);

const separatedOrphanFields = inspect("https://auth.example.net/", {
  identity: [evidence("Facebook login", "title", { region: "document" })],
  orphan_fields: [field({ type: "email", group_id: "newsletter" }), field({ type: "password", group_id: "settings" })]
});
assert.equal(separatedOrphanFields.level, "safe");
assert.equal(separatedOrphanFields.signals.orphan_credential_bundle, false);

const placeholderClassification = inspect("https://example.com/signin", {
  forms: [form({ action: "/session" }, [
    field({ placeholder: "Email" }), field({ aria_label: "Senha" })
  ])]
});
assert.equal(placeholderClassification.signals.credential_bundle, true);
assert.equal(placeholderClassification.level, "safe");

const camelCaseClassification = inspect("https://example.com/signin", {
  forms: [form({ action: "/session" }, [field({ name: "userEmail" }), field({ type: "password" })])]
});
assert.equal(camelCaseClassification.signals.credential_bundle, true);

const multiPart = parseFormDestination("https://collector.example.co.uk/send", {
  url: "https://shop.example.co.uk/checkout",
  protocol: "https:",
  registrable_domain: "example.co.uk"
});
assert.equal(multiPart.external, false);

for (const result of [legitimateLogin, incompatibleIdentity, externalPassword, relatedSignals, orphanCredentials]) {
  assert.notEqual(result.level, "blocked");
}

console.log("Análise pós-carregamento v2: OK");
