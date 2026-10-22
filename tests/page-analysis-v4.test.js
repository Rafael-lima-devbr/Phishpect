const assert = require("assert");
const {
  V4_LATE_OBSERVATION_DELAY_MS,
  mergePageSnapshotsV4,
  analyzePageV4
} = require("../page-analysis-v4.js");

function snapshot(overrides = {}) {
  return {
    schema_version: 4,
    page_url: "https://example.test/login",
    title: "Conta",
    identity_evidence: [],
    forms: [],
    orphan_fields: [],
    observation: {
      phase: "initial",
      scripts: 1,
      iframes: 0,
      dialogs: 0,
      submit_controls: 0,
      meta_refresh_targets: []
    },
    ...overrides
  };
}

const initial = snapshot();
const late = snapshot({
  observation: { ...initial.observation, phase: "late", scripts: 3, submit_controls: 1 },
  identity_evidence: [{ text: "Facebook login", source: "title", region: "document", auxiliary: false }],
  forms: [{
    method: "POST",
    action: "https://collector.invalid/submit",
    region: "main",
    context: [{ text: "Facebook login", source: "form_heading", region: "main", auxiliary: false }],
    fields: [
      { tag: "input", type: "email", name: "email", id: "", autocomplete: "email", placeholder: "", aria_label: "" },
      { tag: "input", type: "password", name: "password", id: "", autocomplete: "current-password", placeholder: "", aria_label: "" }
    ]
  }]
});

const merged = mergePageSnapshotsV4(initial, late);
assert.strictEqual(merged.observations.length, 2);
assert.strictEqual(merged.observation_delta.forms_added, 1);
const result = analyzePageV4(merged);
assert.strictEqual(result.level, "suspicious");
assert.strictEqual(result.signals.late_content_observed, true);
assert.strictEqual(result.features.observation_delay_ms, V4_LATE_OBSERVATION_DELAY_MS);
assert.ok(result.relationships.some((item) => item.code === "external_credentials"));

const legitimateLogin = analyzePageV4(snapshot({
  page_url: "https://accounts.example.com/login",
  forms: [{
    method: "POST",
    action: "/session",
    context: [{ text: "Sign in", source: "form_heading", region: "main", auxiliary: false }],
    fields: [
      { tag: "input", type: "email", name: "email", autocomplete: "email" },
      { tag: "input", type: "password", name: "password", autocomplete: "current-password" }
    ]
  }]
}));
assert.strictEqual(legitimateLogin.level, "safe");

const externalNewsletter = analyzePageV4(snapshot({
  forms: [{
    method: "POST",
    action: "https://newsletter.example/subscribe",
    context: [{ text: "Newsletter", source: "form_heading", region: "main", auxiliary: false }],
    fields: [{ tag: "input", type: "email", name: "email", autocomplete: "email" }]
  }]
}));
assert.strictEqual(externalNewsletter.level, "safe");

const socialFooter = analyzePageV4(snapshot({
  identity_evidence: [
    { text: "Follow us on Facebook", source: "image_alt", region: "footer", auxiliary: true },
    { text: "Download on Google Play", source: "image_alt", region: "footer", auxiliary: true }
  ]
}));
assert.strictEqual(socialFooter.level, "safe");
assert.deepStrictEqual(socialFooter.signals.presented_brands, []);

console.log("Análise integrada V4 de página: OK");
