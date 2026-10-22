const assert = require("assert");
const { analyzeUrlV4 } = require("../analysis-v4.js");

const safeCases = [
  "https://accounts.google.com/signin/v2/identifier",
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
  "https://github.com/login/oauth/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fcallback",
  "https://example.com/account/login",
  "http://example.com/",
  "https://tenant-name.vercel.app/",
  "https://company.github.io/docs/google-login-guide",
  "https://xn--bcher-kva.example/conta",
  "https://shop.example/checkout?utm_source=newsletter&utm_campaign=long-campaign-name",
  "https://crm.example/customer/account/verification/history",
  "https://[2001:db8::1]/status",
  "https://example.com:443/login"
];

for (const url of safeCases) {
  assert.strictEqual(analyzeUrlV4(url).level, "safe", `esperava safe: ${url}`);
}

const suspiciousCases = [
  "http://paypal-secure-login.test/verify/account",
  "https://192.0.2.10/login/auth/account",
  "https://google-login.test/redirect?url=https%3A%2F%2Fevil.example%2Fsignin",
  "https://paypal.example@secure-login.test/account",
  "https://paypal.example@@secure-login.test/account",
  "https://ledger-login-auth.tenant.pages.dev/verify"
];

for (const url of suspiciousCases) {
  const result = analyzeUrlV4(url);
  assert.notStrictEqual(result.level, "safe", `esperava risco: ${url}`);
  assert.ok(result.reasons.length > 0);
  assert.ok(Array.isArray(result.relationships));
}

const nested = analyzeUrlV4("https://google-login.test/continue?redirect=https%3A%2F%2Fexample.invalid%2Fauth");
assert.strictEqual(nested.signals.nested_url, true);
assert.ok(nested.features.nested_urls.length === 1);

const unusualPortOnly = analyzeUrlV4("https://example.com:8443/status");
assert.strictEqual(unusualPortOnly.level, "safe");
assert.strictEqual(unusualPortOnly.signals.unusual_port, true);

const blocked = analyzeUrlV4("https://phishing-test.invalid/");
assert.strictEqual(blocked.level, "blocked");

const invalid = analyzeUrlV4("javascript:alert(1)");
assert.strictEqual(invalid.level, "blocked");
assert.strictEqual(invalid.decision_basis, "invalid-or-unsupported-url");

console.log("Análise integrada V4 de URL: OK");
