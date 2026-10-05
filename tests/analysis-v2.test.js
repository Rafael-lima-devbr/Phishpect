const assert = require("node:assert/strict");
const { analyzeUrl } = require("../analysis-v2.js");

const officialBrand = analyzeUrl("https://roblox.com/");
assert.equal(officialBrand.signals.brand_mismatch, false);

const misleadingCountryDomain = analyzeUrl("https://www.roblox.com.hr/");
assert.equal(misleadingCountryDomain.signals.brand_mismatch, true);
assert.equal(misleadingCountryDomain.score, 20);

const sharedBrandAndLogin = analyzeUrl("https://instagram-login1.github.io/");
assert.equal(sharedBrandAndLogin.signals.brand_mismatch, true);
assert.ok(sharedBrandAndLogin.reasons.some((reason) => reason.includes("Hospedagem compartilhada")));

const sharedBrand = analyzeUrl("https://amazon-clone-projects.github.io/");
assert.equal(sharedBrand.signals.brand_mismatch, true);

assert.equal(analyzeUrl("https://example.github.io/").score, 0);
assert.equal(analyzeUrl("https://account-verify.example.invalid/").level, "suspicious");
assert.equal(analyzeUrl("https://u.to/example").score, 10);
assert.equal(analyzeUrl("https://one-two-three.example/").score, 5);
assert.equal(analyzeUrl("https://host1234.example/").score, 5);
assert.equal(analyzeUrl(`https://example.com/${"a".repeat(61)}`).score, 5);
assert.ok(!analyzeUrl(`https://example.com/a?${"b".repeat(140)}`).reasons.some(
  (reason) => reason.includes("Caminho da URL")
));

console.log("Regras locais V2: OK");
