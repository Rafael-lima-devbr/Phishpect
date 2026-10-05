const assert = require("node:assert/strict");
const { analyzeUrl, limitedLevenshtein, V3_1_SUSPICIOUS_THRESHOLD } = require("../analysis.js");

function expectLevel(url, level) {
  const result = analyzeUrl(url);
  assert.equal(result.level, level, `${url}: esperado ${level}, recebido ${result.level} (${result.score}) — ${result.reasons.join("; ")}`);
  return result;
}

const longLegitimateUrl = `https://example.com/uma/url/muito/longa/${"segmento/".repeat(14)}?${
  Array.from({ length: 8 }, (_, index) => `param${index}=valor`).join("&")
}`;
expectLevel(longLegitimateUrl, "safe");
expectLevel("http://example.com/", "safe");
expectLevel("https://example.com/login/account/verify", "safe");
expectLevel("https://accounts.google.com/login", "safe");

const diverse = expectLevel("http://login-user-1234-a.example.com/", "suspicious");
assert.ok(diverse.evidence_categories.includes("transport"));
assert.ok(diverse.evidence_categories.includes("authentication"));
assert.ok(diverse.evidence_categories.includes("structure"));
assert.ok(diverse.diversity_bonus > 0);

const structureOnly = expectLevel("https://random-segmented-host-123456789.example/", "safe");
assert.deepEqual(structureOnly.evidence_categories, ["structure"]);

expectLevel("https://microsoft-login.example.com/", "suspicious");
expectLevel("https://login.microsoft.example.com/", "suspicious");
expectLevel("https://micros0ft-login.example.com/", "suspicious");
expectLevel("https://paypa1-secure.example.com/", "suspicious");
expectLevel("https://amazon.verify-account.example.net/", "suspicious");

const sharedBrandPath = expectLevel("https://demo.github.io/Amazon-Clone", "suspicious");
assert.equal(sharedBrandPath.signals.brand_in_pathname, "amazon");
assert.deepEqual(sharedBrandPath.evidence_categories, ["path_query", "infrastructure"]);

const shortenerBrandPath = expectLevel("https://1url.at/www/roblox-users-123-profile", "suspicious");
assert.equal(shortenerBrandPath.signals.uses_shortener, true);

for (const url of [
  "https://amazon.com/",
  "https://www.amazon.com/",
  "https://accounts.microsoft.com/",
  "https://login.microsoft.com/",
  "https://facebook.com/",
  "https://discord.com/",
  "https://discord.gg/",
  "https://ledger.com/",
  "https://metamask.io/"
]) {
  const result = expectLevel(url, "safe");
  assert.equal(result.signals.brand_mismatch, false);
}

const compoundBrand = expectLevel("http://facebooknotify-noreply.example/", "suspicious");
assert.equal(compoundBrand.signals.brand, "facebook");
assert.equal(compoundBrand.signals.brand_match_type, "compound");
expectLevel("https://applesupport.example/", "suspicious");

expectLevel("http://demo.godaddysites.com/", "suspicious");

const publicSuffix = expectLevel("https://accounts.example.co.uk/login", "safe");
assert.equal(publicSuffix.features.registrable_domain, "example.co.uk");

const punycodeOnly = expectLevel("https://xn--bcher-kva.example/", "safe");
assert.equal(punycodeOnly.signals.punycode, true);

const punycodeBrand = expectLevel("https://xn--pple-43d.example/", "suspicious");
assert.equal(punycodeBrand.signals.brand_match_type, "typo");

expectLevel("https://google.com@example.net/login", "suspicious");
assert.equal(limitedLevenshtein("micros0ft", "microsoft", 1), 1);
assert.equal(limitedLevenshtein("unrelated", "microsoft", 1), 2);
assert.equal(V3_1_SUSPICIOUS_THRESHOLD, 24);

console.log("Regras locais V3.1: OK");
