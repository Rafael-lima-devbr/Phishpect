const assert = require("node:assert/strict");
const { analyzeUrl, limitedLevenshtein, V3_SUSPICIOUS_THRESHOLD } = require("../analysis-v3.js");

function expectSafe(url) {
  const result = analyzeUrl(url);
  assert.equal(result.level, "safe", `${url} deveria ser segura, recebeu ${result.score}: ${result.reasons.join("; ")}`);
  assert.ok(result.score < V3_SUSPICIOUS_THRESHOLD);
  return result;
}

function expectSuspicious(url) {
  const result = analyzeUrl(url);
  assert.equal(result.level, "suspicious", `${url} deveria ser suspeita, recebeu ${result.score}: ${result.reasons.join("; ")}`);
  assert.ok(result.score >= V3_SUSPICIOUS_THRESHOLD);
  return result;
}

const longLegitimateUrl = `https://example.com/uma/url/muito/longa/${"segmento/".repeat(14)}?${
  Array.from({ length: 8 }, (_, index) => `param${index}=valor`).join("&")
}`;
expectSafe(longLegitimateUrl);
expectSafe("https://accounts.google.com/login");
expectSafe("http://example.com/");
expectSafe("https://example.com/login/account/verify");

for (const url of [
  "https://microsoft-login.example.com/",
  "https://login.microsoft.example.com/",
  "https://micros0ft-login.example.com/",
  "https://paypa1-secure.example.com/",
  "https://amazon.verify-account.example.net/"
]) {
  const result = expectSuspicious(url);
  assert.equal(result.signals.brand_mismatch, true);
  assert.equal(result.signals.authentication_in_hostname, true);
}

for (const url of [
  "https://amazon.com/",
  "https://www.amazon.com/",
  "https://accounts.microsoft.com/",
  "https://login.microsoft.com/"
]) {
  const result = expectSafe(url);
  assert.equal(result.signals.brand_mismatch, false);
}

expectSafe("https://share.google/");
expectSafe("https://outlook.live.com/");

const publicSuffixResult = expectSafe("https://accounts.example.co.uk/login");
assert.equal(publicSuffixResult.features.registrable_domain, "example.co.uk");
assert.deepEqual(publicSuffixResult.features.subdomains, ["accounts"]);

const privateSuffixResult = analyzeUrl("https://microsoft-login.github.io/");
assert.equal(privateSuffixResult.features.registrable_domain, "microsoft-login.github.io");

const punycodeOnly = expectSafe("https://xn--bcher-kva.example/");
assert.ok(punycodeOnly.reasons.some((reason) => reason.includes("Punycode")));

const punycodeBrand = expectSuspicious("https://xn--pple-43d.example/");
assert.equal(punycodeBrand.signals.brand, "apple");
assert.equal(punycodeBrand.signals.brand_match_type, "typo");

const deceptiveUserInfo = expectSuspicious("https://google.com@example.net/login");
assert.ok(deceptiveUserInfo.reasons.some((reason) => reason.includes("hostname real")));

assert.equal(limitedLevenshtein("micros0ft", "microsoft", 1), 1);
assert.equal(limitedLevenshtein("unrelated", "microsoft", 1), 2);

console.log("Regras locais V3: OK");
