const assert = require("node:assert/strict");
const {
  normalizeDomain,
  normalizeUrlForReputation,
  createReputationDatabase,
  checkExternalReputation
} = require("../reputation.js");

assert.equal(normalizeDomain("WWW.Example.COM."), "example.com");
assert.equal(normalizeUrlForReputation("HTTPS://WWW.Example.COM/path/?b=2&a=1#fragment"), "example.com/path?a=1&b=2");
assert.equal(normalizeUrlForReputation("http://example.com/"), "example.com");
assert.equal(normalizeUrlForReputation("https://example.com:8443/"), "example.com:8443");
assert.equal(normalizeUrlForReputation("ftp://example.com/"), null);

const unavailable = createReputationDatabase(null);
assert.equal(unavailable.available, false);
assert.deepEqual(checkExternalReputation("https://example.com/", unavailable), {
  listed: false,
  available: false,
  source: "Phishing.Database",
  matchType: null
});

const database = createReputationDatabase({
  urls: ["phish.example/login?a=1&b=2"],
  domains: ["bad.example", "tenant-a.github.io"]
});
assert.equal(database.available, true);
assert.equal(checkExternalReputation("https://phish.example/login?b=2&a=1#x", database).listed, true);
assert.equal(checkExternalReputation("https://bad.example/anything", database).matchType, "domain");
assert.equal(checkExternalReputation("https://tenant-a.github.io/login", database).listed, true);
assert.equal(checkExternalReputation("https://tenant-b.github.io/login", database).listed, false);
assert.equal(checkExternalReputation("https://github.io/", database).listed, false);

console.log("Reputação: OK");
