const assert = require("node:assert/strict");
const {
  NAVIGATION_ALLOWANCE_TTL_MS,
  createNavigationAllowance,
  matchesNavigationAllowance,
  isExpiredNavigationAllowance,
  sameDocumentUrl,
  isWarningPageUrl,
  createPendingRedirectTracker
} = require("../navigation-state.js");

const now = 1_000;
const allowance = createNavigationAllowance("https://example.com/path", now);
assert.deepEqual(allowance, { url: "https://example.com/path", expiresAt: now + NAVIGATION_ALLOWANCE_TTL_MS });
assert.equal(matchesNavigationAllowance(allowance, "https://example.com/path", now + 1), true);
assert.equal(matchesNavigationAllowance(allowance, "https://example.com/other", now + 1), false);
assert.equal(matchesNavigationAllowance(allowance, "https://example.com/path", allowance.expiresAt), false);
assert.equal(isExpiredNavigationAllowance(allowance, allowance.expiresAt), true);
assert.equal(isExpiredNavigationAllowance({ url: "https://example.com" }, now), true);

assert.equal(sameDocumentUrl("https://example.com/a#one", "https://example.com/a#two"), true);
assert.equal(sameDocumentUrl("https://example.com/a?q=1", "https://example.com/a?q=2"), false);
assert.equal(isWarningPageUrl(
  "chrome-extension://extension-id/warning.html?url=https%3A%2F%2Fexample.com",
  "chrome-extension://extension-id/warning.html"
), true);
assert.equal(isWarningPageUrl("https://attacker.example/warning.html", "chrome-extension://extension-id/warning.html"), false);
assert.equal(isWarningPageUrl("chrome-extension://other-id/warning.html", "chrome-extension://extension-id/warning.html"), false);

const tracker = createPendingRedirectTracker();
const older = tracker.begin(7, "https://example.com/first");
const newer = tracker.begin(7, "https://example.com/second");
tracker.finish(7, older);
assert.equal(tracker.current(7), newer);
tracker.finish(7, newer);
assert.equal(tracker.current(7), undefined);

console.log("Estado de navegação: OK");
