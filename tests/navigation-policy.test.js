const assert = require("node:assert/strict");
const { getNavigationDecision, sameDocumentFragmentNavigation } = require("../navigation-policy.js");

function event(overrides = {}) {
  return { defaultPrevented: false, button: 0, ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, ...overrides };
}

function link(href, attributes = {}) {
  return {
    href,
    target: attributes.target || "",
    hasAttribute(name) { return name === "download" && Boolean(attributes.download); },
    getAttribute(name) { return attributes[name] ?? null; }
  };
}

const current = "https://example.com/page?mode=1#top";
assert.deepEqual(getNavigationDecision(event(), link("https://example.net/next"), current), {
  intercept: true,
  destination: "https://example.net/next"
});

for (const candidate of [
  [event({ button: 1 }), link("https://example.net/")],
  [event({ ctrlKey: true }), link("https://example.net/")],
  [event({ metaKey: true }), link("https://example.net/")],
  [event({ shiftKey: true }), link("https://example.net/")],
  [event({ altKey: true }), link("https://example.net/")],
  [event(), link("https://example.net/", { target: "_blank" })],
  [event(), link("https://example.net/", { target: "preview" })],
  [event(), link("https://example.net/file", { download: "file" })],
  [event(), link("mailto:user@example.com")],
  [event(), link("https://example.com/page?mode=1#section")]
]) {
  assert.equal(getNavigationDecision(candidate[0], candidate[1], current).intercept, false);
}

assert.equal(getNavigationDecision(event(), link("https://example.com/page?mode=2#section"), current).intercept, true);
assert.equal(sameDocumentFragmentNavigation(current, "https://example.com/page?mode=1#section"), true);
assert.equal(sameDocumentFragmentNavigation(current, "https://example.com/page?mode=1#top"), true);
assert.equal(sameDocumentFragmentNavigation(current, "https://example.com/other#section"), false);

console.log("Política de navegação: OK");
