const assert = require("node:assert/strict");
const { collectPageSnapshot, analyzePage, parseFormDestination } = require("../page-analysis.js");

function field(attributes = {}) {
  return {
    tagName: attributes.tagName || "INPUT",
    getAttribute(name) { return attributes[name] ?? null; },
    get value() { throw new Error("O conteúdo digitado não pode ser lido"); }
  };
}

function form(attributes = {}, fields = []) {
  return {
    getAttribute(name) { return attributes[name] ?? null; },
    querySelectorAll(selector) {
      assert.equal(selector, "input, textarea, select");
      return fields;
    }
  };
}

function documentFixture({ title = "", headings = [], imageAlts = [], forms = [] } = {}) {
  return {
    title,
    querySelectorAll(selector) {
      if (selector === "form") return forms;
      if (selector === "h1, h2") return headings.map((textContent) => ({ textContent }));
      if (selector === "img[alt]") return imageAlts.map((alt) => ({ getAttribute: () => alt }));
      return [];
    }
  };
}

function inspect(url, fixture) {
  return analyzePage(collectPageSnapshot(documentFixture(fixture), url));
}

assert.equal(inspect("https://example.com/article", { title: "Artigo comum" }).level, "safe");

const legitimateLogin = inspect("https://accounts.example.com/signin", {
  title: "Área do cliente",
  forms: [form({ action: "/session", method: "post" }, [
    field({ type: "email", name: "email" }),
    field({ type: "password", name: "password" })
  ])]
});
assert.equal(legitimateLogin.level, "safe");
assert.equal(legitimateLogin.signals.credential_bundle, true);

const passwordOnly = inspect("https://example.com/account", {
  forms: [form({ action: "/account", method: "post" }, [field({ type: "password" })])]
});
assert.equal(passwordOnly.level, "safe");

const externalOnly = inspect("https://example.com/search", {
  forms: [form({ action: "https://example.net/search" }, [field({ type: "search", name: "q" })])]
});
assert.equal(externalOnly.level, "safe");

const insecureLogin = inspect("http://portal.example.com/login", {
  forms: [form({ action: "/session", method: "post" }, [field({ type: "password" })])]
});
assert.equal(insecureLogin.level, "suspicious");
assert.equal(insecureLogin.signals.insecure_credentials, true);

const externalCredentials = inspect("https://portal.example.com/login", {
  forms: [form({ action: "https://collector.example.net/session", method: "post" }, [
    field({ autocomplete: "username" }),
    field({ type: "password" })
  ])]
});
assert.equal(externalCredentials.level, "suspicious");
assert.equal(externalCredentials.signals.credential_external, true);

const brandArticle = inspect("https://news.example.net/story", {
  title: "Novidades da Microsoft",
  headings: ["Um artigo sobre tecnologia"]
});
assert.equal(brandArticle.level, "safe");
assert.equal(brandArticle.signals.brand_mismatch, false);

const brandImpersonation = inspect("https://secure.example.net/login", {
  title: "Microsoft — entrar",
  forms: [form({ action: "/session", method: "post" }, [field({ type: "password" })])]
});
assert.equal(brandImpersonation.level, "suspicious");
assert.equal(brandImpersonation.signals.brand_mismatch, true);

const officialBrand = inspect("https://login.microsoft.com/", {
  title: "Microsoft — entrar",
  forms: [form({ action: "/session", method: "post" }, [field({ type: "password" })])]
});
assert.equal(officialBrand.level, "safe");

const sensitiveExternal = inspect("https://shop.example.com/checkout", {
  forms: [form({ action: "https://processor.example.net/collect", method: "post" }, [
    field({ autocomplete: "cc-number" }),
    field({ autocomplete: "cc-csc" })
  ])]
});
assert.equal(sensitiveExternal.level, "suspicious");
assert.equal(sensitiveExternal.signals.sensitive_external, true);

const multiPart = parseFormDestination("https://collector.example.co.uk/send", {
  url: "https://shop.example.co.uk/checkout",
  protocol: "https:",
  registrable_domain: "example.co.uk"
});
assert.equal(multiPart.external, false);

for (const result of [legitimateLogin, insecureLogin, externalCredentials, brandImpersonation, sensitiveExternal]) {
  assert.notEqual(result.level, "blocked");
}

console.log("Análise pós-carregamento: OK");
