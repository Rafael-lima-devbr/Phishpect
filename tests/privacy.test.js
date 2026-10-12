const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { collectPageSnapshot } = require("../page-analysis.js");

const secret = "segredo-que-nao-pode-sair";
const sensitiveField = {
  tagName: "TEXTAREA",
  getAttribute(name) { return name === "name" ? "message" : null; },
  get value() { throw new Error(secret); },
  textContent: secret
};
const form = {
  getAttribute() { return null; },
  querySelectorAll() { return [sensitiveField]; }
};
const documentFixture = {
  title: "Contato",
  querySelectorAll(selector) {
    if (selector === "form") return [form];
    return [];
  }
};
const snapshot = collectPageSnapshot(documentFixture, "https://example.com/contact");
assert.equal(JSON.stringify(snapshot).includes(secret), false);

for (const file of ["background.js", "content.js"]) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const logCalls = [...source.matchAll(/console\.(?:warn|error|log)\(([^\n]*)\)/g)].map((match) => match[1]);
  assert.ok(logCalls.every((call) => /^"[^"]*"$/.test(call.trim())), `${file} deve usar apenas mensagens de log constantes`);
}

console.log("Privacidade: OK");
