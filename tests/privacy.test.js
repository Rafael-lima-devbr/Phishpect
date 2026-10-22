const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { collectPageSnapshot: collectV1Snapshot } = require("../page-analysis.js");
const { collectPageSnapshot: collectV2Snapshot } = require("../page-analysis-v2.js");
const { collectPageSnapshotV4 } = require("../page-analysis-v4.js");

const secret = "segredo-que-nao-pode-sair";
const sensitiveField = {
  tagName: "TEXTAREA",
  getAttribute(name) { return name === "name" ? "message" : null; },
  closest(selector) { return selector === "form" ? form : null; },
  get value() { throw new Error(secret); },
  textContent: secret
};
const form = {
  getAttribute() { return null; },
  closest() { return null; },
  querySelectorAll(selector) {
    if (selector === "input, textarea, select") return [sensitiveField];
    return [];
  }
};
const documentFixture = {
  title: "Contato",
  querySelectorAll(selector) {
    if (selector === "form") return [form];
    if (selector === "input, textarea, select") return [sensitiveField];
    return [];
  }
};
for (const collectPageSnapshot of [collectV1Snapshot, collectV2Snapshot, collectPageSnapshotV4]) {
  const snapshot = collectPageSnapshot(documentFixture, "https://example.com/contact");
  assert.equal(JSON.stringify(snapshot).includes(secret), false);
}

for (const file of ["page-analysis.js", "page-analysis-v2.js", "page-analysis-v4.js", "content.js", "background.js"]) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  assert.equal(/(?:input|textarea|field)\.value\b/.test(source), false, `${file} não pode ler valores digitados`);
  assert.equal(/outerHTML|innerHTML/.test(source), false, `${file} não pode serializar HTML bruto`);
}

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
assert.equal(JSON.stringify(manifest).includes("http://localhost"), false);
assert.equal(JSON.stringify(manifest).includes("https://localhost"), false);
assert.equal(Object.hasOwn(manifest, "externally_connectable"), false);

for (const file of ["background.js", "content.js"]) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const logCalls = [...source.matchAll(/console\.(?:warn|error|log)\(([^\n]*)\)/g)].map((match) => match[1]);
  assert.ok(logCalls.every((call) => /^"[^"]*"$/.test(call.trim())), `${file} deve usar apenas mensagens de log constantes`);
}

console.log("Privacidade: OK");
