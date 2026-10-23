const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const reference = require("../scripts/v4/frozen-reference.js");

const root = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

assert.equal(manifest.version, "0.5.1");
assert.equal(manifest.background.service_worker, "background-v41.js");
assert.ok(manifest.content_scripts[0].js.includes("analysis-v41.js"));
assert.ok(manifest.content_scripts[0].js.includes("content-v41.js"));
assert.equal(manifest.content_scripts[0].js.includes("content.js"), false);

const background = fs.readFileSync(path.join(root, "background-v41.js"), "utf8");
assert.ok(background.includes('"analysis-v4.js", "analysis-v41.js"'));
assert.ok(background.includes('"combined-analysis-v4.js", "combined-analysis-v41.js"'));
assert.ok(background.includes("analyzeUrlV41(url)"));
assert.ok(background.includes("combineV41Evidence"));

for (const [file, expected] of Object.entries(reference.files)) {
  const bytes = fs.readFileSync(path.join(root, file));
  assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), expected, `${file} histórico deve permanecer intacto`);
}

console.log("Runtime e integridade histórica da V4.1: OK");
