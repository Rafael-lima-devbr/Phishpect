const assert = require("node:assert/strict");
const fs = require("node:fs");
const { parseCsv, sha256File } = require("../scripts/v4/evaluation-lib.js");
const { hostPathIdentity, registrableDomain } = require("../scripts/validation/dataset-c-lib.js");
const { normalizeUrlForReputation } = require("../reputation.js");
const reference = require("../scripts/v4/frozen-reference.js");

const datasetPath = "evaluation/datasets/dataset-d.csv";
const manifestPath = "evaluation/sources/dataset-d/manifest.json";
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const rows = parseCsv(fs.readFileSync(datasetPath, "utf8"));
assert.equal(rows.length, 200);
assert.equal(rows.filter((row) => row.label === "legitimate").length, 100);
assert.equal(rows.filter((row) => row.label === "phishing").length, 100);
assert.equal(sha256File(datasetPath), manifest.dataset.sha256);
assert.ok(["sealed-not-evaluated", "evaluated-once"].includes(manifest.status));

const legitimateDomains = new Set(rows.filter((row) => row.label === "legitimate").map((row) => registrableDomain(new URL(row.url))));
const phishingDomains = new Set(rows.filter((row) => row.label === "phishing").map((row) => registrableDomain(new URL(row.url))));
assert.equal(legitimateDomains.size, 100); assert.equal(phishingDomains.size, 100);
assert.equal([...legitimateDomains].filter((domain) => phishingDomains.has(domain)).length, 0);

const historical = ["dataset-a.csv", "dataset-b.csv", "dataset-c.csv"].flatMap((name) => parseCsv(fs.readFileSync(`evaluation/datasets/${name}`, "utf8")));
const exact = new Set(historical.map((row) => normalizeUrlForReputation(row.url)).filter(Boolean));
const hostPath = new Set(historical.map((row) => hostPathIdentity(row.url)).filter(Boolean));
assert.equal(rows.filter((row) => exact.has(normalizeUrlForReputation(row.url))).length, 0);
assert.equal(rows.filter((row) => hostPath.has(hostPathIdentity(row.url))).length, 0);
for (const [file, expected] of Object.entries(reference.files)) assert.equal(sha256File(file), expected, file);
console.log("Dataset D e referência congelada: OK");
