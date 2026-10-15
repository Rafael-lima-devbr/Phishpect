const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { domainToASCII } = require("node:url");
const {
  sha256File,
  stringifyCsv,
  deterministicSort,
  classifyLegitimate,
  readHistoricalUrlSets,
  filterCandidates,
  selectByQuotas,
  wilsonInterval,
  calculateMetrics
} = require("../scripts/validation/dataset-c-lib.js");
const { createReputationDatabase } = require("../reputation.js");
const { verifyFrozenFiles, verifySealedDataset } = require("../scripts/evaluate-dataset-c.js");

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "phishpect-dataset-c-"));
try {
  const historyDirectory = path.join(temporary, "history");
  fs.mkdirSync(historyDirectory);
  fs.writeFileSync(path.join(historyDirectory, "old.csv"), "url,label\nhttps://old.example/login,phishing\n");
  const history = readHistoricalUrlSets(historyDirectory);
  const reputation = createReputationDatabase({ urls: [], domains: ["listed.example"] });
  const rows = [
    { url: "https://safe.example/internal/page", label: "legitimate", source: "test" },
    { url: "https://safe.example/internal/page?tracking=1", label: "legitimate", source: "test" },
    { url: "not-a-url", label: "legitimate", source: "test" },
    { url: "https://old.example/login", label: "legitimate", source: "test" },
    { url: "https://listed.example/page", label: "legitimate", source: "test" },
    { url: "https://login.example.net/account/signin", label: "legitimate", source: "test" }
  ];
  const filtered = filterCandidates(rows, {
    seed: "fixture-seed",
    history,
    reputation,
    onePerDomain: true
  });
  assert.equal(filtered.counters.invalid, 1);
  assert.equal(filtered.counters.duplicate_host_path, 1);
  assert.equal(filtered.counters.historical_overlap, 1);
  assert.equal(filtered.counters.reputation_overlap, 1);
  assert.equal(filtered.rows.length, 2);

  assert.equal(classifyLegitimate({ url: "https://tenant.github.io/login" }), "shared_hosting");
  assert.equal(classifyLegitimate({ url: "https://xn--bcher-kva.example/path" }), "idn_punycode");
  assert.equal(classifyLegitimate({ url: "https://shop.example/cart", source_category: "ecommerce" }), "commerce_finance");
  assert.equal(classifyLegitimate({ url: "https://example.com/account/verify" }), "authentication");
  assert.equal(classifyLegitimate({ url: "https://example.com/path?a=1&b=2&c=3" }), "long_or_query");
  assert.equal(classifyLegitimate({ url: "https://a-b-c123.example/path" }), "unusual_structure");
  assert.equal(classifyLegitimate({ url: "https://example.com/article" }), "internal_general");

  const orderedA = deterministicSort(rows, "same-seed").map((row) => row.url);
  const orderedB = deterministicSort([...rows].reverse(), "same-seed").map((row) => row.url);
  assert.deepEqual(orderedA, orderedB);
  const selected = selectByQuotas(filtered.rows, { internal_general: 1, authentication: 1 }, "stratum");
  assert.equal(selected.rows.length, 2);

  const interval = wilsonInterval(50, 100);
  assert.ok(interval.low < 0.5 && interval.high > 0.5);
  const metrics = calculateMetrics([
    { label: "phishing", result: "suspicious" },
    { label: "phishing", result: "safe" },
    { label: "legitimate", result: "suspicious" },
    { label: "legitimate", result: "safe" }
  ], "result");
  assert.deepEqual({ tp: metrics.tp, tn: metrics.tn, fp: metrics.fp, fn: metrics.fn }, { tp: 1, tn: 1, fp: 1, fn: 1 });

  assert.deepEqual(verifyFrozenFiles(path.resolve(__dirname, "..")), []);
  const sealedRows = [
    ...Array.from({ length: 300 }, (_, index) => ({ url: `https://legitimate-${index}.example/page`, label: "legitimate" })),
    ...Array.from({ length: 300 }, (_, index) => ({ url: `https://phishing-${index}.example/page`, label: "phishing" }))
  ];
  const datasetPath = path.join(temporary, "dataset-c.csv");
  fs.writeFileSync(datasetPath, stringifyCsv(sealedRows, ["url", "label"]));
  const sealed = verifySealedDataset(datasetPath, {
    status: "sealed-not-evaluated",
    dataset: { sha256: sha256File(datasetPath) }
  });
  assert.deepEqual(sealed.errors, []);

  const candidateRows = [];
  const addCandidates = (count, factory) => {
    for (let index = 0; index < count; index += 1) candidateRows.push(factory(index));
  };
  addCandidates(90, (index) => ({ url: `https://internal-${index}.example/article`, source: "synthetic" }));
  addCandidates(45, (index) => ({ url: `https://auth-${index}.example/account/login`, source: "synthetic" }));
  addCandidates(45, (index) => ({ url: `https://long-${index}.example/path?a=1&b=2&c=3`, source: "synthetic" }));
  addCandidates(45, (index) => ({ url: `https://tenant-${index}.github.io/page`, source: "synthetic" }));
  addCandidates(30, (index) => ({ url: `https://commerce-${index}.example/cart`, source: "synthetic", source_category: "ecommerce" }));
  addCandidates(15, (index) => ({ url: `https://${domainToASCII(`bücher${index}.example`)}/page`, source: "synthetic" }));
  addCandidates(30, (index) => ({ url: `https://a-b-c${index}.example/page`, source: "synthetic" }));
  const legitimatePath = path.join(temporary, "legitimate.csv");
  const openPhishPath = path.join(temporary, "openphish.txt");
  const phishTankPath = path.join(temporary, "phishtank.json");
  const builtDatasetPath = path.join(temporary, "built-dataset-c.csv");
  const builtManifestPath = path.join(temporary, "manifest.json");
  const emptyHistory = path.join(temporary, "empty-history");
  const emptyReputation = path.join(temporary, "reputation.json");
  fs.mkdirSync(emptyHistory);
  fs.writeFileSync(legitimatePath, stringifyCsv(candidateRows, ["url", "source", "source_category"]));
  fs.writeFileSync(openPhishPath, `${Array.from({ length: 150 }, (_, index) => `https://openphish-${index}.test/path`).join("\n")}\n`);
  fs.writeFileSync(phishTankPath, JSON.stringify(Array.from({ length: 150 }, (_, index) => ({
    url: `https://phishtank-${index}.test/path`, phish_id: index + 1, verified: "yes", online: "yes"
  }))));
  fs.writeFileSync(emptyReputation, JSON.stringify({ urls: [], domains: [] }));
  execFileSync(process.execPath, [
    path.resolve(__dirname, "../scripts/build-dataset-c.js"),
    `--legitimate=${legitimatePath}`,
    `--openphish=${openPhishPath}`,
    `--phishtank=${phishTankPath}`,
    `--output=${builtDatasetPath}`,
    `--manifest=${builtManifestPath}`,
    `--history=${emptyHistory}`,
    `--reputation=${emptyReputation}`,
    "--seed=synthetic-test-seed"
  ], { stdio: "pipe" });
  const builtRows = require("../scripts/validation/dataset-c-lib.js").parseCsv(fs.readFileSync(builtDatasetPath, "utf8"));
  assert.equal(builtRows.length, 600);
  assert.equal(builtRows.filter((row) => row.label === "legitimate").length, 300);
  assert.equal(builtRows.filter((row) => row.label === "phishing").length, 300);
  const verificationOutput = execFileSync(process.execPath, [
    path.resolve(__dirname, "../scripts/evaluate-dataset-c.js"),
    `--dataset=${builtDatasetPath}`,
    `--manifest=${builtManifestPath}`,
    `--output-dir=${path.join(temporary, "must-not-exist")}`
  ], { encoding: "utf8" });
  assert.match(verificationOutput, /verified-not-executed/);
  assert.equal(fs.existsSync(path.join(temporary, "must-not-exist")), false);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

console.log("Preparação do Dataset C: OK");
