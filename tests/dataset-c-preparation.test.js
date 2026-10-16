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
const {
  verifyFrozenFiles,
  verifySealedDataset,
  scoreDistributionRows,
  errorSummaryRows
} = require("../scripts/evaluate-dataset-c.js");
const { validateRows } = require("../scripts/seal-dataset-c.js");
const {
  USER_AGENT,
  PHISHTANK_PUBLIC_URL,
  requestUrl,
  requestedSources,
  mergeManifestRecords
} = require("../scripts/collect-dataset-c-sources.js");

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "phishpect-dataset-c-"));
try {
  assert.match(USER_AGENT, /^Phishpect-validation\/0\.4/);
  assert.equal(requestUrl("phishtank", {}), PHISHTANK_PUBLIC_URL);
  const secret = "not-a-real-key";
  assert.ok(requestUrl("phishtank", { PHISHTANK_APP_KEY: secret }).includes(encodeURIComponent(secret)));
  assert.ok(!PHISHTANK_PUBLIC_URL.includes(secret));
  assert.deepEqual(requestedSources(["--sources=tranco,common_crawl_collections"]), ["tranco", "common_crawl_collections"]);
  const sourceManifestPath = path.join(temporary, "source-manifest.json");
  fs.writeFileSync(sourceManifestPath, JSON.stringify({ records: [
    { path: "raw/openphish-first.txt", sha256: "first", acquired_at: "2026-10-15T01:00:00.000Z" }
  ] }));
  assert.deepEqual(
    mergeManifestRecords(sourceManifestPath, [
      { path: "raw/openphish-second.txt", sha256: "second", acquired_at: "2026-10-15T13:00:00.000Z" }
    ]).map((record) => record.sha256),
    ["first", "second"]
  );
  fs.writeFileSync(sourceManifestPath, JSON.stringify({ records: [
    { path: "raw/openphish.txt", sha256: "same", acquired_at: "2026-10-15T01:00:00.000Z", etag: "known", acquisition: "downloaded" }
  ] }));
  assert.equal(mergeManifestRecords(sourceManifestPath, [
    { path: "raw/openphish.txt", sha256: "same", acquired_at: "2026-10-15T01:00:00.000Z", etag: null, acquisition: "preserved-existing" }
  ])[0].etag, "known");

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
  assert.deepEqual(scoreDistributionRows([
    { local_score: 0, label: "legitimate" },
    { local_score: 10, label: "phishing" },
    { local_score: 10, label: "legitimate" }
  ]), [
    { score: 0, legitimate: 1, phishing: 0, total: 1 },
    { score: 10, legitimate: 1, phishing: 1, total: 2 }
  ]);
  assert.deepEqual(errorSummaryRows([
    { label: "legitimate", final_classification: "safe" },
    { label: "legitimate", final_classification: "suspicious" },
    { label: "phishing", final_classification: "safe" },
    { label: "phishing", final_classification: "blocked" }
  ]), [
    { error_type: "false_positive", label: "legitimate", classification: "suspicious", count: 1, proportion_of_class: 0.5 },
    { error_type: "false_negative", label: "phishing", classification: "safe", count: 1, proportion_of_class: 0.5 }
  ]);

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
  const validationRows = candidateRows.map((row) => ({
    ...row,
    label: "legitimate",
    stratum: classifyLegitimate(row)
  }));
  const validationPhishing = Array.from({ length: 300 }, (_, index) => ({
    url: `https://phishing-${index}.test/path`,
    label: "phishing",
    source: "openphish",
    capture_id: index < 150 ? "capture-a" : "capture-b"
  }));
  const emptySets = { normalized: new Set(), hostPath: new Set() };
  const finalValidation = validateRows(validationRows, validationPhishing, {
    datasetAB: emptySets,
    historical: emptySets,
    reputation: createReputationDatabase({ urls: [], domains: [] })
  });
  assert.deepEqual(finalValidation.errors, []);
  assert.deepEqual(finalValidation.uniqueDomains, { legitimate: 300, phishing: 300 });
  assert.deepEqual(finalValidation.phishingComposition, { "capture-a": 150, "capture-b": 150 });
  assert.match(validateRows(validationRows, validationPhishing.slice(0, 299), {
    datasetAB: emptySets,
    historical: emptySets,
    reputation: createReputationDatabase({ urls: [], domains: [] })
  }).errors.join("\n"), /Classe phishing: 299\/300/);
  const sharedDomainPhishing = validationPhishing.map((row, index) => index === 0
    ? { ...row, url: validationRows[0].url }
    : row);
  assert.match(validateRows(validationRows, sharedDomainPhishing, {
    datasetAB: emptySets,
    historical: emptySets,
    reputation: createReputationDatabase({ urls: [], domains: [] })
  }).errors.join("\n"), /Domínios compartilhados entre classes: 1/);
  const legitimatePath = path.join(temporary, "legitimate.csv");
  const openPhishPath = path.join(temporary, "openphish.txt");
  const selectedPhishingPath = path.join(temporary, "selected-phishing.csv");
  const builtDatasetPath = path.join(temporary, "built-dataset-c.csv");
  const builtManifestPath = path.join(temporary, "manifest.json");
  const emptyHistory = path.join(temporary, "empty-history");
  const emptyReputation = path.join(temporary, "reputation.json");
  fs.mkdirSync(emptyHistory);
  fs.writeFileSync(legitimatePath, stringifyCsv(candidateRows, ["url", "source", "source_category"]));
  fs.writeFileSync(openPhishPath, `${Array.from({ length: 300 }, (_, index) => `https://openphish-${index}.test/path`).join("\n")}\n`);
  fs.writeFileSync(selectedPhishingPath, stringifyCsv(validationPhishing, [
    "url", "label", "source", "capture_id"
  ]));
  fs.writeFileSync(emptyReputation, JSON.stringify({ urls: [], domains: [] }));
  execFileSync(process.execPath, [
    path.resolve(__dirname, "../scripts/build-dataset-c.js"),
    `--legitimate=${legitimatePath}`,
    `--openphish=${openPhishPath}`,
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

  const sealedDatasetPath = path.join(temporary, "sealed-dataset-c.csv");
  const finalManifestPath = path.join(temporary, "sealed-manifest.json");
  const selectedLegitimatePath = path.join(temporary, "selected-legitimate.csv");
  fs.writeFileSync(selectedLegitimatePath, stringifyCsv(validationRows, [
    "url", "label", "source", "source_category", "stratum"
  ]));
  execFileSync(process.execPath, [
    path.resolve(__dirname, "../scripts/seal-dataset-c.js"),
    `--legitimate=${selectedLegitimatePath}`,
    `--phishing=${selectedPhishingPath}`,
    `--output=${sealedDatasetPath}`,
    `--manifest=${finalManifestPath}`,
    `--history=${emptyHistory}`,
    `--reputation=${emptyReputation}`,
    "--seed=synthetic-test-seed"
  ], { stdio: "pipe" });
  const finalManifest = JSON.parse(fs.readFileSync(finalManifestPath, "utf8"));
  assert.equal(finalManifest.status, "sealed-not-evaluated");
  assert.equal(finalManifest.detector_executed, false);
  assert.deepEqual(finalManifest.frozen_file_mismatches, []);
  assert.equal(finalManifest.dataset.total, 600);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

console.log("Preparação do Dataset C: OK");
