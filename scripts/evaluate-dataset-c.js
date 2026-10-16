const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const reference = require("./validation/frozen-reference.js");
const {
  DEFAULT_SEED,
  sha256File,
  parseCsv,
  stringifyCsv,
  calculateMetrics,
  loadReputation
} = require("./validation/dataset-c-lib.js");
const { csvFiles, urlSets } = require("./filter-dataset-c-candidates.js");
const { validateRows } = require("./seal-dataset-c.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function verifyFrozenFiles(repositoryRoot) {
  const mismatches = [];
  for (const [relativePath, expected] of Object.entries(reference.files)) {
    const absolutePath = path.join(repositoryRoot, relativePath);
    const actual = fs.existsSync(absolutePath) ? sha256File(absolutePath) : null;
    if (actual !== expected) mismatches.push({ path: relativePath, expected, actual });
  }
  return mismatches;
}

function verifySealedDataset(datasetPath, manifest) {
  const rows = parseCsv(fs.readFileSync(datasetPath, "utf8"));
  const actualHash = sha256File(datasetPath);
  const errors = [];
  if (manifest.status !== "sealed-not-evaluated") errors.push("Manifesto não está marcado como sealed-not-evaluated");
  if (actualHash !== manifest.dataset?.sha256) errors.push("Hash do Dataset C diverge do manifesto");
  if (rows.length !== 600 || rows.filter((row) => row.label === "legitimate").length !== 300 || rows.filter((row) => row.label === "phishing").length !== 300) {
    errors.push("Dataset C precisa conter exatamente 300 legítimas e 300 phishing");
  }
  return { rows, actualHash, errors };
}

function increment(counter, value) {
  const key = String(value);
  counter[key] = (counter[key] || 0) + 1;
}

function scoreDistributionRows(records) {
  const scores = [...new Set(records.map((record) => Number(record.local_score)))].sort((left, right) => left - right);
  return scores.map((score) => {
    const atScore = records.filter((record) => Number(record.local_score) === score);
    const legitimate = atScore.filter((record) => record.label === "legitimate").length;
    const phishing = atScore.filter((record) => record.label === "phishing").length;
    return { score, legitimate, phishing, total: legitimate + phishing };
  });
}

function errorSummaryRows(records) {
  const definitions = [
    ["false_positive", "legitimate", (record) => record.final_classification !== "safe"],
    ["false_negative", "phishing", (record) => record.final_classification === "safe"]
  ];
  return definitions.flatMap(([errorType, label, predicate]) => {
    const classRows = records.filter((record) => record.label === label);
    const errors = classRows.filter(predicate);
    const byClassification = [...new Set(errors.map((record) => record.final_classification))].sort();
    if (!byClassification.length) {
      return [{ error_type: errorType, label, classification: "", count: 0, proportion_of_class: 0 }];
    }
    return byClassification.map((classification) => {
      const count = errors.filter((record) => record.final_classification === classification).length;
      return { error_type: errorType, label, classification, count, proportion_of_class: count / classRows.length };
    });
  });
}

function repositoryHead(repositoryRoot) {
  return execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help")) {
    console.log("Uso oficial: node scripts/evaluate-dataset-c.js --dataset=evaluation/datasets/dataset-c.csv --manifest=evaluation/sources/dataset-c/manifest.json --output-dir=evaluation/results/dataset-c/official --confirm-official");
    return;
  }
  const datasetPath = option(argv, "dataset");
  const manifestPath = option(argv, "manifest");
  const outputDirectory = option(argv, "output-dir", "evaluation/results/dataset-c/official");
  if (!datasetPath || !manifestPath) throw new Error("Use --dataset=CSV e --manifest=JSON");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const repositoryRoot = path.resolve(__dirname, "..");
  const expectedDatasetHash = option(argv, "expected-dataset-sha256");
  const expectedSeed = option(argv, "expected-seed", manifest.seed || DEFAULT_SEED);
  const frozenMismatches = verifyFrozenFiles(repositoryRoot);
  const sealed = verifySealedDataset(datasetPath, manifest);
  const evaluationRoot = path.join(repositoryRoot, "evaluation");
  const abFiles = [
    path.join(evaluationRoot, "datasets", "dataset-a.csv"),
    path.join(evaluationRoot, "datasets", "dataset-b.csv")
  ].filter(fs.existsSync);
  const abResolved = new Set(abFiles.map((file) => path.resolve(file).toLowerCase()));
  const historicalFiles = csvFiles(evaluationRoot).filter((file) => !abResolved.has(path.resolve(file).toLowerCase()));
  const actualValidation = validateRows(
    sealed.rows.filter((row) => row.label === "legitimate"),
    sealed.rows.filter((row) => row.label === "phishing"),
    {
      datasetAB: urlSets(abFiles),
      historical: urlSets(historicalFiles),
      reputation: loadReputation(path.join(repositoryRoot, "reputation", "threat-db.json"))
    }
  );
  if (manifest.seed !== expectedSeed) sealed.errors.push(`Seed divergente: ${manifest.seed || "ausente"}`);
  if (expectedDatasetHash && sealed.actualHash !== expectedDatasetHash) sealed.errors.push("SHA-256 não corresponde ao valor esperado na autorização oficial");
  sealed.errors.push(...actualValidation.errors);
  const verification = {
    detector_reference: reference.commit,
    dataset_sha256: sealed.actualHash,
    dataset_errors: sealed.errors,
    frozen_file_mismatches: frozenMismatches,
    seed: manifest.seed,
    final_overlaps: actualValidation.overlaps,
    unique_domains: actualValidation.uniqueDomains,
    shared_domains_between_classes: actualValidation.sharedDomains.length
  };
  if (sealed.errors.length || frozenMismatches.length) {
    console.error(JSON.stringify(verification, null, 2));
    process.exitCode = 2;
    return;
  }
  if (!argv.includes("--confirm-official")) {
    console.log(JSON.stringify({
      status: "verified-not-executed",
      message: "O detector não foi chamado. A avaliação exige autorização e --confirm-official.",
      ...verification
    }, null, 2));
    return;
  }
  if (fs.existsSync(outputDirectory) && fs.readdirSync(outputDirectory).length) {
    throw new Error("Diretório oficial já contém resultados; a execução não será sobrescrita");
  }

  // Carregamento deliberadamente posterior à confirmação e a todas as verificações.
  const { analyzeUrl } = require("../analysis.js");
  const { checkExternalReputation } = require("../reputation.js");
  const reputation = loadReputation(path.join(repositoryRoot, "reputation", "threat-db.json"));
  const records = sealed.rows.map((row) => {
    const local = analyzeUrl(row.url);
    const external = checkExternalReputation(row.url, reputation);
    return {
      ...row,
      local_score: local.score,
      local_classification: local.level,
      local_reasons: JSON.stringify(local.reasons || []),
      local_contributions: JSON.stringify(local.contributions || []),
      local_category_scores: JSON.stringify(local.category_scores || {}),
      local_evidence_categories: JSON.stringify(local.evidence_categories || []),
      local_diversity_bonus: local.diversity_bonus || 0,
      local_signals: JSON.stringify(local.signals || {}),
      local_features: JSON.stringify(local.features || null),
      reputation_available: external.available,
      reputation_listed: external.listed,
      reputation_source: external.source,
      reputation_match_type: external.matchType || "",
      final_classification: external.listed ? "blocked" : local.level
    };
  });
  const scoreDistribution = {}, categories = {}, reasons = {};
  const categoriesByLabel = { legitimate: {}, phishing: {} };
  const reasonsByLabel = { legitimate: {}, phishing: {} };
  const classificationsByLabel = { legitimate: {}, phishing: {} };
  for (const record of records) {
    increment(scoreDistribution, record.local_score);
    increment(classificationsByLabel[record.label], record.final_classification);
    for (const category of JSON.parse(record.local_evidence_categories)) {
      increment(categories, category);
      increment(categoriesByLabel[record.label], category);
    }
    for (const reason of JSON.parse(record.local_reasons)) {
      increment(reasons, reason);
      increment(reasonsByLabel[record.label], reason);
    }
  }
  const metrics = {
    local_only: calculateMetrics(records, "local_classification"),
    local_plus_frozen_reputation: calculateMetrics(records, "final_classification")
  };
  const columns = Object.keys(records[0]);
  const scoreRows = scoreDistributionRows(records);
  const errorRows = errorSummaryRows(records);
  fs.mkdirSync(outputDirectory, { recursive: true });
  const outputPaths = {
    predictions: path.join(outputDirectory, "predictions.csv"),
    falsePositives: path.join(outputDirectory, "false-positives.csv"),
    falseNegatives: path.join(outputDirectory, "false-negatives.csv"),
    metrics: path.join(outputDirectory, "metrics.json"),
    scoreDistribution: path.join(outputDirectory, "score-distribution.csv"),
    errorSummary: path.join(outputDirectory, "error-summary.csv"),
    run: path.join(outputDirectory, "run.json"),
    artifactHashes: path.join(outputDirectory, "artifact-hashes.json")
  };
  fs.writeFileSync(outputPaths.predictions, stringifyCsv(records, columns));
  fs.writeFileSync(outputPaths.falsePositives, stringifyCsv(records.filter((row) => row.label === "legitimate" && row.final_classification !== "safe"), columns));
  fs.writeFileSync(outputPaths.falseNegatives, stringifyCsv(records.filter((row) => row.label === "phishing" && row.final_classification === "safe"), columns));
  fs.writeFileSync(outputPaths.scoreDistribution, stringifyCsv(scoreRows, ["score", "legitimate", "phishing", "total"]));
  fs.writeFileSync(outputPaths.errorSummary, stringifyCsv(errorRows, ["error_type", "label", "classification", "count", "proportion_of_class"]));
  fs.writeFileSync(outputPaths.metrics, `${JSON.stringify({
    metrics,
    score_distribution: scoreDistribution,
    categories,
    categories_by_label: categoriesByLabel,
    reasons,
    reasons_by_label: reasonsByLabel,
    classifications_by_label: classificationsByLabel,
    balanced_dataset_notice: "Dataset C has a fixed 50/50 class balance; precision and accuracy do not estimate web prevalence performance."
  }, null, 2)}\n`);
  const run = {
    schema_version: 1,
    status: "official-complete",
    executed_at: new Date().toISOString(),
    timezone: reference.timezone,
    detector_reference: reference,
    dataset_sha256: sealed.actualHash,
    manifest_sha256: sha256File(manifestPath),
    repository_head: repositoryHead(repositoryRoot),
    command: process.argv.map((value) => JSON.stringify(value)).join(" "),
    environment: {
      node: process.version,
      platform: process.platform,
      release: os.release(),
      architecture: process.arch,
      cpu: os.cpus()[0]?.model || null,
      ram_bytes: os.totalmem()
    },
    parameters: { output_directory: outputDirectory, expected_dataset_sha256: expectedDatasetHash, expected_seed: expectedSeed },
    verification,
    outputs: [
      "predictions.csv", "false-positives.csv", "false-negatives.csv", "metrics.json",
      "score-distribution.csv", "error-summary.csv", "artifact-hashes.json"
    ]
  };
  fs.writeFileSync(outputPaths.run, `${JSON.stringify(run, null, 2)}\n`);
  const artifactHashes = Object.fromEntries(Object.values(outputPaths)
    .filter((file) => file !== outputPaths.artifactHashes)
    .map((file) => [path.basename(file), { sha256: sha256File(file), bytes: fs.statSync(file).size }]));
  fs.writeFileSync(outputPaths.artifactHashes, `${JSON.stringify({
    schema_version: 1,
    created_at: new Date().toISOString(),
    dataset_sha256: sealed.actualHash,
    artifacts: artifactHashes
  }, null, 2)}\n`);
  console.log(JSON.stringify({ status: run.status, metrics, output_directory: outputDirectory }, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { verifyFrozenFiles, verifySealedDataset, scoreDistributionRows, errorSummaryRows, repositoryHead };
