const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const reference = require("./validation/frozen-reference.js");
const {
  sha256File,
  parseCsv,
  stringifyCsv,
  calculateMetrics,
  loadReputation
} = require("./validation/dataset-c-lib.js");

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
  const frozenMismatches = verifyFrozenFiles(repositoryRoot);
  const sealed = verifySealedDataset(datasetPath, manifest);
  const verification = {
    detector_reference: reference.commit,
    dataset_sha256: sealed.actualHash,
    dataset_errors: sealed.errors,
    frozen_file_mismatches: frozenMismatches
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
  for (const record of records) {
    increment(scoreDistribution, record.local_score);
    for (const category of JSON.parse(record.local_evidence_categories)) increment(categories, category);
    for (const reason of JSON.parse(record.local_reasons)) increment(reasons, reason);
  }
  const metrics = {
    local_only: calculateMetrics(records, "local_classification"),
    local_plus_frozen_reputation: calculateMetrics(records, "final_classification")
  };
  const columns = Object.keys(records[0]);
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(path.join(outputDirectory, "predictions.csv"), stringifyCsv(records, columns));
  fs.writeFileSync(path.join(outputDirectory, "false-positives.csv"), stringifyCsv(records.filter((row) => row.label === "legitimate" && row.local_classification !== "safe"), columns));
  fs.writeFileSync(path.join(outputDirectory, "false-negatives.csv"), stringifyCsv(records.filter((row) => row.label === "phishing" && row.local_classification === "safe"), columns));
  fs.writeFileSync(path.join(outputDirectory, "metrics.json"), `${JSON.stringify({ metrics, score_distribution: scoreDistribution, categories, reasons }, null, 2)}\n`);
  const run = {
    schema_version: 1,
    status: "official-complete",
    executed_at: new Date().toISOString(),
    timezone: reference.timezone,
    detector_reference: reference,
    dataset_sha256: sealed.actualHash,
    manifest_sha256: sha256File(manifestPath),
    command: process.argv.map((value) => JSON.stringify(value)).join(" "),
    environment: {
      node: process.version,
      platform: process.platform,
      release: os.release(),
      architecture: process.arch,
      cpu: os.cpus()[0]?.model || null,
      ram_bytes: os.totalmem()
    },
    parameters: { output_directory: outputDirectory },
    outputs: ["predictions.csv", "false-positives.csv", "false-negatives.csv", "metrics.json"]
  };
  fs.writeFileSync(path.join(outputDirectory, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  console.log(JSON.stringify({ status: run.status, metrics, output_directory: outputDirectory }, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { verifyFrozenFiles, verifySealedDataset };
