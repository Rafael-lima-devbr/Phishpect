const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { analyzeUrlV4 } = require("../../analysis-v4.js");
const { createReputationDatabase, checkExternalReputation } = require("../../reputation.js");
const { combineV4Evidence } = require("../../combined-analysis-v4.js");
const { parseCsv, writeCsv, metrics, sha256File, writeArtifactHashes } = require("./evaluation-lib.js");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(ROOT, "evaluation", "results", "v4", "development", "url-regression");
const DATASETS = ["dataset-a.csv", "dataset-b.csv", "dataset-c.csv"];

function main() {
  fs.mkdirSync(OUTPUT, { recursive: true });
  const reputationPath = path.join(ROOT, "reputation", "threat-db.json");
  const reputation = createReputationDatabase(JSON.parse(fs.readFileSync(reputationPath, "utf8")));
  const summary = [];
  for (const fileName of DATASETS) {
    const inputPath = path.join(ROOT, "evaluation", "datasets", fileName);
    const rows = parseCsv(fs.readFileSync(inputPath, "utf8"));
    const predictions = rows.map((row) => {
      const url = analyzeUrlV4(row.url);
      const reputationResult = checkExternalReputation(row.url, reputation);
      const complete = combineV4Evidence(url, null, reputationResult);
      return {
        url: row.url,
        label: row.label,
        classification: complete.finalClassification,
        score: complete.score,
        url_level: url.level,
        url_score: url.score,
        evidence_groups: url.evidence_groups,
        relationships: url.relationships,
        signals: url.signals,
        reasons: complete.reasons,
        reputation_available: reputationResult.available,
        reputation_listed: reputationResult.listed,
        reputation_match_type: reputationResult.matchType
      };
    });
    const datasetName = path.basename(fileName, ".csv");
    writeCsv(path.join(OUTPUT, `${datasetName}-predictions.csv`), predictions, [
      "url", "label", "classification", "score", "url_level", "url_score",
      "evidence_groups", "relationships", "signals", "reasons",
      "reputation_available", "reputation_listed", "reputation_match_type"
    ]);
    const result = {
      dataset: datasetName,
      role: "development-regression-url-only; not independent V4 validation",
      input_sha256: sha256File(inputPath),
      ...metrics(predictions)
    };
    fs.writeFileSync(path.join(OUTPUT, `${datasetName}-metrics.json`), `${JSON.stringify(result, null, 2)}\n`);
    summary.push(result);
  }
  const run = {
    status: "development-regression-complete",
    independent_validation: false,
    executed_at: new Date().toISOString(),
    timezone: "America/Bahia",
    node: process.version,
    platform: { type: os.type(), release: os.release(), architecture: os.arch() },
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    detector_hashes: Object.fromEntries([
      "analysis-v4.js", "combined-analysis-v4.js", "reputation.js", "reputation/threat-db.json"
    ].map((relative) => [relative, sha256File(path.join(ROOT, relative))])),
    engineering_history: [
      {
        status: "rejected",
        reason: "Eligibility required excessive diversity and caused an unacceptable recall collapse.",
        confusion_matrices: {
          dataset_a: { TP: 10, TN: 100, FP: 0, FN: 90 },
          dataset_b: { TP: 14, TN: 100, FP: 0, FN: 86 },
          dataset_c: { TP: 84, TN: 300, FP: 0, FN: 216 }
        }
      },
      {
        status: "rejected",
        reason: "Structural recovery exposed an OAuth redirect false positive in the synthetic suite; the general OAuth/SSO context was corrected before acceptance.",
        confusion_matrices: {
          dataset_a: { TP: 19, TN: 100, FP: 0, FN: 81 },
          dataset_b: { TP: 19, TN: 100, FP: 0, FN: 81 },
          dataset_c: { TP: 171, TN: 298, FP: 2, FN: 129 }
        }
      }
    ],
    summary
  };
  fs.writeFileSync(path.join(OUTPUT, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  writeArtifactHashes(OUTPUT);
  console.log(JSON.stringify(summary, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
