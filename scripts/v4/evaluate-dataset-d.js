const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { analyzeUrlV4 } = require("../../analysis-v4.js");
const { combineV4Evidence } = require("../../combined-analysis-v4.js");
const { createReputationDatabase, checkExternalReputation } = require("../../reputation.js");
const { parseCsv, writeCsv, metrics, sha256File, writeArtifactHashes } = require("./evaluation-lib.js");
const reference = require("./frozen-reference.js");

const datasetPath = "evaluation/datasets/dataset-d.csv";
const manifestPath = "evaluation/sources/dataset-d/manifest.json";
const output = "evaluation/results/v4/dataset-d/official";
function verify() {
  if (!process.argv.includes("--confirm-official")) throw new Error("Avaliação recusada sem --confirm-official");
  if (!fs.existsSync(datasetPath) || !fs.existsSync(manifestPath)) throw new Error("Dataset D não selado");
  if (fs.existsSync(output)) throw new Error("Resultado oficial já existe; execução única preservada");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.status !== "sealed-not-evaluated" || manifest.detector_executed !== false) throw new Error("Estado do manifesto inválido");
  if (sha256File(datasetPath) !== manifest.dataset.sha256) throw new Error("Hash do Dataset D divergiu");
  const rows = parseCsv(fs.readFileSync(datasetPath, "utf8"));
  if (rows.length !== 200 || rows.filter((row) => row.label === "legitimate").length !== 100 || rows.filter((row) => row.label === "phishing").length !== 100) throw new Error("Composição inválida");
  for (const [file, expected] of Object.entries(reference.files)) if (sha256File(file) !== expected) throw new Error(`Detector congelado divergiu: ${file}`);
  return { manifest, rows };
}
function main() {
  const { manifest, rows } = verify();
  const reputation = createReputationDatabase(JSON.parse(fs.readFileSync("reputation/threat-db.json", "utf8")));
  const predictions = rows.map((row, index) => {
    const url = analyzeUrlV4(row.url); const rep = checkExternalReputation(row.url, reputation); const result = combineV4Evidence(url, null, rep);
    return { sample_id: `D-${String(index + 1).padStart(3, "0")}`, url: row.url, label: row.label, source: row.source,
      stratum: row.stratum, classification: result.finalClassification, score: result.score,
      decision_basis: result.INTEGRATION.decision_basis, categories: JSON.stringify(result.INTEGRATION.evidence_groups),
      signals: JSON.stringify(result.URL.signals), reasons: JSON.stringify(result.reasons), reputation_available: rep.available,
      reputation_listed: rep.listed, reputation_match_type: rep.matchType || "" };
  });
  fs.mkdirSync(output, { recursive: false });
  writeCsv(path.join(output, "predictions.csv"), predictions, Object.keys(predictions[0]));
  const resultMetrics = metrics(predictions);
  fs.writeFileSync(path.join(output, "metrics.json"), `${JSON.stringify(resultMetrics, null, 2)}\n`);
  const errors = predictions.filter((row) => (row.label === "phishing") === (row.classification === "safe"));
  writeCsv(path.join(output, "errors.csv"), errors, Object.keys(predictions[0]));
  const scoreCounts = Object.entries(predictions.reduce((out, row) => (out[row.score] = (out[row.score] || 0) + 1, out), {})).map(([score, count]) => ({ score, count }));
  writeCsv(path.join(output, "score-distribution.csv"), scoreCounts, ["score", "count"]);
  const run = { status: "official-independent-validation-complete", executed_once: true, executed_at: new Date().toISOString(), timezone: "America/Bahia",
    command: "node scripts/v4/evaluate-dataset-d.js --confirm-official", node: process.version, platform: { type: os.type(), release: os.release(), architecture: os.arch() },
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(), detector_reference: reference,
    dataset_sha256: manifest.dataset.sha256, dataset_manifest_sha256: sha256File(manifestPath), configuration: "V4 initial integrated decision: URL + frozen local reputation; no artificial page snapshot" };
  fs.writeFileSync(path.join(output, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  writeArtifactHashes(output);
  manifest.status = "evaluated-once"; manifest.detector_executed = true; manifest.official_result = { path: output.replaceAll("\\", "/"), executed_at: run.executed_at, metrics_sha256: sha256File(path.join(output, "metrics.json")) };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(resultMetrics, null, 2));
}
try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
