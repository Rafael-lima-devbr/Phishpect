const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { analyzeUrlV4 } = require("../../analysis-v4.js");
const { analyzePageV4 } = require("../../page-analysis-v4.js");
const { combineV4Evidence } = require("../../combined-analysis-v4.js");
const { createReputationDatabase, checkExternalReputation } = require("../../reputation.js");
const { writeCsv, metrics, sha256File, writeArtifactHashes } = require("./evaluation-lib.js");

const ROOT = path.resolve(__dirname, "../..");
const CORPUS = path.join(ROOT, "evaluation", "page-corpus", "corpus-manifest.json");
const OUTPUT = path.join(ROOT, "evaluation", "results", "v4", "development", "page-regression");

function emptyUrl() {
  return { version: "4.0", level: "safe", score: 0, reasons: [], signals: {}, evidence_groups: [], relationships: [] };
}

function main() {
  fs.mkdirSync(OUTPUT, { recursive: true });
  const corpus = JSON.parse(fs.readFileSync(CORPUS, "utf8"));
  if (corpus.corpus_sha256 !== "29574db70b518a4efffafca3d0451b4d3eae26c9d6abe283be54d9030479adab") {
    throw new Error("Corpus histórico inesperado");
  }
  const reputation = createReputationDatabase(JSON.parse(fs.readFileSync(path.join(ROOT, "reputation", "threat-db.json"), "utf8")));
  const predictions = corpus.samples.map((sample) => {
    const snapshotPath = path.join(ROOT, "evaluation", "results", "page-analysis", "development-v2", "derived-snapshots", `${sample.sample_id}.json`);
    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
    const url = analyzeUrlV4(sample.url);
    const page = analyzePageV4(snapshot);
    const reputationResult = checkExternalReputation(sample.url, reputation);
    const complete = combineV4Evidence(url, page, reputationResult);
    const urlAndReputation = combineV4Evidence(url, null, reputationResult);
    const urlAndPage = combineV4Evidence(url, page, { listed: false, available: false });
    const pageOnly = combineV4Evidence(emptyUrl(), page, { listed: false, available: false });
    const reputationOnly = combineV4Evidence(emptyUrl(), null, reputationResult);
    return {
      sample_id: sample.sample_id,
      label: sample.label,
      url: sample.url,
      snapshot_sha256: sha256File(snapshotPath),
      classification: complete.finalClassification,
      score: complete.score,
      url_only: url.level,
      page_only: pageOnly.finalClassification,
      reputation_only: reputationOnly.finalClassification,
      url_reputation: urlAndReputation.finalClassification,
      url_page: urlAndPage.finalClassification,
      complete_v4: complete.finalClassification,
      url_groups: url.evidence_groups,
      page_groups: page.evidence_groups,
      integration_relationships: complete.INTEGRATION.relationships,
      url_signals: url.signals,
      page_signals: page.signals,
      reasons: complete.reasons
    };
  });
  writeCsv(path.join(OUTPUT, "predictions.csv"), predictions, [
    "sample_id", "label", "url", "snapshot_sha256", "classification", "score",
    "url_only", "page_only", "reputation_only", "url_reputation", "url_page", "complete_v4",
    "url_groups", "page_groups", "integration_relationships", "url_signals", "page_signals", "reasons"
  ]);
  const modalities = ["url_only", "page_only", "reputation_only", "url_reputation", "url_page", "complete_v4"];
  const ablation = Object.fromEntries(modalities.map((modality) => [modality, metrics(predictions, modality)]));
  fs.writeFileSync(path.join(OUTPUT, "ablation-metrics.json"), `${JSON.stringify({
    status: "development-ablation",
    independent_validation: false,
    corpus_sha256: corpus.corpus_sha256,
    ablation
  }, null, 2)}\n`);
  const run = {
    status: "development-page-regression-complete",
    independent_validation: false,
    executed_at: new Date().toISOString(),
    timezone: "America/Bahia",
    node: process.version,
    platform: { type: os.type(), release: os.release(), architecture: os.arch() },
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    corpus_sha256: corpus.corpus_sha256,
    limitations: [
      "Snapshots are static and do not reproduce the V4 late DOM observation.",
      "Scripts, iframes, Shadow DOM and network-loaded content remain inert.",
      "This known corpus is development/regression data for V4."
    ],
    detector_hashes: Object.fromEntries([
      "analysis-v4.js", "page-analysis-v4.js", "combined-analysis-v4.js", "reputation.js"
    ].map((relative) => [relative, sha256File(path.join(ROOT, relative))]))
  };
  fs.writeFileSync(path.join(OUTPUT, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  writeArtifactHashes(OUTPUT);
  console.log(JSON.stringify(ablation, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
