const fs = require("node:fs");
const path = require("node:path");
const { analyzeUrlV41 } = require("../../analysis-v41.js");
const { analyzePageV4 } = require("../../page-analysis-v4.js");
const { combineV41Evidence } = require("../../combined-analysis-v41.js");
const { createReputationDatabase, checkExternalReputation } = require("../../reputation.js");
const { parseCsv, writeCsv, metrics, sha256File, writeArtifactHashes } = require("../v4/evaluation-lib.js");

const label = process.argv.find((item) => item.startsWith("--iteration="))?.split("=")[1] || "candidate";
const root = path.resolve(__dirname, "../..");
const output = path.join(root, "evaluation", "results", "v4.1", "development", label);
const reputation = createReputationDatabase(JSON.parse(fs.readFileSync(path.join(root, "reputation/threat-db.json"), "utf8")));

function evaluateUrlDataset(name, relative) {
  const rows = parseCsv(fs.readFileSync(path.join(root, relative), "utf8")).map((row) => {
    const url = analyzeUrlV41(row.url);
    const reputationResult = checkExternalReputation(row.url, reputation);
    const result = combineV41Evidence(url, null, reputationResult);
    return { url: row.url, label: row.label, classification: result.finalClassification, score: result.score,
      decision_basis: result.INTEGRATION.decision_basis, categories: result.INTEGRATION.evidence_groups,
      relationships: result.INTEGRATION.relationships, signals: result.URL.signals, reasons: result.reasons };
  });
  writeCsv(path.join(output, `${name}-predictions.csv`), rows, Object.keys(rows[0]));
  return metrics(rows);
}

function evaluatePageCorpus() {
  const corpus = JSON.parse(fs.readFileSync(path.join(root, "evaluation/page-corpus/corpus-manifest.json"), "utf8"));
  const rows = corpus.samples.map((sample) => {
    const snapshotFile = path.join(root, "evaluation/results/page-analysis/development-v2/derived-snapshots", `${sample.sample_id}.json`);
    const snapshot = JSON.parse(fs.readFileSync(snapshotFile, "utf8"));
    const url = analyzeUrlV41(sample.url);
    const page = analyzePageV4(snapshot);
    const reputationResult = checkExternalReputation(sample.url, reputation);
    const result = combineV41Evidence(url, page, reputationResult);
    return { sample_id: sample.sample_id, url: sample.url, label: sample.label, classification: result.finalClassification,
      score: result.score, decision_basis: result.INTEGRATION.decision_basis, url_groups: url.evidence_groups,
      page_groups: page.evidence_groups, relationships: result.INTEGRATION.relationships,
      url_signals: url.signals, page_signals: page.signals, reasons: result.reasons, snapshot_sha256: sha256File(snapshotFile) };
  });
  writeCsv(path.join(output, "page-corpus-predictions.csv"), rows, Object.keys(rows[0]));
  return metrics(rows);
}

fs.mkdirSync(output, { recursive: true });
const summary = {
  status: "V4.1 development evaluation; not independent validation",
  iteration: label,
  executed_at: new Date().toISOString(),
  datasets: {
    A: evaluateUrlDataset("dataset-a", "evaluation/datasets/dataset-a.csv"),
    B: evaluateUrlDataset("dataset-b", "evaluation/datasets/dataset-b.csv"),
    C: evaluateUrlDataset("dataset-c", "evaluation/datasets/dataset-c.csv"),
    D: evaluateUrlDataset("dataset-d", "evaluation/datasets/dataset-d.csv"),
    page_corpus: evaluatePageCorpus()
  }
};
fs.writeFileSync(path.join(output, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
writeArtifactHashes(output);
console.log(JSON.stringify(summary.datasets, null, 2));
