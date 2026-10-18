const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { analyzePage } = require("../../page-analysis-v2.js");
const { combineAnalyses } = require("../../combined-analysis.js");
const frozenReference = require("../validation/frozen-reference.js");

const ROOT = path.resolve(__dirname, "../..");
const CORPUS_ROOT = path.join(ROOT, "evaluation", "page-corpus");
const CORPUS_MANIFEST = path.join(CORPUS_ROOT, "corpus-manifest.json");
const OLD_RESULTS = path.join(ROOT, "evaluation", "results", "page-analysis", "official");
const OUTPUT = path.join(ROOT, "evaluation", "results", "page-analysis", "development-v2");
const SNAPSHOT_MANIFEST = path.join(OUTPUT, "snapshot-manifest.json");
const EXPECTED_CORPUS_HASH = "29574db70b518a4efffafca3d0451b4d3eae26c9d6abe283be54d9030479adab";

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function csvCell(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(fileName, columns, rows) {
  const lines = [columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))];
  fs.writeFileSync(path.join(OUTPUT, fileName), `${lines.join("\n")}\n`);
}

function parseCsv(content) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index];
    if (quoted) {
      if (character === '"' && content[index + 1] === '"') {
        value += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        value += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(value);
      value = "";
    } else if (character === "\n") {
      row.push(value.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      value = "";
    } else {
      value += character;
    }
  }
  if (value || row.length) {
    row.push(value);
    rows.push(row);
  }
  const [headers, ...records] = rows;
  return records.filter((record) => record.some(Boolean)).map((record) => Object.fromEntries(headers.map((header, index) => [header, record[index] ?? ""])));
}

function readCsv(fileName) {
  return parseCsv(fs.readFileSync(path.join(OLD_RESULTS, fileName), "utf8"));
}

function jsonValue(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function isPositive(classification) {
  return classification === "suspicious" || classification === "blocked";
}

function outcome(label, classification) {
  if (label === "phishing") return isPositive(classification) ? "TP" : "FN";
  return isPositive(classification) ? "FP" : "TN";
}

function wilson(successes, total, z = 1.959963984540054) {
  if (!total) return { estimate: null, lower: null, upper: null, confidence: 0.95, method: "Wilson" };
  const proportion = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (proportion + (z * z) / (2 * total)) / denominator;
  const margin = (z * Math.sqrt((proportion * (1 - proportion) / total) + (z * z) / (4 * total * total))) / denominator;
  return { estimate: proportion, lower: Math.max(0, center - margin), upper: Math.min(1, center + margin), confidence: 0.95, method: "Wilson" };
}

function metricsFor(rows, key) {
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const classifications = { safe: 0, suspicious: 0, blocked: 0 };
  for (const row of rows) {
    const classification = row[key].classification;
    counts[outcome(row.label, classification)] += 1;
    classifications[classification] = (classifications[classification] || 0) + 1;
  }
  const recall = counts.TP / (counts.TP + counts.FN);
  const precision = counts.TP + counts.FP ? counts.TP / (counts.TP + counts.FP) : 0;
  const accuracy = (counts.TP + counts.TN) / rows.length;
  const falseAlertRate = counts.FP / (counts.FP + counts.TN);
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    samples: rows.length,
    confusion_matrix: counts,
    metrics: { recall, precision, f1, accuracy, false_alert_rate: falseAlertRate },
    confidence_intervals_95: {
      recall: wilson(counts.TP, counts.TP + counts.FN),
      precision: wilson(counts.TP, counts.TP + counts.FP),
      accuracy: wilson(counts.TP + counts.TN, rows.length),
      false_alert_rate: wilson(counts.FP, counts.FP + counts.TN)
    },
    classifications,
    prevalence_warning: "Corpus balanceado artificialmente em 50/50; precision e accuracy não estimam diretamente o desempenho na web real."
  };
}

function urlAnalysisFromPrediction(row) {
  const reasons = jsonValue(row.reasons, []);
  return {
    finalClassification: row.classification,
    score: Number(row.score),
    reasons,
    externalReputation: { available: false, listed: false, status: "not_consulted" },
    localAnalysis: {
      level: row.classification === "blocked" ? "suspicious" : row.classification,
      score: Number(row.score),
      reasons,
      signals: jsonValue(row.signals, {}),
      evidence_categories: jsonValue(row.categories, [])
    }
  };
}

function compactPageResult(result) {
  return {
    classification: result.level,
    score: result.score,
    categories: result.evidence_categories,
    diversity: result.diversity_bonus,
    signals: result.signals,
    reasons: result.reasons
  };
}

function compactCombinedResult(result) {
  return {
    classification: result.finalClassification,
    score: result.score,
    categories: result.PAGE_ANALYSIS.evidence_categories,
    diversity: result.PAGE_ANALYSIS.diversity_bonus,
    signals: {
      ...result.PAGE_ANALYSIS.signals,
      cross_layer_suspicious: result.COMBINED_ANALYSIS.cross_layer_suspicious,
      page_added_risk: result.COMBINED_ANALYSIS.page_added_risk
    },
    reasons: result.reasons
  };
}

function predictionRows(rows, key) {
  return rows.map((row) => ({
    sample_id: row.sample_id,
    true_label: row.label,
    url: row.url,
    snapshot_path: row.snapshot_path,
    snapshot_sha256: row.snapshot_sha256,
    classification: row[key].classification,
    outcome: outcome(row.label, row[key].classification),
    score: row[key].score,
    categories: row[key].categories,
    diversity: row[key].diversity,
    signals: row[key].signals,
    reasons: row[key].reasons
  }));
}

function transitionRows(rows, oldKey, newKey, modality) {
  return rows.map((row) => {
    const oldOutcome = outcome(row.label, row[oldKey].classification);
    const newOutcome = outcome(row.label, row[newKey].classification);
    return {
      sample_id: row.sample_id,
      true_label: row.label,
      url: row.url,
      modality,
      old_classification: row[oldKey].classification,
      old_score: row[oldKey].score,
      old_outcome: oldOutcome,
      new_classification: row[newKey].classification,
      new_score: row[newKey].score,
      new_outcome: newOutcome,
      transition: `${oldOutcome}->${newOutcome}`,
      old_categories: row[oldKey].categories,
      new_categories: row[newKey].categories,
      old_signals: row[oldKey].signals,
      new_signals: row[newKey].signals,
      new_reasons: row[newKey].reasons
    };
  });
}

function countTransitions(rows) {
  const counts = {};
  for (const row of rows) counts[row.transition] = (counts[row.transition] || 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort());
}

function assertInputs(corpus, snapshots) {
  if (fs.existsSync(path.join(OUTPUT, "run.json"))) throw new Error("Development comparison already executed; refusing repeated metric tuning");
  if (corpus.corpus_sha256 !== EXPECTED_CORPUS_HASH || corpus.composition?.total !== 240) throw new Error("Unexpected development corpus");
  if (snapshots.source_corpus_sha256 !== EXPECTED_CORPUS_HASH || snapshots.samples?.length !== 240) throw new Error("Unexpected v2 snapshot manifest");
  for (const record of snapshots.samples) {
    const target = path.join(OUTPUT, record.snapshot_path);
    if (sha256File(target) !== record.snapshot_sha256) throw new Error(`Derived snapshot mismatch: ${record.sample_id}`);
  }
  for (const fileName of ["metrics-page.json", "metrics-combined.json", "predictions-page.csv", "predictions-combined.csv", "predictions-url.csv"]) {
    if (!fs.existsSync(path.join(OLD_RESULTS, fileName))) throw new Error(`Missing historical result: ${fileName}`);
  }
  for (const relativePath of ["analysis.js", "page-analysis.js", "combined-analysis.js"]) {
    if (sha256File(path.join(ROOT, relativePath)) !== frozenReference.files[relativePath]) throw new Error(`Historical detector changed: ${relativePath}`);
  }
}

function main() {
  const startedAt = new Date().toISOString();
  const corpus = JSON.parse(fs.readFileSync(CORPUS_MANIFEST, "utf8"));
  const snapshots = JSON.parse(fs.readFileSync(SNAPSHOT_MANIFEST, "utf8"));
  assertInputs(corpus, snapshots);
  const snapshotById = new Map(snapshots.samples.map((item) => [item.sample_id, item]));
  const oldPageById = new Map(readCsv("predictions-page.csv").map((row) => [row.sample_id, row]));
  const oldCombinedById = new Map(readCsv("predictions-combined.csv").map((row) => [row.sample_id, row]));
  const urlById = new Map(readCsv("predictions-url.csv").map((row) => [row.sample_id, row]));
  const rows = corpus.samples.map((sample) => {
    const snapshotRecord = snapshotById.get(sample.sample_id);
    const snapshot = JSON.parse(fs.readFileSync(path.join(OUTPUT, snapshotRecord.snapshot_path), "utf8"));
    const pageResult = analyzePage(snapshot);
    const combinedResult = combineAnalyses(urlAnalysisFromPrediction(urlById.get(sample.sample_id)), pageResult);
    const oldPage = oldPageById.get(sample.sample_id);
    const oldCombined = oldCombinedById.get(sample.sample_id);
    return {
      sample_id: sample.sample_id,
      label: sample.label,
      url: sample.url,
      snapshot_path: path.relative(ROOT, path.join(OUTPUT, snapshotRecord.snapshot_path)).replaceAll("\\", "/"),
      snapshot_sha256: snapshotRecord.snapshot_sha256,
      old_page: {
        classification: oldPage.classification,
        score: Number(oldPage.score),
        categories: jsonValue(oldPage.categories, []),
        diversity: Number(jsonValue(oldPage.diversity, 0)),
        signals: jsonValue(oldPage.signals, {}),
        reasons: jsonValue(oldPage.reasons, [])
      },
      new_page: compactPageResult(pageResult),
      old_combined: {
        classification: oldCombined.classification,
        score: Number(oldCombined.score),
        categories: jsonValue(oldCombined.categories, []),
        diversity: Number(jsonValue(oldCombined.diversity, 0)),
        signals: jsonValue(oldCombined.signals, {}),
        reasons: jsonValue(oldCombined.reasons, [])
      },
      new_combined: compactCombinedResult(combinedResult)
    };
  });
  const pageTransitions = transitionRows(rows, "old_page", "new_page", "PAGE_ANALYSIS");
  const combinedTransitions = transitionRows(rows, "old_combined", "new_combined", "COMBINED_ANALYSIS");
  const oldPageMetrics = JSON.parse(fs.readFileSync(path.join(OLD_RESULTS, "metrics-page.json"), "utf8"));
  const oldCombinedMetrics = JSON.parse(fs.readFileSync(path.join(OLD_RESULTS, "metrics-combined.json"), "utf8"));
  const newPageMetrics = metricsFor(rows, "new_page");
  const newCombinedMetrics = metricsFor(rows, "new_combined");
  const changedPage = pageTransitions.filter((row) => row.old_outcome !== row.new_outcome);
  const changedCombined = combinedTransitions.filter((row) => row.old_outcome !== row.new_outcome);
  const comparison = {
    status: "development-comparison",
    source_corpus_sha256: EXPECTED_CORPUS_HASH,
    page: { old: oldPageMetrics, new: newPageMetrics, transitions: countTransitions(pageTransitions) },
    combined: { old: oldCombinedMetrics, new: newCombinedMetrics, transitions: countTransitions(combinedTransitions) },
    changes: {
      page_false_positives_removed: changedPage.filter((row) => row.transition === "FP->TN").map((row) => row.sample_id),
      page_false_positives_introduced: changedPage.filter((row) => row.transition === "TN->FP").map((row) => row.sample_id),
      page_false_negatives_recovered: changedPage.filter((row) => row.transition === "FN->TP").map((row) => row.sample_id),
      page_true_positives_lost: changedPage.filter((row) => row.transition === "TP->FN").map((row) => row.sample_id),
      combined_false_positives_removed: changedCombined.filter((row) => row.transition === "FP->TN").map((row) => row.sample_id),
      combined_false_positives_introduced: changedCombined.filter((row) => row.transition === "TN->FP").map((row) => row.sample_id),
      combined_false_negatives_recovered: changedCombined.filter((row) => row.transition === "FN->TP").map((row) => row.sample_id),
      combined_true_positives_lost: changedCombined.filter((row) => row.transition === "TP->FN").map((row) => row.sample_id)
    }
  };
  fs.writeFileSync(path.join(OUTPUT, "metrics-comparison.json"), `${JSON.stringify(comparison, null, 2)}\n`);
  const predictionColumns = ["sample_id", "true_label", "url", "snapshot_path", "snapshot_sha256", "classification", "outcome", "score", "categories", "diversity", "signals", "reasons"];
  writeCsv("predictions-page-v2.csv", predictionColumns, predictionRows(rows, "new_page"));
  writeCsv("predictions-combined-v2.csv", predictionColumns, predictionRows(rows, "new_combined"));
  const transitionColumns = ["sample_id", "true_label", "url", "modality", "old_classification", "old_score", "old_outcome", "new_classification", "new_score", "new_outcome", "transition", "old_categories", "new_categories", "old_signals", "new_signals", "new_reasons"];
  writeCsv("transitions-page-v1-v2.csv", transitionColumns, pageTransitions);
  writeCsv("transitions-combined-v1-v2.csv", transitionColumns, combinedTransitions);
  writeCsv("changed-errors.csv", transitionColumns, [...changedPage, ...changedCombined]);
  const finishedAt = new Date().toISOString();
  const run = {
    status: "development-comparison-complete",
    independent_validation: false,
    tuning_iterations: 0,
    preliminary_dry_runs_discarded: 2,
    preliminary_corrections: [
      "Removed the ambiguous standalone 'account' authentication token and required explicit sign-in/log-in language.",
      "Restored camelCase token boundaries and localized orphan fields by structural container instead of aggregating them globally."
    ],
    started_at: startedAt,
    finished_at: finishedAt,
    timezone: "America/Bahia",
    node_version: process.version,
    platform: { type: os.type(), release: os.release(), architecture: os.arch() },
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    source_corpus_sha256: EXPECTED_CORPUS_HASH,
    historical_detector_reference: frozenReference,
    new_page_analyzer: { path: "page-analysis-v2.js", sha256: sha256File(path.join(ROOT, "page-analysis-v2.js")) },
    unchanged_integration: { path: "combined-analysis.js", sha256: sha256File(path.join(ROOT, "combined-analysis.js")) },
    methodology: "Final development comparison after principle-driven implementation and pre-final conceptual/code-consistency corrections; no metric-driven recalibration was performed.",
    transition_counts: { page: countTransitions(pageTransitions), combined: countTransitions(combinedTransitions) }
  };
  fs.writeFileSync(path.join(OUTPUT, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
  const artifacts = fs.readdirSync(OUTPUT, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name !== "artifact-hashes.json")
    .map((entry) => entry.name)
    .sort();
  const hashes = {
    algorithm: "SHA-256",
    generated_at: new Date().toISOString(),
    artifacts: artifacts.map((name) => ({ name, sha256: sha256File(path.join(OUTPUT, name)), bytes: fs.statSync(path.join(OUTPUT, name)).size }))
  };
  fs.writeFileSync(path.join(OUTPUT, "artifact-hashes.json"), `${JSON.stringify(hashes, null, 2)}\n`);
  console.log(JSON.stringify({ output: path.relative(ROOT, OUTPUT), comparison }, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exitCode = 1;
}
