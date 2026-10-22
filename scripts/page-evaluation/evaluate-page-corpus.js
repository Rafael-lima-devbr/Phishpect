const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const frozenReference = require("../validation/frozen-reference.js");

const ROOT = path.resolve(__dirname, "../..");
const CORPUS_ROOT = path.join(ROOT, "evaluation", "page-corpus");
const MANIFEST_PATH = path.join(CORPUS_ROOT, "corpus-manifest.json");
const OUTPUT = path.join(ROOT, "evaluation", "results", "page-analysis", "official");
const EXPECTED_CORPUS_HASH = "29574db70b518a4efffafca3d0451b4d3eae26c9d6abe283be54d9030479adab";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalCorpusHash(samples) {
  const projection = samples
    .map((sample) => ({
      sample_id: sample.sample_id,
      label: sample.label,
      url: sample.url,
      original_sha256: sample.original_sha256,
      sanitized_sha256: sample.sanitized_sha256,
      snapshot_sha256: sample.snapshot_sha256
    }))
    .sort((left, right) => left.sample_id.localeCompare(right.sample_id));
  return sha256(Buffer.from(stableStringify(projection), "utf8"));
}

function assertPreconditions(manifest) {
  if (!process.argv.includes("--confirm-official")) throw new Error("Missing explicit --confirm-official authorization");
  if (manifest.status !== "sealed-not-evaluated" || manifest.detector_executed !== false) {
    throw new Error("Corpus is not sealed-not-evaluated");
  }
  if (manifest.composition?.total !== 240 || manifest.composition?.legitimate !== 120 || manifest.composition?.phishing !== 120) {
    throw new Error("Corpus composition is not exactly 120/120");
  }
  if (manifest.corpus_sha256 !== EXPECTED_CORPUS_HASH || canonicalCorpusHash(manifest.samples) !== EXPECTED_CORPUS_HASH) {
    throw new Error("Corpus hash mismatch");
  }
  if (fs.existsSync(OUTPUT) && fs.readdirSync(OUTPUT).length > 0) {
    throw new Error("Official page-analysis results already exist; refusing a second execution");
  }
  for (const sample of manifest.samples) {
    for (const [property, hashProperty] of [["original_path", "original_sha256"], ["sanitized_path", "sanitized_sha256"], ["snapshot_path", "snapshot_sha256"]]) {
      const filePath = path.join(CORPUS_ROOT, sample[property]);
      if (sha256File(filePath) !== sample[hashProperty]) throw new Error(`Sample hash mismatch: ${sample.sample_id} ${property}`);
    }
  }
  const detectorMismatches = Object.entries(frozenReference.files)
    .map(([relativePath, expected]) => ({ relativePath, expected, actual: sha256File(path.join(ROOT, relativePath)) }))
    .filter((item) => item.actual !== item.expected);
  if (detectorMismatches.length) throw new Error(`Frozen detector mismatch: ${JSON.stringify(detectorMismatches)}`);
}

function csvCell(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(fileName, columns, rows) {
  const lines = [columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))];
  fs.writeFileSync(path.join(OUTPUT, fileName), `${lines.join("\n")}\n`);
}

function wilson(successes, total, z = 1.959963984540054) {
  if (!total) return { estimate: null, lower: null, upper: null, confidence: 0.95, method: "Wilson" };
  const proportion = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (proportion + (z * z) / (2 * total)) / denominator;
  const margin = (z * Math.sqrt((proportion * (1 - proportion) / total) + (z * z) / (4 * total * total))) / denominator;
  return { estimate: proportion, lower: Math.max(0, center - margin), upper: Math.min(1, center + margin), confidence: 0.95, method: "Wilson" };
}

function isPositive(classification) {
  return classification === "suspicious" || classification === "blocked";
}

function outcome(label, classification) {
  const positive = isPositive(classification);
  if (label === "phishing") return positive ? "TP" : "FN";
  return positive ? "FP" : "TN";
}

function metricsFor(rows, modality) {
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const classifications = { safe: 0, suspicious: 0, blocked: 0 };
  for (const row of rows) {
    counts[outcome(row.label, row[modality].classification)] += 1;
    classifications[row[modality].classification] = (classifications[row[modality].classification] || 0) + 1;
  }
  const recall = counts.TP / (counts.TP + counts.FN);
  const precision = counts.TP + counts.FP ? counts.TP / (counts.TP + counts.FP) : 0;
  const accuracy = (counts.TP + counts.TN) / rows.length;
  const falseAlertRate = counts.FP / (counts.FP + counts.TN);
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    modality,
    samples: rows.length,
    class_balance: { legitimate: counts.TN + counts.FP, phishing: counts.TP + counts.FN },
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

function signalKeys(signals) {
  const keys = [];
  for (const [key, value] of Object.entries(signals || {})) {
    if (value === true) keys.push(key);
    if (Array.isArray(value)) value.forEach((item) => keys.push(`${key}:${item}`));
  }
  return keys.sort();
}

function predictionRows(rows, modality) {
  return rows.map((row) => ({
    sample_id: row.sample_id,
    source: row.source,
    source_row_index: row.source_row_index,
    true_label: row.label,
    url: row.page_url,
    analyzed_file: row.snapshot_path,
    analyzed_file_sha256: row.snapshot_sha256,
    classification: row[modality].classification,
    predicted_positive: isPositive(row[modality].classification),
    outcome: outcome(row.label, row[modality].classification),
    score: row[modality].score,
    categories: row[modality].categories,
    diversity: row[modality].diversity,
    signals: row[modality].signals,
    reasons: row[modality].reasons,
    reputation_status: "not_consulted",
    final_classification: row[modality].classification
  }));
}

function scoreDistribution(rows, modality) {
  const buckets = new Map();
  for (const row of rows) {
    const key = `${row.label}\0${row[modality].classification}\0${row[modality].score}`;
    buckets.set(key, (buckets.get(key) || 0) + 1);
  }
  return [...buckets.entries()].map(([key, count]) => {
    const [true_label, classification, score] = key.split("\0");
    return { true_label, classification, score: Number(score), count };
  }).sort((a, b) => a.true_label.localeCompare(b.true_label) || a.score - b.score || a.classification.localeCompare(b.classification));
}

function categorySummary(rows) {
  const aggregate = new Map();
  const add = (label, kind, key) => {
    const mapKey = `${label}\0${kind}\0${key || "(none)"}`;
    aggregate.set(mapKey, (aggregate.get(mapKey) || 0) + 1);
  };
  for (const row of rows) {
    const pageCategories = row.page.categories;
    const pageSignals = signalKeys(row.page.signals);
    pageCategories.forEach((category) => add(row.label, "page_category", category));
    pageSignals.forEach((signal) => add(row.label, "page_signal", signal));
    add(row.label, "page_category_combination", pageCategories.length ? pageCategories.slice().sort().join("+") : "(none)");
    add(row.label, "page_diversity", String(row.page.diversity));
  }
  return [...aggregate.entries()].map(([key, count]) => {
    const [true_label, summary_type, value] = key.split("\0");
    return { true_label, summary_type, value, count, proportion: count / 120 };
  }).sort((a, b) => a.true_label.localeCompare(b.true_label) || a.summary_type.localeCompare(b.summary_type) || b.count - a.count || a.value.localeCompare(b.value));
}

function publicAnalysis(result) {
  return {
    classification: result.level,
    score: result.score,
    categories: result.evidence_categories || [],
    diversity: result.evidence_categories?.length || 0,
    diversity_bonus: result.diversity_bonus || 0,
    signals: result.signals || {},
    reasons: result.reasons || [],
    category_scores: result.category_scores || {},
    contributions: result.contributions || []
  };
}

function preflightOnly(manifest) {
  const original = process.argv;
  if (!original.includes("--confirm-official")) original.push("--confirm-official");
  assertPreconditions(manifest);
  console.log(JSON.stringify({ status: "ready", corpus_sha256: manifest.corpus_sha256, samples: manifest.samples.length, detector_reference: frozenReference.commit }, null, 2));
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  if (process.argv.includes("--preflight")) return preflightOnly(manifest);
  assertPreconditions(manifest);

  // Detector modules are intentionally imported only after the sealed-corpus checks above.
  const { analyzeUrl } = require("../../analysis.js");
  const { analyzePage } = require("../../page-analysis.js");
  const { combineAnalyses } = require("../../combined-analysis.js");
  fs.mkdirSync(OUTPUT, { recursive: true });
  const startedAt = new Date().toISOString();
  const rows = manifest.samples.map((sample) => {
    const snapshot = JSON.parse(fs.readFileSync(path.join(CORPUS_ROOT, sample.snapshot_path), "utf8"));
    const urlRaw = analyzeUrl(sample.url);
    const pageRaw = analyzePage(snapshot);
    const urlWrapper = {
      finalClassification: urlRaw.level,
      score: urlRaw.score,
      reasons: urlRaw.reasons,
      localAnalysis: urlRaw,
      externalReputation: { status: "not_consulted" }
    };
    const combinedRaw = combineAnalyses(urlWrapper, pageRaw);
    return {
      sample_id: sample.sample_id,
      source: manifest.source.dataset,
      source_row_index: sample.source_row_index,
      label: sample.label,
      page_url: sample.url,
      snapshot_path: sample.snapshot_path,
      snapshot_sha256: sample.snapshot_sha256,
      url_analysis_raw: urlRaw,
      page_analysis_raw: pageRaw,
      combined_analysis_raw: combinedRaw,
      url: publicAnalysis(urlRaw),
      page: publicAnalysis(pageRaw),
      combined: {
        classification: combinedRaw.finalClassification,
        score: combinedRaw.score,
        categories: { url: urlRaw.evidence_categories || [], page: pageRaw.evidence_categories || [] },
        diversity: { url: urlRaw.evidence_categories?.length || 0, page: pageRaw.evidence_categories?.length || 0 },
        signals: { url: urlRaw.signals || {}, page: pageRaw.signals || {}, cross_layer_suspicious: combinedRaw.COMBINED_ANALYSIS.cross_layer_suspicious },
        reasons: combinedRaw.reasons || []
      }
    };
  });

  const predictionColumns = ["sample_id", "source", "source_row_index", "true_label", "url", "analyzed_file", "analyzed_file_sha256", "classification", "predicted_positive", "outcome", "score", "categories", "diversity", "signals", "reasons", "reputation_status", "final_classification"];
  const urlPredictions = predictionRows(rows, "url");
  const pagePredictions = predictionRows(rows, "page");
  const combinedPredictions = predictionRows(rows, "combined");
  writeCsv("predictions-url.csv", predictionColumns, urlPredictions);
  writeCsv("predictions-page.csv", predictionColumns, pagePredictions);
  writeCsv("predictions-combined.csv", predictionColumns, combinedPredictions);

  const metrics = {
    url: metricsFor(rows, "url"),
    page: metricsFor(rows, "page"),
    combined: metricsFor(rows, "combined")
  };
  fs.writeFileSync(path.join(OUTPUT, "metrics-url.json"), `${JSON.stringify(metrics.url, null, 2)}\n`);
  fs.writeFileSync(path.join(OUTPUT, "metrics-page.json"), `${JSON.stringify(metrics.page, null, 2)}\n`);
  fs.writeFileSync(path.join(OUTPUT, "metrics-combined.json"), `${JSON.stringify(metrics.combined, null, 2)}\n`);

  const transitions = rows.map((row) => ({
    sample_id: row.sample_id,
    true_label: row.label,
    url: row.page_url,
    url_classification: row.url.classification,
    url_score: row.url.score,
    url_outcome: outcome(row.label, row.url.classification),
    page_classification: row.page.classification,
    page_score: row.page.score,
    page_outcome: outcome(row.label, row.page.classification),
    combined_classification: row.combined.classification,
    combined_score: row.combined.score,
    combined_outcome: outcome(row.label, row.combined.classification),
    transition: `${outcome(row.label, row.url.classification)}->${outcome(row.label, row.combined.classification)}`,
    page_categories: row.page.categories,
    page_signals: signalKeys(row.page.signals),
    combined_reasons: row.combined.reasons,
    snapshot_sha256: row.snapshot_sha256
  }));
  const transitionColumns = Object.keys(transitions[0]);
  writeCsv("transition-analysis.csv", transitionColumns, transitions);
  writeCsv("recovered-false-negatives.csv", transitionColumns, transitions.filter((row) => row.transition === "FN->TP"));
  writeCsv("introduced-false-positives.csv", transitionColumns, transitions.filter((row) => row.transition === "TN->FP"));
  writeCsv("false-positives-page.csv", predictionColumns, pagePredictions.filter((row) => row.outcome === "FP"));
  writeCsv("false-negatives-page.csv", predictionColumns, pagePredictions.filter((row) => row.outcome === "FN"));
  writeCsv("false-positives-combined.csv", predictionColumns, combinedPredictions.filter((row) => row.outcome === "FP"));
  writeCsv("false-negatives-combined.csv", predictionColumns, combinedPredictions.filter((row) => row.outcome === "FN"));
  writeCsv("category-summary.csv", ["true_label", "summary_type", "value", "count", "proportion"], categorySummary(rows));
  writeCsv("score-distribution-url.csv", ["true_label", "classification", "score", "count"], scoreDistribution(rows, "url"));
  writeCsv("score-distribution-page.csv", ["true_label", "classification", "score", "count"], scoreDistribution(rows, "page"));

  const finishedAt = new Date().toISOString();
  const run = {
    schema_version: 1,
    status: "official-complete",
    execution_count_for_corpus_and_detector: 1,
    started_at: startedAt,
    finished_at: finishedAt,
    timezone: "America/Bahia",
    node_version: process.version,
    platform: { type: os.type(), release: os.release(), architecture: os.arch() },
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    detector_reference: frozenReference,
    detector_hashes_verified: true,
    corpus: { path: path.relative(ROOT, MANIFEST_PATH).replaceAll("\\", "/"), sha256: manifest.corpus_sha256, samples: 240, legitimate: 120, phishing: 120 },
    source: manifest.source,
    source_file_hashes: manifest.acquisition.parquet_pool?.manifest?.source_files || [],
    sanitization: manifest.sanitization,
    configurations: {
      url_only: "analysis.js analyzeUrl; no page input; reputation not consulted",
      page_only: "page-analysis.js analyzePage over sealed static snapshot; no URL score input",
      combined: "combined-analysis.js combineAnalyses using the same URL and page results; reputation not consulted"
    },
    transition_counts: Object.fromEntries([...new Set(transitions.map((row) => row.transition))].sort().map((key) => [key, transitions.filter((row) => row.transition === key).length])),
    metric_files: ["metrics-url.json", "metrics-page.json", "metrics-combined.json"],
    prevalence_warning: "Corpus balanceado artificialmente em 50/50; precision e accuracy não estimam diretamente o desempenho na web real."
  };
  fs.writeFileSync(path.join(OUTPUT, "run.json"), `${JSON.stringify(run, null, 2)}\n`);

  const artifactFiles = fs.readdirSync(OUTPUT).filter((name) => name !== "artifact-hashes.json").sort();
  const artifactHashes = {
    algorithm: "SHA-256",
    generated_at: new Date().toISOString(),
    corpus_sha256: manifest.corpus_sha256,
    artifacts: artifactFiles.map((name) => ({ name, sha256: sha256File(path.join(OUTPUT, name)), bytes: fs.statSync(path.join(OUTPUT, name)).size }))
  };
  fs.writeFileSync(path.join(OUTPUT, "artifact-hashes.json"), `${JSON.stringify(artifactHashes, null, 2)}\n`);
  console.log(JSON.stringify({ output: path.relative(ROOT, OUTPUT), metrics, transition_counts: run.transition_counts }, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exitCode = 1;
}
