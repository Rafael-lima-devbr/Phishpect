const fs = require("node:fs");
const path = require("node:path");

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"' && quoted && text[index + 1] === '"') {
      field += '"'; index += 1;
    } else if (character === '"') quoted = !quoted;
    else if (character === "," && !quoted) { row.push(field); field = ""; }
    else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(field); if (row.some(Boolean)) rows.push(row); row = []; field = "";
    } else field += character;
  }
  row.push(field); if (row.some(Boolean)) rows.push(row);
  return rows;
}

function readCsv(filePath) {
  const rows = parseCsv(fs.readFileSync(filePath, "utf8"));
  const header = rows.shift();
  return rows.map((row) => Object.fromEntries(header.map((column, index) => [column, row[index] || ""])));
}

function escapeCsv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(filePath, rows) {
  const columns = [
    "url", "label", "baseline_score", "baseline_reasons", "candidate_score", "candidate_reasons",
    "candidate_categories", "candidate_category_scores", "candidate_diversity_bonus"
  ];
  const lines = [columns.join(","), ...rows.map((row) => columns.map((column) => escapeCsv(row[column])).join(","))];
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
}

function pairedRow(v3, v31) {
  return {
    url: v31.url,
    label: v31.label,
    baseline_score: v3.local_score,
    baseline_reasons: v3.local_reasons,
    candidate_score: v31.local_score,
    candidate_reasons: v31.local_reasons,
    candidate_categories: v31.local_evidence_categories,
    candidate_category_scores: v31.local_category_scores,
    candidate_diversity_bonus: v31.local_diversity_bonus
  };
}

function patternCounts(rows) {
  const counts = new Map();
  for (const row of rows) {
    const pattern = JSON.parse(row.candidate_categories || "[]").join("+") || "none";
    counts.set(pattern, (counts.get(pattern) || 0) + 1);
  }
  return Object.fromEntries([...counts.entries()].sort((left, right) => right[1] - left[1]));
}

function main() {
  const [, , v3Path, v31Path, outputPrefix] = process.argv;
  if (!v3Path || !v31Path || !outputPrefix) {
    throw new Error("Uso: node scripts/compare-analyzer-results.js v3.csv v3-1.csv prefixo-saida");
  }

  const v3 = readCsv(v3Path);
  const v31 = readCsv(v31Path);
  const v3ByUrl = new Map(v3.map((record) => [record.url, record]));
  const pairs = v31.map((record) => [v3ByUrl.get(record.url), record]);
  if (pairs.some(([previous]) => !previous)) throw new Error("Os resultados não contêm as mesmas URLs");

  const recovered = pairs
    .filter(([previous, current]) => current.label === "phishing" && previous.local_classification === "safe" && current.local_classification !== "safe")
    .map(([previous, current]) => pairedRow(previous, current));
  const lostDetections = pairs
    .filter(([previous, current]) => current.label === "phishing" && previous.local_classification !== "safe" && current.local_classification === "safe")
    .map(([previous, current]) => pairedRow(previous, current));
  const newFalsePositives = pairs
    .filter(([previous, current]) => current.label === "legitimate" && previous.local_classification === "safe" && current.local_classification !== "safe")
    .map(([previous, current]) => pairedRow(previous, current));

  fs.mkdirSync(path.dirname(outputPrefix), { recursive: true });
  const recoveredPath = `${outputPrefix}-recovered.csv`;
  const lostPath = `${outputPrefix}-lost-detections.csv`;
  const falsePositivePath = `${outputPrefix}-new-false-positives.csv`;
  writeCsv(recoveredPath, recovered);
  writeCsv(lostPath, lostDetections);
  writeCsv(falsePositivePath, newFalsePositives);

  const summary = {
    baseline_source: v3Path,
    candidate_source: v31Path,
    recovered: recovered.length,
    recovered_by_evidence_categories: patternCounts(recovered),
    lost_detections: lostDetections.length,
    new_false_positives: newFalsePositives.length,
    files: { recovered: recoveredPath, lost_detections: lostPath, new_false_positives: falsePositivePath }
  };
  fs.writeFileSync(`${outputPrefix}-summary.json`, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
