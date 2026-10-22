const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"' && quoted && text[index + 1] === '"') { field += '"'; index += 1; }
    else if (character === '"') quoted = !quoted;
    else if (character === "," && !quoted) { row.push(field); field = ""; }
    else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(field); if (row.some(Boolean)) rows.push(row); row = []; field = "";
    } else field += character;
  }
  row.push(field); if (row.some(Boolean)) rows.push(row);
  const [headers, ...data] = rows;
  return data.map((values) => Object.fromEntries(headers.map((header, index) => [header.trim(), values[index] || ""])));
}

function csvCell(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(filePath, rows, columns) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const output = [columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))];
  fs.writeFileSync(filePath, `${output.join("\n")}\n`);
}

function isPhishing(label) {
  return ["1", "true", "fraudulent", "malicious", "phish", "phishing"].includes(String(label).trim().toLowerCase());
}

function positive(classification) {
  return classification === "suspicious" || classification === "blocked";
}

function wilson(successes, total, z = 1.959963984540054) {
  if (!total) return { estimate: null, lower: null, upper: null, confidence: 0.95, method: "Wilson" };
  const estimate = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (estimate + (z * z) / (2 * total)) / denominator;
  const margin = z * Math.sqrt((estimate * (1 - estimate) / total) + (z * z) / (4 * total * total)) / denominator;
  return { estimate, lower: Math.max(0, center - margin), upper: Math.min(1, center + margin), confidence: 0.95, method: "Wilson" };
}

function metrics(rows, classificationKey = "classification") {
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const classifications = { safe: 0, suspicious: 0, blocked: 0 };
  for (const row of rows) {
    const classification = row[classificationKey];
    const actual = isPhishing(row.label);
    const predicted = positive(classification);
    if (actual && predicted) counts.TP += 1;
    else if (actual) counts.FN += 1;
    else if (predicted) counts.FP += 1;
    else counts.TN += 1;
    classifications[classification] = (classifications[classification] || 0) + 1;
  }
  const divide = (left, right) => right ? left / right : 0;
  const recall = divide(counts.TP, counts.TP + counts.FN);
  const precision = divide(counts.TP, counts.TP + counts.FP);
  const accuracy = divide(counts.TP + counts.TN, rows.length);
  const falseAlertRate = divide(counts.FP, counts.FP + counts.TN);
  const f1 = divide(2 * precision * recall, precision + recall);
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
    prevalence_warning: "Conjunto artificialmente balanceado; precision e accuracy não estimam diretamente o desempenho esperado na web real."
  };
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function writeArtifactHashes(directory, excluded = ["artifact-hashes.json"]) {
  const artifacts = fs.readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && !excluded.includes(entry.name))
    .map((entry) => ({
      name: entry.name,
      sha256: sha256File(path.join(directory, entry.name)),
      bytes: fs.statSync(path.join(directory, entry.name)).size
    })).sort((left, right) => left.name.localeCompare(right.name));
  fs.writeFileSync(path.join(directory, "artifact-hashes.json"), `${JSON.stringify({ algorithm: "SHA-256", artifacts }, null, 2)}\n`);
  return artifacts;
}

module.exports = { parseCsv, writeCsv, isPhishing, positive, wilson, metrics, sha256File, writeArtifactHashes };
