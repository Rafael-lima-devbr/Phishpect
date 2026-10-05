const fs = require("node:fs");
const path = require("node:path");
const { createReputationDatabase, checkExternalReputation } = require("../reputation.js");

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

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function isFraudulent(label) {
  return ["1", "true", "fraudulent", "phishing", "malicious"].includes(label.trim().toLowerCase());
}

function metrics(records, classificationField) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  for (const record of records) {
    const actual = isFraudulent(record.label);
    const predicted = record[classificationField] !== "safe";
    if (actual && predicted) tp += 1;
    else if (actual) fn += 1;
    else if (predicted) fp += 1;
    else tn += 1;
  }
  const divide = (a, b) => b ? a / b : 0;
  const recall = divide(tp, tp + fn);
  const precision = divide(tp, tp + fp);
  return {
    tp, fn, fp, tn,
    recall,
    precision,
    f1: divide(2 * precision * recall, precision + recall),
    false_alert_rate: divide(fp, fp + tn),
    accuracy: divide(tp + tn, records.length)
  };
}

function writeCsv(outputPath, records) {
  const columns = [
    "url", "label", "analyzer_version", "local_score", "local_classification",
    "local_reasons", "local_contributions", "local_category_scores",
    "local_evidence_categories", "local_diversity_bonus", "local_signals", "local_features",
    "external_listed", "external_source", "final_classification"
  ];
  const output = [
    columns.join(","),
    ...records.map((record) => columns.map((column) => csv(record[column])).join(","))
  ].join("\n");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${output}\n`);
}

function mistakePath(outputPath, kind) {
  const extension = path.extname(outputPath);
  return path.join(
    path.dirname(outputPath),
    `${path.basename(outputPath, extension)}-${kind}${extension || ".csv"}`
  );
}

function parseArguments(argv) {
  let analyzerVersion = "v3.1";
  const positional = [];
  for (const argument of argv) {
    if (argument.startsWith("--analyzer=")) {
      analyzerVersion = argument.slice("--analyzer=".length).toLowerCase();
    } else {
      positional.push(argument);
    }
  }
  if (!["v2", "v3", "v3.1"].includes(analyzerVersion)) {
    throw new Error("O analisador deve ser v2, v3 ou v3.1");
  }
  return {
    analyzerVersion,
    inputPath: positional[0],
    outputPath: positional[1] || `evaluation/results/raw/dataset-a-${analyzerVersion}.csv`
  };
}

function main() {
  const { analyzerVersion, inputPath, outputPath } = parseArguments(process.argv.slice(2));
  if (!inputPath) {
    throw new Error("Uso: node scripts/evaluate-dataset.js [--analyzer=v2|v3|v3.1] entrada.csv [saida.csv]");
  }

  const analyzerModule = {
    v2: "../analysis-v2.js",
    v3: "../analysis-v3.js",
    "v3.1": "../analysis.js"
  }[analyzerVersion];
  const { analyzeUrl } = require(analyzerModule);
  const rows = parseCsv(fs.readFileSync(inputPath, "utf8"));
  const header = rows.shift().map((value) => value.trim().toLowerCase());
  const urlIndex = header.indexOf("url"), labelIndex = header.indexOf("label");
  if (urlIndex < 0 || labelIndex < 0) throw new Error("O CSV precisa das colunas url e label");

  let databaseData = {};
  try {
    databaseData = JSON.parse(fs.readFileSync("reputation/threat-db.json", "utf8"));
  } catch {
    console.warn("Base externa indisponível; avaliando apenas a análise local.");
  }
  const database = createReputationDatabase(databaseData);

  const records = rows.map((row) => {
    const url = row[urlIndex], label = row[labelIndex];
    const local = analyzeUrl(url);
    const external = checkExternalReputation(url, database);
    return {
      url,
      label,
      analyzer_version: analyzerVersion,
      local_score: local.score,
      local_classification: local.level,
      local_reasons: JSON.stringify(local.reasons || []),
      local_contributions: JSON.stringify(local.contributions || []),
      local_category_scores: JSON.stringify(local.category_scores || {}),
      local_evidence_categories: JSON.stringify(local.evidence_categories || []),
      local_diversity_bonus: local.diversity_bonus || 0,
      local_signals: JSON.stringify(local.signals || {}),
      local_features: JSON.stringify(local.features || null),
      external_listed: external.listed,
      external_source: external.source,
      final_classification: external.listed ? "blocked" : local.level
    };
  });

  writeCsv(outputPath, records);
  const falsePositives = records.filter(
    (record) => !isFraudulent(record.label) && record.local_classification !== "safe"
  );
  const falseNegatives = records.filter(
    (record) => isFraudulent(record.label) && record.local_classification === "safe"
  );
  const falsePositivePath = mistakePath(outputPath, "false-positives");
  const falseNegativePath = mistakePath(outputPath, "false-negatives");
  writeCsv(falsePositivePath, falsePositives);
  writeCsv(falseNegativePath, falseNegatives);

  const result = {
    analyzer: analyzerVersion,
    local_only: metrics(records, "local_classification"),
    local_plus_external: metrics(records, "final_classification"),
    output: outputPath,
    false_positives: falsePositivePath,
    false_negatives: falseNegativePath
  };
  console.log(JSON.stringify(result, null, 2));
}

try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
