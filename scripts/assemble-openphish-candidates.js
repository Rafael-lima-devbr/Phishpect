const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  parseCsv,
  registrableDomain,
  stringifyCsv,
  deterministicSort,
  loadReputation,
  sha256File
} = require("./validation/dataset-c-lib.js");
const { urlSets, csvFiles, filterRows } = require("./filter-dataset-c-candidates.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function captureRows(filePath) {
  const captureId = path.basename(filePath, path.extname(filePath));
  const acquiredAt = fs.statSync(filePath).mtime.toISOString();
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/).map((url) => url.trim()).filter(Boolean)
    .map((url, index) => ({
      url,
      label: "phishing",
      source: "openphish",
      capture_id: captureId,
      source_id: `${captureId}:${index + 1}`,
      source_timestamp: acquiredAt,
      selection_rule: "OpenPhish textual feed capture; no URL visited",
      evidence: `capture=${captureId};line=${index + 1}`
    }));
}

function main() {
  const argv = process.argv.slice(2);
  const inputOption = option(argv, "inputs");
  if (!inputOption) throw new Error("Use --inputs=CAPTURA1;CAPTURA2");
  const inputFiles = inputOption.split(";").map((file) => file.trim()).filter(Boolean);
  const output = option(argv, "output", "evaluation/sources/dataset-c/openphish-candidates-filtered.csv");
  const reportPath = option(argv, "report", "evaluation/sources/dataset-c/openphish-assembly-report.json");
  const legitimatePath = option(argv, "legitimate", "evaluation/sources/dataset-c/legitimate-candidates-filtered.csv");
  const evaluationRoot = path.resolve(option(argv, "history", "evaluation"));
  const seed = option(argv, "seed", DEFAULT_SEED);
  const abFiles = [
    path.join(evaluationRoot, "datasets", "dataset-a.csv"),
    path.join(evaluationRoot, "datasets", "dataset-b.csv")
  ].filter(fs.existsSync);
  const abResolved = new Set(abFiles.map((file) => path.resolve(file).toLowerCase()));
  const historicalFiles = csvFiles(evaluationRoot).filter((file) => !abResolved.has(path.resolve(file).toLowerCase()));
  const context = {
    seed,
    datasetAB: urlSets(abFiles),
    historical: urlSets(historicalFiles),
    reputation: loadReputation("reputation/threat-db.json"),
    legitimate: false,
    onePerDomain: true,
    excludedDomains: fs.existsSync(legitimatePath)
      ? new Set(parseCsv(fs.readFileSync(legitimatePath, "utf8")).map((row) => registrableDomain(new URL(row.url))))
      : new Set()
  };
  const perCapture = [];
  const combinedRows = [];
  for (const file of inputFiles) {
    const rows = captureRows(file);
    const filtered = filterRows(rows, context);
    perCapture.push({
      capture_id: rows[0]?.capture_id || path.basename(file),
      path: file.replaceAll("\\", "/"),
      acquired_at: fs.statSync(file).mtime.toISOString(),
      sha256: sha256File(file),
      bytes: fs.statSync(file).size,
      counters: filtered.counters
    });
    combinedRows.push(...rows);
  }
  const combined = filterRows(combinedRows, context);
  const selected = deterministicSort(combined.rows, `${seed}:openphish-final`).slice(0, 300);
  const composition = Object.fromEntries(perCapture.map((capture) => [
    capture.capture_id,
    selected.filter((row) => row.capture_id === capture.capture_id).length
  ]));
  const report = {
    schema_version: 1,
    status: selected.length === 300 ? "candidate-class-complete-not-sealed" : "insufficient-candidates",
    created_at: new Date().toISOString(),
    seed,
    detector_executed: false,
    source: "OpenPhish only",
    methodological_limitation: "Single phishing provider; temporal captures can share campaigns and collection policy.",
    captures: perCapture,
    combined_filters: combined.counters,
    available_after_filtering: combined.rows.length,
    selected: selected.length,
    unique_domains: new Set(selected.map((row) => row.registrable_domain)).size,
    maximum_domain_concentration: selected.length ? 1 : 0,
    selection_by_capture: composition
  };
  fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
  if (selected.length === 300) {
    fs.writeFileSync(output, stringifyCsv(selected, [
      "url", "label", "source", "capture_id", "source_id", "source_timestamp",
      "stratum", "selection_rule", "evidence"
    ]));
    report.output = output;
    report.output_sha256 = sha256File(output);
  }
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { captureRows };
