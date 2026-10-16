const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  LEGITIMATE_QUOTAS,
  parseCsv,
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

const SELECTION_ORDER = Object.freeze([
  "shared_hosting", "idn_punycode", "commerce_finance", "authentication",
  "long_or_query", "unusual_structure", "internal_general"
]);

function selectUniqueByQuota(rows, seed) {
  const selected = [];
  const usedDomains = new Set();
  const available = {};
  const shortfalls = {};
  for (const stratum of SELECTION_ORDER) {
    const candidates = deterministicSort(rows.filter((row) => row.stratum === stratum), `${seed}:final:${stratum}`);
    available[stratum] = new Set(candidates.map((row) => row.registrable_domain)).size;
    let added = 0;
    for (const row of candidates) {
      if (usedDomains.has(row.registrable_domain)) continue;
      usedDomains.add(row.registrable_domain);
      selected.push(row);
      added += 1;
      if (added === LEGITIMATE_QUOTAS[stratum]) break;
    }
    if (added < LEGITIMATE_QUOTAS[stratum]) shortfalls[stratum] = LEGITIMATE_QUOTAS[stratum] - added;
  }
  return { selected, available, shortfalls, uniqueDomains: usedDomains.size };
}

function main() {
  const argv = process.argv.slice(2);
  const inputOption = option(argv, "inputs");
  if (!inputOption) throw new Error("Use --inputs=ARQUIVO1;ARQUIVO2");
  const inputFiles = inputOption.split(";").map((file) => file.trim()).filter(Boolean);
  const output = option(argv, "output", "evaluation/sources/dataset-c/legitimate-candidates-filtered.csv");
  const reportPath = option(argv, "report", "evaluation/sources/dataset-c/legitimate-assembly-report.json");
  const seed = option(argv, "seed", DEFAULT_SEED);
  const evaluationRoot = path.resolve(option(argv, "history", "evaluation"));
  const abFiles = [
    path.join(evaluationRoot, "datasets", "dataset-a.csv"),
    path.join(evaluationRoot, "datasets", "dataset-b.csv")
  ].filter(fs.existsSync);
  const abResolved = new Set(abFiles.map((file) => path.resolve(file).toLowerCase()));
  const historicalFiles = csvFiles(evaluationRoot).filter((file) => !abResolved.has(path.resolve(file).toLowerCase()));
  const rows = inputFiles.flatMap((file) => parseCsv(fs.readFileSync(file, "utf8")))
    .filter((row) => row.source !== "wikidata-p856")
    .map((row) => ({ ...row, label: "legitimate" }));
  const filtered = filterRows(rows, {
    seed,
    datasetAB: urlSets(abFiles),
    historical: urlSets(historicalFiles),
    reputation: loadReputation("reputation/threat-db.json"),
    legitimate: true,
    onePerDomain: false
  });
  const selection = selectUniqueByQuota(filtered.rows, seed);
  const report = {
    schema_version: 1,
    status: Object.keys(selection.shortfalls).length ? "insufficient-candidates" : "candidate-class-complete-not-sealed",
    created_at: new Date().toISOString(),
    seed,
    detector_executed: false,
    inputs: inputFiles.map((file) => ({ path: file.replaceAll("\\", "/"), sha256: sha256File(file) })),
    filters: filtered.counters,
    available_unique_domains_by_stratum: selection.available,
    quotas: LEGITIMATE_QUOTAS,
    shortfalls: selection.shortfalls,
    selected: selection.selected.length,
    unique_domains: selection.uniqueDomains
  };
  fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  if (!Object.keys(selection.shortfalls).length) {
    fs.writeFileSync(output, stringifyCsv(selection.selected, [
      "url", "label", "source", "source_id", "source_timestamp", "source_category",
      "stratum", "selection_rule", "evidence"
    ]));
    report.output = output;
    report.output_sha256 = sha256File(output);
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { SELECTION_ORDER, selectUniqueByQuota };
