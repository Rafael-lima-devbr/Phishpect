const fs = require("node:fs");
const path = require("node:path");
const reference = require("./validation/frozen-reference.js");
const {
  DEFAULT_SEED,
  LEGITIMATE_QUOTAS,
  PHISHING_QUOTAS,
  sha256File,
  parseCsv,
  stringifyCsv,
  readHistoricalUrlSets,
  filterCandidates,
  selectByQuotas,
  loadReputation
} = require("./validation/dataset-c-lib.js");

function argumentsFrom(argv) {
  const values = {};
  for (const argument of argv) {
    const match = argument.match(/^--([^=]+)=(.*)$/);
    if (match) values[match[1]] = match[2];
  }
  if (values.help === "true" || argv.includes("--help")) return { help: true };
  const required = ["legitimate", "openphish", "output", "manifest"];
  for (const name of required) if (!values[name]) throw new Error(`Parâmetro obrigatório ausente: --${name}=CAMINHO`);
  return {
    ...values,
    seed: values.seed || DEFAULT_SEED,
    history: values.history || "evaluation",
    reputation: values.reputation || "reputation/threat-db.json",
    acquiredAt: values["acquired-at"] || new Date().toISOString()
  };
}

function legitimateRows(filePath) {
  return parseCsv(fs.readFileSync(filePath, "utf8")).map((row, index) => ({
    ...row,
    label: "legitimate",
    source: row.source || "tranco-common-crawl",
    source_id: row.source_id || String(index + 1)
  }));
}

function openPhishRows(filePath, acquiredAt) {
  const captureId = path.basename(filePath, path.extname(filePath));
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/)
    .map((url) => url.trim()).filter(Boolean)
    .map((url, index) => ({
      url,
      label: "phishing",
      source: "openphish",
      capture_id: captureId,
      source_id: String(index + 1),
      source_timestamp: acquiredAt
    }));
}

function main() {
  const options = argumentsFrom(process.argv.slice(2));
  if (options.help) {
    console.log("Uso: node scripts/build-dataset-c.js --legitimate=CSV --openphish=CAPTURA1;CAPTURA2 --output=CSV --manifest=JSON [--seed=VALOR]");
    return;
  }
  const history = readHistoricalUrlSets(path.resolve(options.history));
  const reputation = loadReputation(path.resolve(options.reputation));
  const baseContext = { seed: options.seed, history, reputation, onePerDomain: true };

  const legitimateFiltered = filterCandidates(legitimateRows(options.legitimate), baseContext);
  const legitimateSelected = selectByQuotas(legitimateFiltered.rows, LEGITIMATE_QUOTAS, "stratum");
  const legitimateDomains = new Set(legitimateSelected.rows.map((row) => row.registrable_domain));

  const openPhishFiles = options.openphish.split(";").map((filePath) => filePath.trim()).filter(Boolean);
  const phishingInput = openPhishFiles.flatMap((filePath) => openPhishRows(filePath, options.acquiredAt));
  const phishingFiltered = filterCandidates(phishingInput, { ...baseContext, excludedDomains: legitimateDomains });
  const phishingSelected = selectByQuotas(phishingFiltered.rows, PHISHING_QUOTAS, "source");

  const selected = [...legitimateSelected.rows, ...phishingSelected.rows]
    .map(({ registrable_domain, source_category, ...row }) => row);
  const columns = [
    "url", "label", "source", "capture_id", "source_id", "source_timestamp",
    "stratum", "selection_rule", "evidence"
  ];
  fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
  fs.writeFileSync(options.output, stringifyCsv(selected, columns));

  const sourceFiles = [options.legitimate, ...openPhishFiles].map((filePath) => ({
    path: path.relative(process.cwd(), path.resolve(filePath)).replaceAll("\\", "/"),
    sha256: sha256File(filePath)
  }));
  const manifest = {
    schema_version: 1,
    status: "sealed-not-evaluated",
    created_at: new Date().toISOString(),
    acquired_at: options.acquiredAt,
    timezone: reference.timezone,
    seed: options.seed,
    detector_reference: reference,
    dataset: {
      path: path.relative(process.cwd(), path.resolve(options.output)).replaceAll("\\", "/"),
      sha256: sha256File(options.output),
      total: selected.length,
      legitimate: legitimateSelected.rows.length,
      phishing: phishingSelected.rows.length
    },
    source_files: sourceFiles,
    historical_csv_files: history.files,
    filters: {
      legitimate: legitimateFiltered.counters,
      phishing: phishingFiltered.counters
    },
    composition: {
      legitimate: Object.fromEntries(Object.keys(LEGITIMATE_QUOTAS).map((name) => [name, legitimateSelected.rows.filter((row) => row.stratum === name).length])),
      phishing: Object.fromEntries(Object.keys(PHISHING_QUOTAS).map((name) => [name, phishingSelected.rows.filter((row) => row.source === name).length])),
      phishing_by_capture: Object.fromEntries([...new Set(phishingSelected.rows.map((row) => row.capture_id))]
        .sort().map((captureId) => [captureId, phishingSelected.rows.filter((row) => row.capture_id === captureId).length]))
    },
    available_after_filtering: {
      legitimate: legitimateSelected.available,
      phishing: phishingSelected.available
    },
    official_evaluation: null
  };
  fs.mkdirSync(path.dirname(path.resolve(options.manifest)), { recursive: true });
  fs.writeFileSync(options.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify({ dataset: manifest.dataset, composition: manifest.composition, filters: manifest.filters }, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { argumentsFrom, legitimateRows, openPhishRows };
