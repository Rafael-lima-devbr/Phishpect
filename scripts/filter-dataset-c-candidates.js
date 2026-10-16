const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  deterministicSort,
  parseCsv,
  parseHttpUrl,
  registrableDomain,
  hostPathIdentity,
  classifyLegitimate,
  loadReputation,
  sha256File
} = require("./validation/dataset-c-lib.js");
const { normalizeUrlForReputation, checkExternalReputation } = require("../reputation.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function urlSets(files) {
  const normalized = new Set();
  const hostPath = new Set();
  for (const file of files) {
    for (const row of parseCsv(fs.readFileSync(file, "utf8"))) {
      const exact = normalizeUrlForReputation(row.url);
      const equivalent = hostPathIdentity(row.url);
      if (exact) normalized.add(exact);
      if (equivalent) hostPath.add(equivalent);
    }
  }
  return { normalized, hostPath };
}

function csvFiles(directory) {
  const files = [];
  function visit(current) {
    if (!fs.existsSync(current)) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const entryPath = path.join(current, entry.name);
      const relative = path.relative(directory, entryPath).replaceAll("\\", "/").toLowerCase();
      if (relative.includes("dataset-c")) continue;
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".csv")) files.push(entryPath);
    }
  }
  visit(directory);
  return files;
}

function filterRows(rows, context) {
  const counters = {
    input: rows.length,
    invalid_http: 0,
    duplicate_normalized: 0,
    duplicate_host_path: 0,
    overlap_dataset_ab: 0,
    overlap_dataset_ab_normalized: 0,
    overlap_dataset_ab_host_path: 0,
    overlap_historical: 0,
    overlap_historical_normalized: 0,
    overlap_historical_host_path: 0,
    overlap_reputation: 0,
    overlap_other_class_domain: 0,
    domain_concentration: 0,
    missing_stratum: 0,
    accepted: 0
  };
  const normalizedSeen = new Set();
  const hostPathSeen = new Set();
  const domainSeen = new Set();
  const accepted = [];
  for (const row of deterministicSort(rows, context.seed)) {
    const parsed = parseHttpUrl(row.url);
    if (!parsed) { counters.invalid_http += 1; continue; }
    const normalized = normalizeUrlForReputation(parsed.href);
    const equivalent = hostPathIdentity(parsed.href);
    if (!normalized || normalizedSeen.has(normalized)) { counters.duplicate_normalized += 1; continue; }
    normalizedSeen.add(normalized);
    if (!equivalent || hostPathSeen.has(equivalent)) { counters.duplicate_host_path += 1; continue; }
    hostPathSeen.add(equivalent);
    if (context.datasetAB.normalized.has(normalized) || context.datasetAB.hostPath.has(equivalent)) {
      counters.overlap_dataset_ab += 1;
      if (context.datasetAB.normalized.has(normalized)) counters.overlap_dataset_ab_normalized += 1;
      else counters.overlap_dataset_ab_host_path += 1;
      continue;
    }
    if (context.historical.normalized.has(normalized) || context.historical.hostPath.has(equivalent)) {
      counters.overlap_historical += 1;
      if (context.historical.normalized.has(normalized)) counters.overlap_historical_normalized += 1;
      else counters.overlap_historical_host_path += 1;
      continue;
    }
    if (checkExternalReputation(parsed.href, context.reputation).listed) {
      counters.overlap_reputation += 1;
      continue;
    }
    const domain = registrableDomain(parsed);
    if (context.excludedDomains?.has(domain)) { counters.overlap_other_class_domain += 1; continue; }
    if (context.onePerDomain !== false && domainSeen.has(domain)) { counters.domain_concentration += 1; continue; }
    const stratum = context.legitimate ? classifyLegitimate(row) : "phishing";
    if (!stratum) { counters.missing_stratum += 1; continue; }
    if (context.onePerDomain !== false) domainSeen.add(domain);
    accepted.push({ ...row, url: parsed.href, registrable_domain: domain, stratum });
  }
  counters.accepted = accepted.length;
  return { rows: accepted, counters };
}

function main() {
  const argv = process.argv.slice(2);
  const mode = option(argv, "mode", "openphish");
  const legitimate = mode === "legitimate";
  const input = option(argv, "input", legitimate
    ? "evaluation/sources/dataset-c/legitimate-candidates.csv.partial"
    : "evaluation/sources/dataset-c/raw/openphish.txt");
  const output = option(argv, "output", legitimate
    ? "evaluation/sources/dataset-c/legitimate-filter-report.json"
    : "evaluation/sources/dataset-c/openphish-filter-report.json");
  const evaluationRoot = path.resolve(option(argv, "history", "evaluation"));
  const seed = option(argv, "seed", DEFAULT_SEED);
  const datasetAFiles = [path.join(evaluationRoot, "datasets", "dataset-a.csv")];
  const datasetBFiles = [path.join(evaluationRoot, "datasets", "dataset-b.csv")];
  const abFiles = [...datasetAFiles, ...datasetBFiles].filter(fs.existsSync);
  const allFiles = csvFiles(evaluationRoot);
  const abResolved = new Set(abFiles.map((file) => path.resolve(file).toLowerCase()));
  const historicalFiles = allFiles.filter((file) => !abResolved.has(path.resolve(file).toLowerCase()));
  const acquiredAt = fs.statSync(input).mtime.toISOString();
  const rows = legitimate
    ? parseCsv(fs.readFileSync(input, "utf8")).map((row) => ({ ...row, label: "legitimate" }))
    : fs.readFileSync(input, "utf8").split(/\r?\n/).map((url) => url.trim()).filter(Boolean)
      .map((url, index) => ({ url, source: "openphish", source_id: String(index + 1), source_timestamp: acquiredAt }));
  const filtered = filterRows(rows, {
    seed,
    datasetAB: urlSets(abFiles),
    historical: urlSets(historicalFiles),
    reputation: loadReputation("reputation/threat-db.json"),
    legitimate
  });
  const strata = legitimate
    ? Object.fromEntries([...new Set(filtered.rows.map((row) => row.stratum))].sort()
      .map((stratum) => [stratum, filtered.rows.filter((row) => row.stratum === stratum).length]))
    : null;
  const report = {
    schema_version: 1,
    status: "candidate-filtering-only-not-evaluated",
    created_at: new Date().toISOString(),
    seed,
    detector_executed: false,
    input: { path: input.replaceAll("\\", "/"), sha256: sha256File(input), acquired_at: acquiredAt },
    dataset_ab_files: abFiles.map((file) => path.relative(process.cwd(), file).replaceAll("\\", "/")),
    historical_files: historicalFiles.map((file) => path.relative(process.cwd(), file).replaceAll("\\", "/")).sort(),
    counters: filtered.counters,
    accepted_count: filtered.rows.length,
    strata
  };
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { urlSets, csvFiles, filterRows };
