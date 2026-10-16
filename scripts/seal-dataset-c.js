const fs = require("node:fs");
const path = require("node:path");
const reference = require("./validation/frozen-reference.js");
const {
  DEFAULT_SEED,
  LEGITIMATE_QUOTAS,
  parseCsv,
  stringifyCsv,
  hostPathIdentity,
  registrableDomain,
  loadReputation,
  sha256File
} = require("./validation/dataset-c-lib.js");
const { normalizeUrlForReputation, checkExternalReputation } = require("../reputation.js");
const { csvFiles, urlSets } = require("./filter-dataset-c-candidates.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function countBy(rows, key) {
  const counts = {};
  for (const row of rows) counts[row[key] || ""] = (counts[row[key] || ""] || 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function overlapCounts(rows, sets) {
  let normalized = 0;
  let hostPath = 0;
  for (const row of rows) {
    const exact = normalizeUrlForReputation(row.url);
    const equivalent = hostPathIdentity(row.url);
    if (exact && sets.normalized.has(exact)) normalized += 1;
    else if (equivalent && sets.hostPath.has(equivalent)) hostPath += 1;
  }
  return { total: normalized + hostPath, normalized, hostname_path: hostPath };
}

function validateRows(legitimate, phishing, context) {
  const errors = [];
  if (legitimate.length !== 300) errors.push(`Classe legítima: ${legitimate.length}/300`);
  if (phishing.length !== 300) errors.push(`Classe phishing: ${phishing.length}/300`);
  if (legitimate.some((row) => row.label !== "legitimate")) errors.push("Rótulo inválido na classe legítima");
  if (phishing.some((row) => row.label !== "phishing")) errors.push("Rótulo inválido na classe phishing");
  const legitimateComposition = countBy(legitimate, "stratum");
  for (const [stratum, quota] of Object.entries(LEGITIMATE_QUOTAS)) {
    if ((legitimateComposition[stratum] || 0) !== quota) errors.push(`Estrato ${stratum}: ${legitimateComposition[stratum] || 0}/${quota}`);
  }
  if (phishing.some((row) => row.source !== "openphish")) errors.push("Fonte phishing diferente de OpenPhish");

  const legitimateDomains = legitimate.map((row) => registrableDomain(new URL(row.url)));
  const phishingDomains = phishing.map((row) => registrableDomain(new URL(row.url)));
  if (new Set(legitimateDomains).size !== 300) errors.push("Domínios legítimos não são únicos");
  if (new Set(phishingDomains).size !== 300) errors.push("Domínios phishing não são únicos");
  const sharedDomains = [...new Set(phishingDomains.filter((domain) => new Set(legitimateDomains).has(domain)))].sort();
  if (sharedDomains.length) errors.push(`Domínios compartilhados entre classes: ${sharedDomains.length}`);

  const rows = [...legitimate, ...phishing];
  const datasetAB = overlapCounts(rows, context.datasetAB);
  const historical = overlapCounts(rows, context.historical);
  const reputation = rows.filter((row) => checkExternalReputation(row.url, context.reputation).listed).length;
  if (datasetAB.total) errors.push(`Overlap final com A/B: ${datasetAB.total}`);
  if (historical.total) errors.push(`Overlap final histórico: ${historical.total}`);
  if (reputation) errors.push(`Overlap final com reputação: ${reputation}`);

  return {
    errors,
    legitimateComposition,
    phishingComposition: countBy(phishing, "capture_id"),
    uniqueDomains: { legitimate: new Set(legitimateDomains).size, phishing: new Set(phishingDomains).size },
    sharedDomains,
    overlaps: { dataset_ab: datasetAB, historical, reputation: { total: reputation } }
  };
}

function main() {
  const argv = process.argv.slice(2);
  const legitimatePath = option(argv, "legitimate", "evaluation/sources/dataset-c/legitimate-candidates-filtered.csv");
  const phishingPath = option(argv, "phishing", "evaluation/sources/dataset-c/openphish-candidates-filtered.csv");
  const output = option(argv, "output", "evaluation/datasets/dataset-c.csv");
  const manifestPath = option(argv, "manifest", "evaluation/sources/dataset-c/manifest.json");
  const evaluationRoot = path.resolve(option(argv, "history", "evaluation"));
  const reputationPath = option(argv, "reputation", "reputation/threat-db.json");
  const seed = option(argv, "seed", DEFAULT_SEED);
  if (fs.existsSync(output) || fs.existsSync(manifestPath)) throw new Error("Dataset C ou manifesto final já existe; selagem não será sobrescrita");

  const legitimate = parseCsv(fs.readFileSync(legitimatePath, "utf8"));
  const phishing = parseCsv(fs.readFileSync(phishingPath, "utf8"));
  const abFiles = [
    path.join(evaluationRoot, "datasets", "dataset-a.csv"),
    path.join(evaluationRoot, "datasets", "dataset-b.csv")
  ].filter(fs.existsSync);
  const abResolved = new Set(abFiles.map((file) => path.resolve(file).toLowerCase()));
  const historicalFiles = csvFiles(evaluationRoot).filter((file) => !abResolved.has(path.resolve(file).toLowerCase()));
  const validation = validateRows(legitimate, phishing, {
    datasetAB: urlSets(abFiles),
    historical: urlSets(historicalFiles),
    reputation: loadReputation(reputationPath)
  });
  const frozenMismatches = Object.entries(reference.files).flatMap(([file, expected]) => {
    const actual = fs.existsSync(file) ? sha256File(file) : null;
    return actual === expected ? [] : [{ file, expected, actual }];
  });
  if (frozenMismatches.length) validation.errors.push(`Detector congelado divergiu em ${frozenMismatches.length} arquivo(s)`);
  if (validation.errors.length) throw new Error(`Selagem recusada:\n- ${validation.errors.join("\n- ")}`);

  const rows = [...legitimate, ...phishing];
  const columns = [
    "url", "label", "source", "capture_id", "source_id", "source_timestamp",
    "source_category", "stratum", "selection_rule", "evidence"
  ];
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, stringifyCsv(rows, columns));
  const sourceReports = [
    "evaluation/sources/dataset-c/acquisition-manifest.json",
    "evaluation/sources/dataset-c/legitimate-assembly-report.json",
    "evaluation/sources/dataset-c/openphish-assembly-report.json"
  ].filter(fs.existsSync).map((file) => ({ path: file, sha256: sha256File(file) }));
  const openPhishReportPath = "evaluation/sources/dataset-c/openphish-assembly-report.json";
  const openPhishReport = fs.existsSync(openPhishReportPath)
    ? JSON.parse(fs.readFileSync(openPhishReportPath, "utf8")) : null;
  const legitimateReportPath = "evaluation/sources/dataset-c/legitimate-assembly-report.json";
  const legitimateReport = fs.existsSync(legitimateReportPath)
    ? JSON.parse(fs.readFileSync(legitimateReportPath, "utf8")) : null;
  const manifest = {
    schema_version: 1,
    status: "sealed-not-evaluated",
    created_at: new Date().toISOString(),
    seed,
    detector_executed: false,
    official_evaluation: null,
    detector_reference: reference,
    frozen_file_mismatches: frozenMismatches,
    dataset: {
      path: output.replaceAll("\\", "/"),
      sha256: sha256File(output),
      total: rows.length,
      legitimate: legitimate.length,
      phishing: phishing.length
    },
    source_files: [legitimatePath, phishingPath].map((file) => ({ path: file.replaceAll("\\", "/"), sha256: sha256File(file) })),
    source_reports: sourceReports,
    openphish_captures: openPhishReport?.captures || [],
    filters: {
      legitimate: legitimateReport?.filters || null,
      phishing: openPhishReport?.combined_filters || null,
      final_overlaps: validation.overlaps
    },
    composition: {
      legitimate_by_stratum: validation.legitimateComposition,
      phishing_by_capture: validation.phishingComposition
    },
    domains: {
      unique_by_class: validation.uniqueDomains,
      shared_between_classes: validation.sharedDomains.length,
      maximum_per_registrable_domain: 1
    },
    historical_csv_files: historicalFiles.map((file) => path.relative(process.cwd(), file).replaceAll("\\", "/")).sort()
  };
  fs.mkdirSync(path.dirname(path.resolve(manifestPath)), { recursive: true });
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(manifest, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { countBy, overlapCounts, validateRows };
