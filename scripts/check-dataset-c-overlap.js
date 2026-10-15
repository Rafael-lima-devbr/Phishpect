const fs = require("node:fs");
const path = require("node:path");
const {
  parseCsv,
  normalizeUrlForReputation,
  hostPathIdentity,
  registrableDomain,
  readHistoricalUrlSets,
  loadReputation
} = (() => {
  const library = require("./validation/dataset-c-lib.js");
  const { normalizeUrlForReputation } = require("../reputation.js");
  return { ...library, normalizeUrlForReputation };
})();
const { checkExternalReputation } = require("../reputation.js");

function value(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function inspectDataset(datasetPath, historyRoot, reputationPath) {
  const rows = parseCsv(fs.readFileSync(datasetPath, "utf8"));
  const history = readHistoricalUrlSets(path.resolve(historyRoot));
  const reputation = loadReputation(path.resolve(reputationPath));
  const normalizedSeen = new Set(), hostPathSeen = new Set(), domainsByLabel = new Map();
  const report = {
    rows: rows.length,
    invalid: 0,
    duplicate_normalized: 0,
    duplicate_host_path: 0,
    historical_overlap: 0,
    historical_host_path_overlap: 0,
    reputation_overlap: 0,
    cross_class_domain_overlap: 0
  };
  for (const row of rows) {
    const normalized = normalizeUrlForReputation(row.url);
    const equivalent = hostPathIdentity(row.url);
    const domain = registrableDomain(row.url);
    if (!normalized || !equivalent || !domain) { report.invalid += 1; continue; }
    if (normalizedSeen.has(normalized)) report.duplicate_normalized += 1;
    normalizedSeen.add(normalized);
    if (hostPathSeen.has(equivalent)) report.duplicate_host_path += 1;
    hostPathSeen.add(equivalent);
    if (history.normalized.has(normalized)) report.historical_overlap += 1;
    if (history.hostPath.has(equivalent)) report.historical_host_path_overlap += 1;
    if (checkExternalReputation(row.url, reputation).listed) report.reputation_overlap += 1;
    if (!domainsByLabel.has(domain)) domainsByLabel.set(domain, new Set());
    domainsByLabel.get(domain).add(row.label);
  }
  report.cross_class_domain_overlap = [...domainsByLabel.values()].filter((labels) => labels.size > 1).length;
  return report;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help")) {
    console.log("Uso: node scripts/check-dataset-c-overlap.js --dataset=CSV [--history=evaluation] [--reputation=reputation/threat-db.json]");
    return;
  }
  const dataset = value(argv, "dataset");
  if (!dataset) throw new Error("Parâmetro obrigatório ausente: --dataset=CAMINHO");
  const report = inspectDataset(dataset, value(argv, "history", "evaluation"), value(argv, "reputation", "reputation/threat-db.json"));
  console.log(JSON.stringify(report, null, 2));
  const failures = Object.entries(report).filter(([name, count]) => name !== "rows" && count > 0);
  if (failures.length) process.exitCode = 2;
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { inspectDataset };
