const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  parseCsv, stringifyCsv, parseHttpUrl, registrableDomain, hostPathIdentity,
  deterministicSort, classifyLegitimate, loadReputation, sha256File
} = require("../validation/dataset-c-lib.js");
const { normalizeUrlForReputation, checkExternalReputation } = require("../../reputation.js");
const reference = require("./frozen-reference.js");

const SEED = "phishpect-dataset-d-2026-10-22-v1";
const ROOT = path.resolve("evaluation/sources/dataset-d");
const RAW = path.join(ROOT, "raw");
const DATASET = path.resolve("evaluation/datasets/dataset-d.csv");
const MANIFEST = path.join(ROOT, "manifest.json");

function sha256Text(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function nowId() { return new Date().toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z"); }
function verifyFrozen() {
  const mismatches = [];
  for (const [file, expected] of Object.entries(reference.files)) {
    const actual = fs.existsSync(file) ? sha256File(file) : null;
    if (actual !== expected) mismatches.push({ file, expected, actual });
  }
  if (mismatches.length) throw new Error(`Detector congelado divergiu: ${JSON.stringify(mismatches)}`);
}
function historySets() {
  const normalized = new Set(), hostPath = new Set(), files = [];
  for (const name of ["dataset-a.csv", "dataset-b.csv", "dataset-c.csv", "candidates.csv", "sample.csv"]) {
    const file = path.resolve("evaluation/datasets", name);
    if (!fs.existsSync(file)) continue;
    files.push(path.relative(process.cwd(), file).replaceAll("\\", "/"));
    for (const row of parseCsv(fs.readFileSync(file, "utf8"))) {
      const exact = normalizeUrlForReputation(row.url), equivalent = hostPathIdentity(row.url);
      if (exact) normalized.add(exact); if (equivalent) hostPath.add(equivalent);
    }
  }
  const pageManifest = path.resolve("evaluation/page-corpus/corpus-manifest.json");
  if (fs.existsSync(pageManifest)) {
    files.push("evaluation/page-corpus/corpus-manifest.json");
    const value = JSON.parse(fs.readFileSync(pageManifest, "utf8"));
    for (const sample of value.samples || []) {
      const exact = normalizeUrlForReputation(sample.url), equivalent = hostPathIdentity(sample.url);
      if (exact) normalized.add(exact); if (equivalent) hostPath.add(equivalent);
    }
  }
  return { normalized, hostPath, files };
}
function filter(rows, context) {
  const counters = { input: rows.length, invalid: 0, duplicate_normalized: 0, duplicate_host_path: 0,
    historical_overlap: 0, historical_host_path_overlap: 0, reputation_overlap: 0,
    domain_concentration: 0, opposite_class_domain: 0, missing_stratum: 0, accepted: 0 };
  const exactSeen = new Set(), pathSeen = new Set(), domains = new Set(), accepted = [];
  for (const row of deterministicSort(rows, SEED)) {
    const parsed = parseHttpUrl(row.url); if (!parsed) { counters.invalid++; continue; }
    const exact = normalizeUrlForReputation(parsed.href), equivalent = hostPathIdentity(parsed.href);
    if (!exact || exactSeen.has(exact)) { counters.duplicate_normalized++; continue; } exactSeen.add(exact);
    if (!equivalent || pathSeen.has(equivalent)) { counters.duplicate_host_path++; continue; } pathSeen.add(equivalent);
    if (context.history.normalized.has(exact)) { counters.historical_overlap++; continue; }
    if (context.history.hostPath.has(equivalent)) { counters.historical_host_path_overlap++; continue; }
    if (checkExternalReputation(parsed.href, context.reputation).listed) { counters.reputation_overlap++; continue; }
    const domain = registrableDomain(parsed);
    if (context.oppositeDomains?.has(domain)) { counters.opposite_class_domain++; continue; }
    if (!domain || domains.has(domain)) { counters.domain_concentration++; continue; }
    const stratum = row.label === "legitimate" ? classifyLegitimate(row) : "phishing";
    if (!stratum) { counters.missing_stratum++; continue; }
    domains.add(domain);
    accepted.push({ ...row, url: parsed.href, stratum, registrable_domain: domain });
  }
  counters.accepted = accepted.length;
  return { rows: accepted, counters, domains };
}
async function collect() {
  verifyFrozen(); fs.mkdirSync(RAW, { recursive: true });
  const response = await fetch("https://openphish.com/feed.txt", { headers: { "User-Agent": "Phishpect-validation/4.0 (+https://github.com/Rafael-lima-devbr/phishpect)" } });
  if (!response.ok) throw new Error(`OpenPhish respondeu HTTP ${response.status}`);
  const body = await response.text();
  const acquiredAt = new Date().toISOString();
  const file = path.join(RAW, `openphish-${nowId()}.txt`);
  fs.writeFileSync(file, body);
  const entry = { source: "OpenPhish Community Feed", url: "https://openphish.com/feed.txt", acquired_at: acquiredAt,
    path: path.relative(process.cwd(), file).replaceAll("\\", "/"), sha256: sha256File(file), bytes: Buffer.byteLength(body),
    lines: body.split(/\r?\n/).filter(Boolean).length, user_agent: "Phishpect-validation/4.0 (+project repository)" };
  const acquisition = path.join(ROOT, "acquisition-manifest.json");
  const manifest = fs.existsSync(acquisition) ? JSON.parse(fs.readFileSync(acquisition, "utf8")) : { schema_version: 1, captures: [] };
  if (!manifest.captures.some((item) => item.sha256 === entry.sha256)) manifest.captures.push(entry);
  manifest.updated_at = acquiredAt; fs.writeFileSync(acquisition, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(entry, null, 2));
}
function seal() {
  verifyFrozen();
  if (fs.existsSync(DATASET) || fs.existsSync(MANIFEST)) throw new Error("Dataset D ou manifesto já existe; não será sobrescrito");
  const acquisitionPath = path.join(ROOT, "acquisition-manifest.json");
  if (!fs.existsSync(acquisitionPath)) throw new Error("Nenhuma captura OpenPhish posterior ao freeze");
  const acquisition = JSON.parse(fs.readFileSync(acquisitionPath, "utf8"));
  const history = historySets(), reputation = loadReputation("reputation/threat-db.json");
  const phishingInput = [];
  for (const capture of acquisition.captures) {
    for (const url of fs.readFileSync(capture.path, "utf8").split(/\r?\n/).filter(Boolean)) phishingInput.push({
      url, label: "phishing", source: "openphish", capture_id: path.basename(capture.path, ".txt"),
      source_timestamp: capture.acquired_at, selection_rule: "OpenPhish text feed acquired after V4 freeze", evidence: capture.sha256
    });
  }
  const phishing = filter(phishingInput, { history, reputation });
  if (phishing.rows.length < 100) throw new Error(`Phishing elegível insuficiente: ${phishing.rows.length}/100`);
  const phishingSelected = phishing.rows.slice(0, 100), phishingDomains = new Set(phishingSelected.map((row) => row.registrable_domain));
  const legitimateFiles = [
    "evaluation/sources/dataset-c/auditable-legitimate-seeds.csv",
    ...fs.readdirSync("evaluation/sources/dataset-c")
      .filter((name) => name.startsWith("site-metadata-") && name.endsWith(".csv"))
      .map((name) => `evaluation/sources/dataset-c/${name}`)
  ];
  const legitimateInput = legitimateFiles.flatMap((file) => parseCsv(fs.readFileSync(file, "utf8")))
    .map((row) => ({ ...row, label: "legitimate" }));
  const legitimate = filter(legitimateInput, { history, reputation, oppositeDomains: phishingDomains });
  if (legitimate.rows.length < 100) throw new Error(`Legítimas elegíveis insuficientes: ${legitimate.rows.length}/100`);
  const quotas = { authentication: 10, commerce_finance: 15, shared_hosting: 15, long_or_query: 22,
    idn_punycode: 10, unusual_structure: 3, internal_general: 25 };
  const selected = [], selectedDomains = new Set();
  for (const [stratum, quota] of Object.entries(quotas)) {
    const candidates = legitimate.rows.filter((row) => row.stratum === stratum && !selectedDomains.has(row.registrable_domain));
    if (candidates.length < quota) throw new Error(`Estrato legítimo ${stratum}: ${candidates.length}/${quota}`);
    for (const candidate of candidates) {
      if (selected.filter((row) => row.stratum === stratum).length >= quota) break;
      if (!selectedDomains.has(candidate.registrable_domain)) { selected.push(candidate); selectedDomains.add(candidate.registrable_domain); }
    }
  }
  const columns = ["url", "label", "source", "capture_id", "source_id", "source_timestamp", "source_category", "stratum", "selection_rule", "evidence", "registrable_domain"];
  const rows = [...selected, ...phishingSelected]; fs.mkdirSync(path.dirname(DATASET), { recursive: true });
  fs.writeFileSync(DATASET, stringifyCsv(rows, columns));
  const count = (values, key) => values.reduce((out, row) => (out[row[key] || ""] = (out[row[key] || ""] || 0) + 1, out), {});
  const manifest = { schema_version: 1, status: "sealed-not-evaluated", sealed_at: new Date().toISOString(), seed: SEED,
    detector_reference: reference, dataset: { path: "evaluation/datasets/dataset-d.csv", sha256: sha256File(DATASET), rows: 200,
      composition: { legitimate: 100, phishing: 100 }, unique_domains: { legitimate: selectedDomains.size, phishing: phishingDomains.size }, shared_domains: 0 },
    sources: { acquisition_manifest: { path: path.relative(process.cwd(), acquisitionPath).replaceAll("\\", "/"), sha256: sha256File(acquisitionPath) },
      legitimate: legitimateFiles.map((file) => ({ path: file, sha256: sha256File(file) })) },
    filters: { legitimate: legitimate.counters, phishing: phishing.counters }, composition: { legitimate_by_stratum: count(selected, "stratum"), phishing_by_capture: count(phishingSelected, "capture_id") },
    historical_files: history.files, detector_executed: false };
  fs.mkdirSync(ROOT, { recursive: true }); fs.writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(manifest, null, 2));
}
const mode = process.argv[2];
if (mode === "collect") collect().catch((error) => { console.error(error.message); process.exitCode = 1; });
else if (mode === "seal") { try { seal(); } catch (error) { console.error(error.message); process.exitCode = 1; } }
else { console.error("Uso: node scripts/v4/prepare-dataset-d.js collect|seal"); process.exitCode = 1; }
