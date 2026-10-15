const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { parse: parseDomain } = require("tldts");
const {
  normalizeUrlForReputation,
  createReputationDatabase,
  checkExternalReputation
} = require("../../reputation.js");

const DEFAULT_SEED = "phishpect-dataset-c-2026-10-15-v1";
const LEGITIMATE_QUOTAS = Object.freeze({
  internal_general: 90,
  authentication: 45,
  long_or_query: 45,
  shared_hosting: 45,
  commerce_finance: 30,
  idn_punycode: 15,
  unusual_structure: 30
});
const PHISHING_QUOTAS = Object.freeze({ openphish: 150, phishtank: 150 });
const SHARED_HOSTING_SUFFIXES = Object.freeze(["github.io", "vercel.app", "netlify.app"]);
const AUTHENTICATION_TERMS = new Set(["login", "signin", "sign-in", "account", "verify", "verification", "auth"]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

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
      row.push(field);
      if (row.some((value) => value !== "")) rows.push(row);
      row = []; field = "";
    } else field += character;
  }
  row.push(field);
  if (row.some((value) => value !== "")) rows.push(row);
  if (!rows.length) return [];
  const header = rows.shift().map((value) => value.trim());
  return rows.map((values) => Object.fromEntries(header.map((column, index) => [column, values[index] ?? ""])));
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function stringifyCsv(rows, columns) {
  return `${columns.join(",")}\n${rows.map((row) => columns.map((column) => csvEscape(row[column])).join(",")).join("\n")}\n`;
}

function parseHttpUrl(value) {
  try {
    const parsed = new URL(String(value || "").trim());
    return ["http:", "https:"].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function registrableDomain(url) {
  const parsed = typeof url === "string" ? parseHttpUrl(url) : url;
  if (!parsed) return null;
  const parts = parseDomain(parsed.hostname, { allowPrivateDomains: true });
  return parts.domain || parsed.hostname.toLowerCase();
}

function hostPathIdentity(value) {
  const parsed = parseHttpUrl(value);
  if (!parsed) return null;
  const pathname = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, "");
  return `${parsed.hostname.toLowerCase()}${parsed.port ? `:${parsed.port}` : ""}${pathname}`;
}

function deterministicSort(rows, seed = DEFAULT_SEED) {
  return [...rows].sort((left, right) => {
    const leftKey = sha256(`${seed}\0${normalizeUrlForReputation(left.url) || left.url}`);
    const rightKey = sha256(`${seed}\0${normalizeUrlForReputation(right.url) || right.url}`);
    return leftKey.localeCompare(rightKey) || left.url.localeCompare(right.url);
  });
}

function classifyLegitimate(row) {
  const parsed = parseHttpUrl(row.url);
  if (!parsed) return null;
  const hostname = parsed.hostname.toLowerCase();
  const pathTokens = parsed.pathname.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const domainParts = parseDomain(hostname, { allowPrivateDomains: true });
  const subdomainCount = domainParts.subdomain ? domainParts.subdomain.split(".").filter(Boolean).length : 0;
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const digitCount = (hostname.match(/\d/g) || []).length;
  const sourceCategory = String(row.source_category || "").toLowerCase();

  if (SHARED_HOSTING_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`))) return "shared_hosting";
  if (hostname.split(".").some((label) => label.startsWith("xn--"))) return "idn_punycode";
  if (["ecommerce", "financial"].includes(sourceCategory)) return "commerce_finance";
  if (pathTokens.some((token) => AUTHENTICATION_TERMS.has(token))) return "authentication";
  if (parsed.href.length >= 100 || [...parsed.searchParams].length >= 3 || parsed.pathname.length >= 60) return "long_or_query";
  if (subdomainCount >= 2 || hyphenCount >= 2 || digitCount >= 3) return "unusual_structure";
  if (parsed.pathname && parsed.pathname !== "/") return "internal_general";
  return null;
}

function readHistoricalUrlSets(rootDirectory, ignoredFragments = ["dataset-c"]) {
  const normalized = new Set();
  const hostPath = new Set();
  const files = [];
  function visit(directory) {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      const relative = path.relative(rootDirectory, entryPath).replaceAll("\\", "/").toLowerCase();
      if (ignoredFragments.some((fragment) => relative.includes(fragment.toLowerCase()))) continue;
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".csv")) {
        const rows = parseCsv(fs.readFileSync(entryPath, "utf8"));
        if (!rows.some((row) => Object.hasOwn(row, "url"))) continue;
        files.push(relative);
        for (const row of rows) {
          const exact = normalizeUrlForReputation(row.url);
          const equivalent = hostPathIdentity(row.url);
          if (exact) normalized.add(exact);
          if (equivalent) hostPath.add(equivalent);
        }
      }
    }
  }
  visit(rootDirectory);
  return { normalized, hostPath, files: files.sort() };
}

function filterCandidates(rows, context) {
  const counters = {
    input: rows.length,
    invalid: 0,
    duplicate_normalized: 0,
    duplicate_host_path: 0,
    historical_overlap: 0,
    historical_host_path_overlap: 0,
    reputation_overlap: 0,
    excluded_domain_overlap: 0,
    domain_concentration: 0,
    missing_stratum: 0,
    accepted: 0
  };
  const normalizedSeen = new Set();
  const hostPathSeen = new Set();
  const domainSeen = new Set();
  const accepted = [];
  for (const original of deterministicSort(rows, context.seed)) {
    const parsed = parseHttpUrl(original.url);
    if (!parsed) { counters.invalid += 1; continue; }
    const normalized = normalizeUrlForReputation(parsed.href);
    const equivalent = hostPathIdentity(parsed.href);
    if (!normalized || normalizedSeen.has(normalized)) { counters.duplicate_normalized += 1; continue; }
    normalizedSeen.add(normalized);
    if (!equivalent || hostPathSeen.has(equivalent)) { counters.duplicate_host_path += 1; continue; }
    hostPathSeen.add(equivalent);
    if (context.history.normalized.has(normalized)) { counters.historical_overlap += 1; continue; }
    if (context.history.hostPath.has(equivalent)) { counters.historical_host_path_overlap += 1; continue; }
    if (checkExternalReputation(parsed.href, context.reputation).listed) { counters.reputation_overlap += 1; continue; }
    const domain = registrableDomain(parsed);
    if (context.excludedDomains?.has(domain)) { counters.excluded_domain_overlap += 1; continue; }
    if (context.onePerDomain && domainSeen.has(domain)) { counters.domain_concentration += 1; continue; }
    const stratum = original.label === "legitimate" ? classifyLegitimate(original) : "phishing";
    if (!stratum) { counters.missing_stratum += 1; continue; }
    domainSeen.add(domain);
    accepted.push({
      url: parsed.href,
      label: original.label,
      source: original.source,
      source_id: original.source_id || "",
      source_timestamp: original.source_timestamp || "",
      source_category: original.source_category || "",
      stratum,
      registrable_domain: domain
    });
  }
  counters.accepted = accepted.length;
  return { rows: accepted, counters };
}

function selectByQuotas(rows, quotas, key) {
  const selected = [];
  const available = {};
  for (const [name, count] of Object.entries(quotas)) {
    const candidates = rows.filter((row) => row[key] === name);
    available[name] = candidates.length;
    if (candidates.length < count) {
      throw new Error(`Amostras insuficientes para ${name}: ${candidates.length} disponíveis, ${count} necessárias`);
    }
    selected.push(...candidates.slice(0, count));
  }
  return { rows: selected, available };
}

function wilsonInterval(successes, total, z = 1.959963984540054) {
  if (!total) return { low: 0, high: 0 };
  const probability = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (probability + (z * z) / (2 * total)) / denominator;
  const margin = z * Math.sqrt((probability * (1 - probability) + (z * z) / (4 * total)) / total) / denominator;
  return { low: Math.max(0, center - margin), high: Math.min(1, center + margin) };
}

function calculateMetrics(records, field) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (const record of records) {
    const positive = record.label === "phishing";
    const predicted = record[field] !== "safe";
    if (positive && predicted) tp += 1;
    else if (positive) fn += 1;
    else if (predicted) fp += 1;
    else tn += 1;
  }
  const divide = (left, right) => right ? left / right : 0;
  const recall = divide(tp, tp + fn);
  const precision = divide(tp, tp + fp);
  const falseAlertRate = divide(fp, fp + tn);
  return {
    tp, tn, fp, fn,
    recall,
    precision,
    f1: divide(2 * precision * recall, precision + recall),
    accuracy: divide(tp + tn, records.length),
    false_alert_rate: falseAlertRate,
    confidence_95: {
      recall: wilsonInterval(tp, tp + fn),
      false_alert_rate: wilsonInterval(fp, fp + tn)
    }
  };
}

function loadReputation(filePath) {
  return createReputationDatabase(JSON.parse(fs.readFileSync(filePath, "utf8")));
}

module.exports = {
  DEFAULT_SEED,
  LEGITIMATE_QUOTAS,
  PHISHING_QUOTAS,
  SHARED_HOSTING_SUFFIXES,
  sha256,
  sha256File,
  parseCsv,
  stringifyCsv,
  parseHttpUrl,
  registrableDomain,
  hostPathIdentity,
  deterministicSort,
  classifyLegitimate,
  readHistoricalUrlSets,
  filterCandidates,
  selectByQuotas,
  wilsonInterval,
  calculateMetrics,
  loadReputation
};
