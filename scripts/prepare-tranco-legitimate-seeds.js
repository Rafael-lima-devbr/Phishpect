const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  deterministicSort,
  registrableDomain,
  stringifyCsv,
  sha256File
} = require("./validation/dataset-c-lib.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function loadTranco(filePath) {
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean).map((line) => {
    const [rank, domain] = line.split(",");
    return { rank: Number(rank), domain: String(domain || "").trim().toLowerCase() };
  }).filter((row) => row.rank && row.domain);
}

function select(rows, count, seed, intendedStratum, predicate, trancoId) {
  const ordered = deterministicSort(rows.filter(predicate).map((row) => ({
    url: `https://${row.domain}/`,
    source: "tranco-direct-metadata",
    source_id: `${trancoId}:${row.rank}`,
    source_timestamp: "",
    source_category: "",
    intended_stratum: intendedStratum,
    tranco_rank: row.rank,
    selection_rule: `deterministic ${intendedStratum} seed from permanent Tranco list ${trancoId}`,
    evidence: `tranco_id=${trancoId};rank=${row.rank};domain=${row.domain}`
  })), `${seed}:${intendedStratum}`);
  const selected = [];
  const domains = new Set();
  for (const row of ordered) {
    const domain = registrableDomain(row.url);
    if (!domain || domains.has(domain)) continue;
    domains.add(domain);
    selected.push(row);
    if (selected.length === count) break;
  }
  return selected;
}

function main() {
  const argv = process.argv.slice(2);
  const tranco = option(argv, "tranco", "evaluation/sources/dataset-c/raw/tranco-extracted/top-1m.csv");
  const trancoIdPath = option(argv, "tranco-id", "evaluation/sources/dataset-c/raw/tranco_id.txt");
  const output = option(argv, "output", "evaluation/sources/dataset-c/tranco-legitimate-seeds.csv");
  const seed = option(argv, "seed", DEFAULT_SEED);
  const trancoId = fs.readFileSync(trancoIdPath, "utf8").trim();
  const rows = loadTranco(tranco);
  const sharedSuffixes = ["github.io", "vercel.app", "netlify.app"];
  const isIdn = (domain) => domain.split(".").some((label) => label.startsWith("xn--"));
  const isUnusual = (domain) => {
    const parts = domain.split(".");
    const subdomains = Math.max(0, parts.length - 2);
    return subdomains >= 2 || (domain.match(/-/g) || []).length >= 2 || (domain.match(/\d/g) || []).length >= 3;
  };
  const general = select(rows, 500, seed, "general", (row) =>
    row.rank <= 100_000 && !isIdn(row.domain) && !isUnusual(row.domain)
      && !sharedSuffixes.some((suffix) => row.domain === suffix || row.domain.endsWith(`.${suffix}`)), trancoId);
  const unusual = select(rows, 600, seed, "unusual_structure", (row) =>
    !isIdn(row.domain) && isUnusual(row.domain)
      && !sharedSuffixes.some((suffix) => row.domain === suffix || row.domain.endsWith(`.${suffix}`)), trancoId);
  const idn = select(rows, 100, seed, "idn_punycode", (row) => isIdn(row.domain), trancoId);
  const selected = [...general, ...unusual, ...idn];
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, stringifyCsv(selected, [
    "url", "source", "source_id", "source_timestamp", "source_category", "intended_stratum",
    "tranco_rank", "selection_rule", "evidence"
  ]));
  console.log(JSON.stringify({
    tranco_id: trancoId,
    tranco_sha256: sha256File(tranco),
    seed,
    composition: { general: general.length, unusual_structure: unusual.length, idn_punycode: idn.length },
    output,
    output_sha256: sha256File(output)
  }, null, 2));
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { loadTranco, select };
