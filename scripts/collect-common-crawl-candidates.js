const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  deterministicSort,
  parseCsv,
  stringifyCsv,
  registrableDomain
} = require("./validation/dataset-c-lib.js");

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function loadTranco(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const parsed = parseCsv(text);
  if (parsed.length && (parsed[0].domain || parsed[0].Domain)) {
    return parsed.map((row) => ({ domain: row.domain || row.Domain, rank: Number(row.rank || row.Rank) || 0 }));
  }
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    const [rank, domain] = line.split(",");
    return { rank: Number(rank) || 0, domain: String(domain || "").trim().toLowerCase() };
  }).filter((row) => row.domain);
}

function selectDomains(rows, count, seed) {
  const selected = [], selectedDomains = new Set();
  const take = (candidates, amount, suffix) => {
    if (amount <= 0) return;
    let added = 0;
    for (const row of deterministicSort(candidates.map((candidate) => ({ url: `https://${candidate.domain}/`, ...candidate })), `${seed}:${suffix}`)) {
      if (!selectedDomains.has(row.domain)) {
        selectedDomains.add(row.domain);
        selected.push(row);
        added += 1;
        if (added >= amount) break;
      }
    }
  };
  take(rows.filter((row) => ["github.io", "vercel.app", "netlify.app"].some((suffix) => row.domain.endsWith(`.${suffix}`))), 150, "shared-hosting");
  take(rows.filter((row) => row.domain.split(".").some((label) => label.startsWith("xn--"))), 60, "idn");
  take(rows.filter((row) => ((row.domain.match(/-/g) || []).length >= 2 || (row.domain.match(/\d/g) || []).length >= 3)), 120, "unusual");
  const bands = [
    [1, 10_000], [10_001, 100_000], [100_001, 500_000], [500_001, 1_000_000]
  ];
  const remaining = Math.max(0, count - selected.length);
  const perBand = Math.ceil(remaining / bands.length);
  for (const [bandIndex, [minimum, maximum]] of bands.entries()) {
    take(rows.filter((row) => row.rank >= minimum && row.rank <= maximum), perBand, `rank-band:${bandIndex}`);
  }
  if (selected.length < count) take(rows, count - selected.length, "remainder");
  return selected.slice(0, count);
}

async function queryDomain(crawl, domain, limit) {
  const query = new URL(`https://index.commoncrawl.org/${crawl}-index`);
  query.searchParams.set("url", `${domain}/*`);
  query.searchParams.set("output", "json");
  query.searchParams.append("filter", "status:200");
  query.searchParams.append("filter", "mime:text/html");
  query.searchParams.set("collapse", "urlkey");
  query.searchParams.set("limit", String(limit));
  const response = await fetch(query, { headers: { "User-Agent": "Phishpect FEBRACE validation/0.4 (legitimate URL metadata collection)" } });
  if (response.status === 404) return [];
  if (!response.ok) throw new Error(`Common Crawl HTTP ${response.status} para domínio legítimo`);
  return (await response.text()).split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

async function main() {
  const argv = process.argv.slice(2);
  const trancoPath = option(argv, "tranco");
  const crawl = option(argv, "crawl");
  const outputPath = option(argv, "output", "evaluation/sources/dataset-c/legitimate-candidates.csv");
  const seed = option(argv, "seed", DEFAULT_SEED);
  const domainCount = Number(option(argv, "domains", "800"));
  const perDomain = Number(option(argv, "per-domain", "20"));
  const categoryMapPath = option(argv, "category-map");
  const supplementPath = option(argv, "supplement");
  if (!trancoPath || !crawl) throw new Error("Use --tranco=CSV e --crawl=CC-MAIN-AAAA-NN");
  const domains = selectDomains(loadTranco(trancoPath), domainCount, seed);
  if (!argv.includes("--execute")) {
    console.log(JSON.stringify({ status: "dry-run", crawl, seed, selected_domains: domains.length, per_domain: perDomain, category_map: categoryMapPath || null, supplement: supplementPath || null, output: outputPath }, null, 2));
    return;
  }
  const categoryMap = new Map(categoryMapPath
    ? parseCsv(fs.readFileSync(categoryMapPath, "utf8")).map((row) => [String(row.domain || "").toLowerCase(), String(row.source_category || "").toLowerCase()])
    : []);
  const candidates = [];
  for (const [index, domain] of domains.entries()) {
    const records = await queryDomain(crawl, domain.domain, perDomain);
    for (const record of records) {
      candidates.push({
        url: record.url,
        source: "tranco-common-crawl",
        source_id: record.digest || `${domain.rank}:${index}`,
        source_timestamp: record.timestamp || "",
        source_category: categoryMap.get(registrableDomain(record.url)) || "",
        tranco_rank: domain.rank,
        common_crawl: crawl
      });
    }
  }
  if (supplementPath) {
    for (const row of parseCsv(fs.readFileSync(supplementPath, "utf8"))) {
      candidates.push({
        url: row.url,
        source: row.source || "official-catalog",
        source_id: row.source_id || "",
        source_timestamp: row.source_timestamp || "",
        source_category: row.source_category || "",
        tranco_rank: row.tranco_rank || "",
        common_crawl: row.common_crawl || ""
      });
    }
  }
  fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
  fs.writeFileSync(outputPath, stringifyCsv(candidates, [
    "url", "source", "source_id", "source_timestamp", "source_category", "tranco_rank", "common_crawl"
  ]));
  console.log(JSON.stringify({ candidates: candidates.length, output: outputPath }, null, 2));
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
