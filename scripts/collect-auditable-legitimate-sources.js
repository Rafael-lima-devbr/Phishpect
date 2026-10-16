const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  deterministicSort,
  stringifyCsv,
  sha256
} = require("./validation/dataset-c-lib.js");

const USER_AGENT = "Phishpect-validation/0.4 (Dataset C legitimate source collection)";

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

async function fetchJson(url, headers = {}) {
  const response = await fetch(url, {
    headers: { "User-Agent": USER_AGENT, Accept: "application/json", ...headers },
    signal: AbortSignal.timeout(30_000)
  });
  if (response.status === 429 || response.status === 403) {
    throw new Error(`Fonte interrompida por limite de acesso: HTTP ${response.status}`);
  }
  if (!response.ok) throw new Error(`Fonte HTTP ${response.status}`);
  return { data: await response.json(), acquiredAt: new Date().toISOString(), headers: {
    etag: response.headers.get("etag"),
    lastModified: response.headers.get("last-modified")
  } };
}

function githubPagesUrl(repository) {
  const owner = repository.owner?.login;
  if (!owner || !repository.name || repository.has_pages !== true) return null;
  const expectedHost = `${owner.toLowerCase()}.github.io`;
  if (repository.homepage) {
    try {
      const homepage = new URL(repository.homepage);
      if (["http:", "https:"].includes(homepage.protocol) && homepage.hostname.toLowerCase() === expectedHost) {
        return homepage.href;
      }
    } catch {}
  }
  return repository.name.toLowerCase() === expectedHost
    ? `https://${expectedHost}/`
    : `https://${expectedHost}/${encodeURIComponent(repository.name)}/`;
}

async function collectGitHub(pages) {
  const responses = [];
  for (let pageNumber = 1; pageNumber <= pages; pageNumber += 1) {
    const url = new URL("https://api.github.com/search/repositories");
    url.searchParams.set("q", "topic:github-pages fork:false archived:false");
    url.searchParams.set("sort", "stars");
    url.searchParams.set("order", "desc");
    url.searchParams.set("per_page", "100");
    url.searchParams.set("page", String(pageNumber));
    responses.push(await fetchJson(url, {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }));
  }
  return responses;
}

const WIKIDATA_QUERIES = Object.freeze({
  financial: `SELECT DISTINCT ?item ?website WHERE {
    ?item wdt:P31/wdt:P279* wd:Q22687 ; wdt:P856 ?website .
  } LIMIT 500`,
  ecommerce: `SELECT DISTINCT ?item ?website WHERE {
    ?item wdt:P452 wd:Q484847 ; wdt:P856 ?website .
  } LIMIT 500`
});

async function collectWikidata() {
  const responses = [];
  for (const [category, query] of Object.entries(WIKIDATA_QUERIES)) {
    const url = new URL("https://query.wikidata.org/sparql");
    url.searchParams.set("query", query);
    url.searchParams.set("format", "json");
    responses.push({ category, query, ...(await fetchJson(url, { Accept: "application/sparql-results+json" })) });
  }
  return responses;
}

function writeRaw(rawDirectory, name, captureId, payload) {
  fs.mkdirSync(rawDirectory, { recursive: true });
  const rawPath = path.join(rawDirectory, `${name}-${captureId}.json`);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`);
  fs.writeFileSync(rawPath, bytes);
  return { path: rawPath.replaceAll("\\", "/"), bytes: bytes.length, sha256: sha256(bytes) };
}

async function main() {
  const argv = process.argv.slice(2);
  const captureId = option(argv, "capture-id");
  if (!captureId) throw new Error("Informe --capture-id=IDENTIFICADOR reproduzível");
  const rawDirectory = option(argv, "raw-dir", "evaluation/sources/dataset-c/raw/legitimate-sources");
  const output = option(argv, "output", "evaluation/sources/dataset-c/auditable-legitimate-seeds.csv");
  const seed = option(argv, "seed", DEFAULT_SEED);
  const githubPages = Number(option(argv, "github-pages", "5"));
  if (!argv.includes("--execute")) {
    console.log(JSON.stringify({ status: "dry-run", capture_id: captureId, seed, github_pages: githubPages, output }, null, 2));
    return;
  }

  const github = await collectGitHub(githubPages);
  const wikidata = await collectWikidata();
  const rawFiles = [
    writeRaw(rawDirectory, "github-pages-search", captureId, { source: "GitHub REST API", responses: github }),
    writeRaw(rawDirectory, "wikidata-commerce-finance", captureId, { source: "Wikidata Query Service", responses: wikidata })
  ];

  const rows = [];
  for (const response of github) {
    for (const repository of response.data.items || []) {
      const url = githubPagesUrl(repository);
      if (!url) continue;
      rows.push({
        url,
        source: "github-pages-api",
        source_id: repository.full_name,
        source_timestamp: response.acquiredAt,
        source_category: "",
        selection_rule: "public repository from fixed GitHub search with has_pages=true",
        evidence: `repository=${repository.full_name};has_pages=true;api_url=${repository.url}`
      });
    }
  }
  for (const response of wikidata) {
    for (const binding of response.data.results?.bindings || []) {
      rows.push({
        url: binding.website?.value || "",
        source: "wikidata-p856",
        source_id: binding.item?.value?.split("/").pop() || "",
        source_timestamp: response.acquiredAt,
        source_category: response.category,
        selection_rule: response.category === "financial"
          ? "Wikidata official website P856 for an instance/subclass of bank Q22687"
          : "Wikidata official website P856 for an entity with e-commerce Q484847 industry",
        evidence: `item=${binding.item?.value || ""};property=P856;category=${response.category}`
      });
    }
  }
  const valid = rows.filter((row) => {
    try { return ["http:", "https:"].includes(new URL(row.url).protocol); } catch { return false; }
  });
  const ordered = deterministicSort(valid, seed);
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, stringifyCsv(ordered, [
    "url", "source", "source_id", "source_timestamp", "source_category", "selection_rule", "evidence"
  ]));
  console.log(JSON.stringify({
    capture_id: captureId,
    raw_files: rawFiles,
    github_pages_candidates: ordered.filter((row) => row.source === "github-pages-api").length,
    wikidata_financial_seeds: ordered.filter((row) => row.source_category === "financial").length,
    wikidata_ecommerce_seeds: ordered.filter((row) => row.source_category === "ecommerce").length,
    output
  }, null, 2));
}

if (require.main === module) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { USER_AGENT, githubPagesUrl, WIKIDATA_QUERIES };
