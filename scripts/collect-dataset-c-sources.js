const fs = require("node:fs");
const path = require("node:path");
const { sha256 } = require("./validation/dataset-c-lib.js");

const SOURCES = Object.freeze({
  openphish: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
  phishtank: "https://data.phishtank.com/data/online-valid.json",
  tranco: "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip",
  tranco_id: "https://tranco-list.eu/top-1m-id?subdomains=true",
  common_crawl_collections: "https://index.commoncrawl.org/collinfo.json"
});

async function download(name, url, outputDirectory) {
  const response = await fetch(url, { headers: { "User-Agent": "Phishpect FEBRACE validation/0.4 (research dataset preparation)" } });
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const extension = name === "tranco" ? ".csv.zip" : name === "phishtank" || name === "common_crawl_collections" ? ".json" : ".txt";
  const outputPath = path.join(outputDirectory, `${name}${extension}`);
  fs.writeFileSync(outputPath, bytes);
  return {
    name,
    url,
    path: outputPath.replaceAll("\\", "/"),
    acquired_at: new Date().toISOString(),
    sha256: sha256(bytes),
    bytes: bytes.length,
    etag: response.headers.get("etag"),
    last_modified: response.headers.get("last-modified")
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const outputArgument = argv.find((argument) => argument.startsWith("--output-dir="));
  const outputDirectory = outputArgument?.slice("--output-dir=".length) || "evaluation/sources/dataset-c/raw";
  if (!argv.includes("--execute")) {
    console.log(JSON.stringify({
      status: "dry-run",
      message: "Nenhuma fonte foi baixada. Use --execute somente após autorizar a coleta.",
      output_directory: outputDirectory,
      sources: SOURCES
    }, null, 2));
    return;
  }
  fs.mkdirSync(outputDirectory, { recursive: true });
  const records = [];
  for (const [name, url] of Object.entries(SOURCES)) records.push(await download(name, url, outputDirectory));
  const manifest = {
    schema_version: 1,
    purpose: "Dataset C source acquisition; URLs phishing remain text-only",
    created_at: new Date().toISOString(),
    records
  };
  fs.writeFileSync(path.join(outputDirectory, "source-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(manifest, null, 2));
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
