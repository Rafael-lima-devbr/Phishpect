const fs = require("node:fs");
const path = require("node:path");
const { sha256 } = require("./validation/dataset-c-lib.js");

const USER_AGENT = "Phishpect-validation/0.4 (Dataset C research preparation)";
const PHISHTANK_PUBLIC_URL = "https://data.phishtank.com/data/online-valid.json";

const SOURCES = Object.freeze({
  openphish: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
  phishtank: PHISHTANK_PUBLIC_URL,
  tranco: "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip",
  tranco_id: "https://tranco-list.eu/top-1m-id?subdomains=true",
  common_crawl_collections: "https://index.commoncrawl.org/collinfo.json"
});

function option(argv, name) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length);
}

function requestedSources(argv) {
  const names = option(argv, "sources")?.split(",").map((name) => name.trim()).filter(Boolean)
    || Object.keys(SOURCES);
  for (const name of names) {
    if (!Object.hasOwn(SOURCES, name)) throw new Error(`Fonte desconhecida: ${name}`);
  }
  return names;
}

function requestUrl(name, environment = process.env) {
  if (name !== "phishtank") return SOURCES[name];
  const key = String(environment.PHISHTANK_APP_KEY || "").trim();
  return key
    ? `https://data.phishtank.com/data/${encodeURIComponent(key)}/online-valid.json`
    : PHISHTANK_PUBLIC_URL;
}

function outputPathFor(name, outputDirectory, captureId = "") {
  if (name === "openphish" && captureId) {
    const safeCaptureId = captureId.replace(/[^a-zA-Z0-9._-]/g, "-");
    return path.join(outputDirectory, "openphish-captures", `openphish-${safeCaptureId}.txt`);
  }
  const extension = name === "tranco" ? ".csv.zip" : name === "phishtank" || name === "common_crawl_collections" ? ".json" : ".txt";
  return path.join(outputDirectory, `${name}${extension}`);
}

function existingRecord(name, outputDirectory, captureId = "") {
  const outputPath = outputPathFor(name, outputDirectory, captureId);
  if (!fs.existsSync(outputPath)) return null;
  const bytes = fs.readFileSync(outputPath);
  return {
    name,
    url: SOURCES[name],
    path: outputPath.replaceAll("\\", "/"),
    acquired_at: fs.statSync(outputPath).mtime.toISOString(),
    sha256: sha256(bytes),
    bytes: bytes.length,
    etag: null,
    last_modified: null,
    acquisition: "preserved-existing"
  };
}

function mergeManifestRecords(manifestPath, records) {
  let previous = [];
  if (fs.existsSync(manifestPath)) {
    const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    previous = Array.isArray(parsed.records) ? parsed.records : [];
  }
  const merged = new Map();
  for (const record of [...previous, ...records]) {
    const key = `${record.path}\u0000${record.sha256}`;
    const existing = merged.get(key);
    if (!existing || existing.acquisition === "preserved-existing" && record.acquisition !== "preserved-existing") {
      merged.set(key, record);
    }
  }
  return [...merged.values()].sort((left, right) =>
    String(left.acquired_at).localeCompare(String(right.acquired_at))
      || String(left.path).localeCompare(String(right.path))
  );
}

async function download(name, outputDirectory, captureId = "") {
  const response = await fetch(requestUrl(name), { headers: { "User-Agent": USER_AGENT } });
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const outputPath = outputPathFor(name, outputDirectory, captureId);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, bytes);
  return {
    name,
    // Always record the public endpoint. An optional key must never be copied
    // to logs, manifests or repository files.
    url: SOURCES[name],
    path: outputPath.replaceAll("\\", "/"),
    acquired_at: new Date().toISOString(),
    sha256: sha256(bytes),
    bytes: bytes.length,
    etag: response.headers.get("etag"),
    last_modified: response.headers.get("last-modified"),
    acquisition: "downloaded"
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const outputArgument = argv.find((argument) => argument.startsWith("--output-dir="));
  const outputDirectory = outputArgument?.slice("--output-dir=".length) || "evaluation/sources/dataset-c/raw";
  const sourceNames = requestedSources(argv);
  const captureId = option(argv, "capture-id") || "";
  if (captureId && (sourceNames.length !== 1 || sourceNames[0] !== "openphish")) {
    throw new Error("--capture-id só pode ser usado com --sources=openphish");
  }
  if (!argv.includes("--execute")) {
    console.log(JSON.stringify({
      status: "dry-run",
      message: "Nenhuma fonte foi baixada. Use --execute somente após autorizar a coleta.",
      output_directory: outputDirectory,
      user_agent: USER_AGENT,
      sources: Object.fromEntries(sourceNames.map((name) => [name, SOURCES[name]])),
      phishtank_application_key: process.env.PHISHTANK_APP_KEY ? "configured-via-environment" : "not-configured",
      capture_id: captureId || null
    }, null, 2));
    return;
  }
  fs.mkdirSync(outputDirectory, { recursive: true });
  const records = [];
  for (const name of sourceNames) {
    const preserved = existingRecord(name, outputDirectory, captureId);
    records.push(preserved || await download(name, outputDirectory, captureId));
  }
  const manifestPath = path.join(outputDirectory, "source-manifest.json");
  const manifest = {
    schema_version: 1,
    purpose: "Dataset C source acquisition; URLs phishing remain text-only",
    created_at: new Date().toISOString(),
    records: mergeManifestRecords(manifestPath, records)
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify(manifest, null, 2));
}

if (require.main === module) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}

module.exports = {
  USER_AGENT,
  PHISHTANK_PUBLIC_URL,
  SOURCES,
  requestedSources,
  requestUrl,
  outputPathFor,
  existingRecord,
  mergeManifestRecords
};
