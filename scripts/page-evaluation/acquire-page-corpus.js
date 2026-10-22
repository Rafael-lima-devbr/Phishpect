const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { parse: parseDomain } = require("tldts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(ROOT, "evaluation", "page-corpus");
const ORIGINAL = path.join(OUTPUT, "original");
const SOURCE = Object.freeze({
  dataset: "phreshphish/phreshphish",
  revision: "eabec4b7a66324b79cc8a0ad856d1731dc26fe1a",
  version: "1.0.1",
  split: "test",
  license: "CC BY 4.0",
  url: "https://huggingface.co/datasets/phreshphish/phreshphish"
});
const SEED = "phishpect-page-corpus-2026-10-16-v1";
const TARGET = 120;
const MAX_ROWS_PER_CLASS = 500;
const BATCH_SIZE = 100;

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeUrl(value) {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error("non-http-url");
  parsed.hash = "";
  parsed.hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  return parsed.href;
}

function registrableDomain(value) {
  const parsed = new URL(value);
  const parts = parseDomain(parsed.hostname, { allowPrivateDomains: true });
  return parts.domain || parsed.hostname.toLowerCase();
}

async function fetchBatch(label, offset) {
  const query = new URLSearchParams({
    dataset: SOURCE.dataset,
    config: "default",
    split: SOURCE.split,
    where: `"label"='${label}'`,
    offset: String(offset),
    length: String(BATCH_SIZE)
  });
  const endpoint = `https://datasets-server.huggingface.co/filter?${query}`;
  const response = await fetch(endpoint, {
    headers: { "User-Agent": "Phishpect-page-evaluation/1.0" },
    redirect: "error",
    signal: AbortSignal.timeout(180_000)
  });
  if (!response.ok) throw new Error(`Dataset API ${response.status} for ${label} offset ${offset}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const payload = JSON.parse(bytes.toString("utf8"));
  return {
    endpoint,
    response_sha256: sha256(bytes),
    response_bytes: bytes.length,
    rows: payload.rows || [],
    total_filtered_rows: payload.num_rows_total
  };
}

function inspectRow(entry, expectedLabel, counters, seen) {
  counters.input += 1;
  const row = entry?.row || {};
  if (row.label !== expectedLabel) { counters.wrong_label += 1; return null; }
  if (typeof row.html !== "string" || !row.html.trim()) { counters.empty_html += 1; return null; }
  if (typeof row.sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(row.sha256)) {
    counters.missing_source_identifier += 1;
    return null;
  }
  const htmlSha256 = sha256(Buffer.from(row.html, "utf8"));
  let normalized;
  let domain;
  try {
    normalized = normalizeUrl(row.url);
    domain = registrableDomain(normalized);
  } catch {
    counters.invalid_url += 1;
    return null;
  }
  if (seen.urls.has(normalized)) { counters.duplicate_url += 1; return null; }
  if (seen.html.has(htmlSha256)) { counters.duplicate_html += 1; return null; }
  if (seen.domains.has(domain)) { counters.domain_concentration += 1; return null; }
  seen.urls.add(normalized);
  seen.html.add(htmlSha256);
  seen.domains.add(domain);
  counters.eligible += 1;
  return {
    source_row_index: entry.row_idx,
    source_sha256: row.sha256,
    html_sha256: htmlSha256,
    url: row.url,
    normalized_url: normalized,
    registrable_domain: domain,
    target: row.target || null,
    date: row.date || null,
    language: row.lang || null,
    language_score: row.lang_score ?? null,
    html: row.html,
    selection_key: sha256(`${SEED}\n${expectedLabel}\n${row.sha256}`)
  };
}

async function acquireClass(label) {
  const candidates = [];
  const requests = [];
  const counters = {
    input: 0, wrong_label: 0, empty_html: 0, missing_source_identifier: 0,
    invalid_url: 0, duplicate_url: 0, duplicate_html: 0,
    domain_concentration: 0, eligible: 0
  };
  const seen = { urls: new Set(), html: new Set(), domains: new Set() };
  for (let offset = 0; offset < MAX_ROWS_PER_CLASS; offset += BATCH_SIZE) {
    const batch = await fetchBatch(label, offset);
    requests.push({
      offset,
      length: BATCH_SIZE,
      response_sha256: batch.response_sha256,
      response_bytes: batch.response_bytes,
      returned_rows: batch.rows.length,
      total_filtered_rows: batch.total_filtered_rows
    });
    for (const entry of batch.rows) {
      const candidate = inspectRow(entry, label, counters, seen);
      if (candidate) candidates.push(candidate);
    }
    if (candidates.length >= TARGET * 2 || batch.rows.length < BATCH_SIZE) break;
  }
  return { candidates, requests, counters };
}

function select(candidates, excludedDomains = new Set()) {
  return candidates
    .filter((candidate) => !excludedDomains.has(candidate.registrable_domain))
    .sort((left, right) => left.selection_key.localeCompare(right.selection_key))
    .slice(0, TARGET);
}

async function main() {
  if (fs.existsSync(path.join(OUTPUT, "corpus-manifest.json"))) {
    throw new Error("Corpus manifest already exists; refusing to reacquire or replace a sealed corpus");
  }
  fs.mkdirSync(ORIGINAL, { recursive: true });
  const acquiredAt = new Date().toISOString();
  const poolArgument = process.argv.find((argument) => argument.startsWith("--pool="));
  let benignPool;
  let phishPool;
  let parquetPool = null;
  if (poolArgument) {
    const poolPath = path.resolve(ROOT, poolArgument.slice("--pool=".length));
    const poolBytes = fs.readFileSync(poolPath);
    const records = poolBytes.toString("utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
    const inspectRecords = (label) => {
      const candidates = [];
      const counters = {
        input: 0, wrong_label: 0, empty_html: 0, missing_source_identifier: 0,
        invalid_url: 0, duplicate_url: 0, duplicate_html: 0,
        domain_concentration: 0, eligible: 0
      };
      const seen = { urls: new Set(), html: new Set(), domains: new Set() };
      records.filter((row) => row.label === label).forEach((row, index) => {
        const candidate = inspectRow({ row_idx: index, row }, label, counters, seen);
        if (candidate) {
          candidate.source_parquet = row.source_parquet;
          candidates.push(candidate);
        }
      });
      return { candidates, requests: [], counters };
    };
    benignPool = inspectRecords("benign");
    phishPool = inspectRecords("phish");
    const poolManifestPath = `${poolPath}.manifest.json`;
    parquetPool = {
      path: path.relative(ROOT, poolPath).replaceAll("\\", "/"),
      sha256: sha256(poolBytes),
      manifest: fs.existsSync(poolManifestPath)
        ? JSON.parse(fs.readFileSync(poolManifestPath, "utf8"))
        : null
    };
  } else {
    benignPool = await acquireClass("benign");
    phishPool = await acquireClass("phish");
  }
  const benign = select(benignPool.candidates);
  const benignDomains = new Set(benign.map((item) => item.registrable_domain));
  const phish = select(phishPool.candidates, benignDomains);
  if (benign.length !== TARGET || phish.length !== TARGET) {
    throw new Error(`Insufficient eligible samples: benign=${benign.length}, phish=${phish.length}`);
  }

  const selected = [];
  for (const [label, rows, prefix] of [["legitimate", benign, "L"], ["phishing", phish, "P"]]) {
    rows.forEach((row, index) => {
      const sampleId = `PP-${prefix}-${String(index + 1).padStart(3, "0")}`;
      const relativePath = path.posix.join("original", `${sampleId}.html`);
      fs.writeFileSync(path.join(OUTPUT, relativePath), row.html, "utf8");
      selected.push({
        sample_id: sampleId,
        label,
        source_label: label === "legitimate" ? "benign" : "phish",
        source_row_index: row.source_row_index,
        source_parquet: row.source_parquet || null,
        source_sha256: row.source_sha256,
        url: row.url,
        normalized_url: row.normalized_url,
        registrable_domain: row.registrable_domain,
        source_target: row.target,
        source_date: row.date,
        source_language: row.language,
        source_language_score: row.language_score,
        selection_key: row.selection_key,
        original_path: relativePath,
        original_sha256: row.html_sha256,
        original_bytes: Buffer.byteLength(row.html, "utf8")
      });
    });
  }

  const manifest = {
    schema_version: 1,
    status: "acquired-not-sanitized",
    acquired_at: acquiredAt,
    detector_executed: false,
    seed: SEED,
    source: SOURCE,
    selection: {
      target_per_class: TARGET,
      max_rows_considered_per_class: MAX_ROWS_PER_CLASS,
      maximum_per_registrable_domain_per_class: 1,
      shared_domains_between_classes: 0,
      ranking: "SHA-256(seed + source label + source HTML SHA-256)"
    },
    acquisition: {
      user_agent: "Phishpect-page-evaluation/1.0",
      live_page_urls_requested: false,
      mechanism: parquetPool ? "local frozen Parquet export" : "Hugging Face dataset filter API",
      parquet_pool: parquetPool,
      benign: { requests: benignPool.requests, counters: benignPool.counters, pool_size: benignPool.candidates.length },
      phish: { requests: phishPool.requests, counters: phishPool.counters, pool_size: phishPool.candidates.length }
    },
    samples: selected
  };
  fs.writeFileSync(path.join(OUTPUT, "acquisition-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify({ acquiredAt, selected: selected.length, benign: benign.length, phish: phish.length }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
