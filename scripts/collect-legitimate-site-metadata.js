const fs = require("node:fs");
const path = require("node:path");
const {
  DEFAULT_SEED,
  deterministicSort,
  parseCsv,
  stringifyCsv,
  registrableDomain,
  sha256
} = require("./validation/dataset-c-lib.js");

const USER_AGENT = "Phishpect-validation/0.4 (Dataset C same-site metadata collection)";
const AUTH_PATHS = Object.freeze(["/login", "/signin", "/account", "/account/login", "/auth/login"]);
const CONTENT_PATHS = Object.freeze(["/about", "/help", "/docs", "/products", "/news"]);

function option(argv, name, fallback) {
  const prefix = `--${name}=`;
  return argv.find((argument) => argument.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function sameDomain(left, right) {
  return registrableDomain(left) && registrableDomain(left) === registrableDomain(right);
}

function decodeXml(value) {
  return value.replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", '"').replaceAll("&#39;", "'").trim();
}

function locations(text) {
  return [...text.matchAll(/<loc(?:\s[^>]*)?>([\s\S]*?)<\/loc>/gi)].map((match) => decodeXml(match[1]));
}

async function readLimited(response, maximumBytes = 2_000_000) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maximumBytes) throw new Error(`response-too-large:${declared}`);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new Error(`response-too-large:>${maximumBytes}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function request(url, method = "GET") {
  const delays = method === "HEAD" ? [] : [2_000];
  for (let attempt = 0; attempt <= delays.length; attempt += 1) {
    try {
      const response = await fetch(url, {
        method,
        redirect: "follow",
        headers: { "User-Agent": USER_AGENT, Accept: method === "HEAD" ? "text/html" : "text/plain, application/xml, text/xml;q=0.9, */*;q=0.1" },
        signal: AbortSignal.timeout(method === "HEAD" ? 8_000 : 15_000)
      });
      if (response.status === 429) return { ok: false, status: 429, error: "rate-limited-no-retry", url: response.url || url };
      if ([500, 502, 503, 504].includes(response.status) && attempt < delays.length) {
        if (response.body) await response.body.cancel();
        await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
        continue;
      }
      return { response, ok: response.ok, status: response.status, url: response.url || url };
    } catch (error) {
      if (attempt === delays.length) return { ok: false, status: null, error: error.name, url };
      await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
    }
  }
  return { ok: false, status: null, error: "unavailable", url };
}

async function textResource(url, baseUrl) {
  const result = await request(url);
  if (!result.response) return result;
  if (!result.ok || !sameDomain(baseUrl, result.url)) {
    if (result.response.body) await result.response.body.cancel();
    return { ...result, ok: false, error: result.error || (!sameDomain(baseUrl, result.url) ? "cross-domain-redirect" : `http-${result.status}`) };
  }
  const contentType = result.response.headers.get("content-type") || "";
  try {
    const text = await readLimited(result.response);
    return { ok: true, status: result.status, url: result.url, contentType, text };
  } catch (error) {
    return { ok: false, status: result.status, url: result.url, contentType, error: error.message };
  }
}

async function headHtml(url, baseUrl) {
  const result = await request(url, "HEAD");
  if (!result.response) return result;
  const contentType = result.response.headers.get("content-type") || "";
  if (result.response.body) await result.response.body.cancel();
  const ok = result.ok && sameDomain(baseUrl, result.url) && /text\/html|application\/xhtml\+xml/i.test(contentType);
  return { ok, status: result.status, url: result.url, contentType, error: ok ? null : "not-same-domain-html" };
}

async function inspectSeed(seedRow, includeAuthentication, includeContent, includeSitemaps) {
  const base = new URL(seedRow.url);
  const baseUrl = `${base.protocol}//${base.host}/`;
  const acquiredAt = new Date().toISOString();
  const robots = includeSitemaps
    ? await textResource(new URL("/robots.txt", baseUrl), baseUrl)
    : { ok: false, status: null, url: new URL("/robots.txt", baseUrl).href, error: "disabled-for-batch" };
  const sitemapUrls = includeSitemaps && robots.ok
    ? robots.text.split(/\r?\n/).map((line) => line.match(/^\s*Sitemap:\s*(\S+)/i)?.[1]).filter(Boolean).slice(0, 2)
    : [];
  if (includeSitemaps && !sitemapUrls.length) sitemapUrls.push(new URL("/sitemap.xml", baseUrl).href);
  const discovered = [];
  const sitemapEvidence = [];
  for (const sitemapUrl of sitemapUrls) {
    let parsed;
    try { parsed = new URL(sitemapUrl, baseUrl).href; } catch { continue; }
    if (!sameDomain(baseUrl, parsed)) continue;
    const sitemap = await textResource(parsed, baseUrl);
    sitemapEvidence.push({ url: parsed, ok: sitemap.ok, status: sitemap.status, error: sitemap.error || null });
    if (!sitemap.ok) continue;
    const locs = locations(sitemap.text);
    const childSitemaps = /<sitemapindex/i.test(sitemap.text) ? locs.slice(0, 2) : [];
    if (childSitemaps.length) {
      for (const childUrl of childSitemaps) {
        if (!sameDomain(baseUrl, childUrl)) continue;
        const child = await textResource(childUrl, baseUrl);
        sitemapEvidence.push({ url: childUrl, ok: child.ok, status: child.status, error: child.error || null });
        if (child.ok) discovered.push(...locations(child.text));
      }
    } else discovered.push(...locs);
  }
  const sameSiteUrls = [...new Set(discovered)].filter((url) => {
    try { return ["http:", "https:"].includes(new URL(url).protocol) && sameDomain(baseUrl, url); } catch { return false; }
  }).slice(0, 200);
  const authentication = [];
  const siteResponsive = !includeSitemaps || robots.ok || sitemapEvidence.some((item) => item.ok);
  if (includeAuthentication && siteResponsive) {
    for (const authPath of AUTH_PATHS) {
      const result = await headHtml(new URL(authPath, baseUrl), baseUrl);
      authentication.push({ requested_path: authPath, ...result });
      if (result.ok) break;
    }
  }
  const content = [];
  if (includeContent && siteResponsive) {
    for (const contentPath of CONTENT_PATHS) {
      const result = await headHtml(new URL(contentPath, baseUrl), baseUrl);
      content.push({ requested_path: contentPath, ...result });
      if (result.ok) break;
    }
  }
  return {
    seed: seedRow,
    acquired_at: acquiredAt,
    robots: { ok: robots.ok, status: robots.status, url: robots.url, error: robots.error || null },
    sitemaps: sitemapEvidence,
    discovered_urls: sameSiteUrls,
    authentication,
    content
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const input = option(argv, "input");
  const captureId = option(argv, "capture-id");
  if (!input || !captureId) throw new Error("Use --input=CSV e --capture-id=IDENTIFICADOR");
  const intended = option(argv, "intended-stratum", "");
  const category = option(argv, "category", "");
  const offset = Number(option(argv, "offset", "0"));
  const limit = Number(option(argv, "limit", "25"));
  const concurrency = Math.max(1, Math.min(3, Number(option(argv, "concurrency", "2"))));
  const includeAuthentication = option(argv, "authentication", intended === "general" ? "true" : "false") === "true";
  const includeContent = option(argv, "content-paths", ["general", "unusual_structure"].includes(intended) ? "true" : "false") === "true";
  const includeSitemaps = option(argv, "sitemaps", "true") === "true";
  const seed = option(argv, "seed", DEFAULT_SEED);
  const rawOutput = option(argv, "raw-output", `evaluation/sources/dataset-c/raw/site-metadata/site-metadata-${captureId}.json`);
  const output = option(argv, "output", `evaluation/sources/dataset-c/site-metadata-${captureId}.csv`);
  let seeds = parseCsv(fs.readFileSync(input, "utf8"));
  if (intended) seeds = seeds.filter((row) => row.intended_stratum === intended);
  if (category) seeds = seeds.filter((row) => row.source_category === category);
  seeds = deterministicSort(seeds, `${seed}:site-metadata:${intended}:${category}`).slice(offset, offset + limit);
  if (!argv.includes("--execute")) {
    console.log(JSON.stringify({ status: "dry-run", input, capture_id: captureId, intended_stratum: intended || null, category: category || null, offset, selected: seeds.length, concurrency, authentication: includeAuthentication, content_paths: includeContent, sitemaps: includeSitemaps }, null, 2));
    return;
  }
  const records = [];
  let cursor = 0;
  async function worker() {
    while (cursor < seeds.length) {
      const index = cursor;
      cursor += 1;
      records[index] = await inspectSeed(seeds[index], includeAuthentication, includeContent, includeSitemaps);
      if ((index + 1) % 10 === 0) console.log(JSON.stringify({ progress: index + 1, total: seeds.length }));
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const candidates = [];
  for (const record of records) {
    const row = record.seed;
    for (const url of record.discovered_urls) {
      candidates.push({
        url,
        source: `${row.source}-same-site-sitemap`,
        source_id: row.source_id,
        source_timestamp: record.acquired_at,
        source_category: row.source_category || "",
        selection_rule: "URL published in a same-registrable-domain sitemap discovered by robots.txt or /sitemap.xml",
        evidence: `${row.evidence};metadata_capture=${captureId}`
      });
    }
    for (const auth of record.authentication.filter((item) => item.ok)) {
      candidates.push({
        url: auth.url,
        source: `${row.source}-fixed-auth-path`,
        source_id: row.source_id,
        source_timestamp: record.acquired_at,
        source_category: row.source_category || "",
        selection_rule: `fixed authentication path ${auth.requested_path} returned same-domain HTML`,
        evidence: `${row.evidence};status=${auth.status};content_type=${auth.contentType};metadata_capture=${captureId}`
      });
    }
    for (const content of record.content.filter((item) => item.ok)) {
      candidates.push({
        url: content.url,
        source: `${row.source}-fixed-content-path`,
        source_id: row.source_id,
        source_timestamp: record.acquired_at,
        source_category: row.source_category || "",
        selection_rule: `fixed internal content path ${content.requested_path} returned same-domain HTML`,
        evidence: `${row.evidence};status=${content.status};content_type=${content.contentType};metadata_capture=${captureId}`
      });
    }
  }
  const rawPayload = {
    schema_version: 1,
    status: "metadata-only-not-evaluated",
    created_at: new Date().toISOString(),
    input,
    input_sha256: sha256(fs.readFileSync(input)),
    capture_id: captureId,
    seed,
    intended_stratum: intended || null,
    category: category || null,
    offset,
    limit,
    detector_executed: false,
    records
  };
  fs.mkdirSync(path.dirname(path.resolve(rawOutput)), { recursive: true });
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  const rawBytes = Buffer.from(`${JSON.stringify(rawPayload, null, 2)}\n`);
  fs.writeFileSync(rawOutput, rawBytes);
  fs.writeFileSync(output, stringifyCsv(deterministicSort(candidates, `${seed}:${captureId}`), [
    "url", "source", "source_id", "source_timestamp", "source_category", "selection_rule", "evidence"
  ]));
  console.log(JSON.stringify({
    capture_id: captureId,
    inspected: records.length,
    sitemap_candidates: candidates.filter((row) => row.selection_rule.startsWith("URL published")).length,
    authentication_candidates: candidates.filter((row) => row.selection_rule.startsWith("fixed authentication")).length,
    fixed_content_candidates: candidates.filter((row) => row.selection_rule.startsWith("fixed internal content")).length,
    raw_output: rawOutput,
    raw_sha256: sha256(rawBytes),
    output,
    output_sha256: sha256(fs.readFileSync(output))
  }, null, 2));
}

if (require.main === module) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { USER_AGENT, AUTH_PATHS, CONTENT_PATHS, sameDomain, locations };
