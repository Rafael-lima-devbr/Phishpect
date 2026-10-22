const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { performance } = require("node:perf_hooks");
const { execFileSync } = require("node:child_process");
const { analyzeUrlV4 } = require("../../analysis-v4.js");
const {
  collectPageSnapshotV4,
  mergePageSnapshotsV4,
  analyzePageV4,
  V4_LATE_OBSERVATION_DELAY_MS
} = require("../../page-analysis-v4.js");
const { combineV4Evidence } = require("../../combined-analysis-v4.js");
const { createReputationDatabase, checkExternalReputation } = require("../../reputation.js");
const { sha256File, writeArtifactHashes } = require("./evaluation-lib.js");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(ROOT, "evaluation", "results", "v4", "development", "performance");
const ITERATIONS = Number(process.argv.find((item) => item.startsWith("--iterations="))?.split("=")[1]) || 2_000;

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1))];
}

function benchmark(name, operation, iterations = ITERATIONS) {
  for (let index = 0; index < Math.min(100, iterations); index += 1) operation(index);
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now();
    operation(index);
    samples.push(performance.now() - started);
  }
  samples.sort((left, right) => left - right);
  const sum = samples.reduce((total, value) => total + value, 0);
  return {
    stage: name,
    iterations,
    average_ms: sum / samples.length,
    median_ms: percentile(samples, 0.5),
    p95_ms: percentile(samples, 0.95),
    minimum_ms: samples[0],
    maximum_ms: samples.at(-1)
  };
}

function element(tagName, attributes = {}, textContent = "") {
  return {
    tagName,
    textContent,
    parentElement: null,
    getAttribute(name) { return attributes[name] ?? null; },
    closest() { return null; },
    querySelectorAll(selector) {
      if (selector === "input, textarea, select") return attributes.fields || [];
      return [];
    }
  };
}

const fields = [
  element("INPUT", { type: "email", name: "email", autocomplete: "email" }),
  element("INPUT", { type: "password", name: "password", autocomplete: "current-password" })
];
const form = element("FORM", { method: "POST", action: "/session", fields });
const heading = element("H1", {}, "Entrar na conta");
const documentFixture = {
  title: "Área do cliente",
  querySelectorAll(selector) {
    const table = {
      "h1, h2": [heading],
      "img[alt]": [],
      form: [form],
      "input, textarea, select": fields,
      script: [{}, {}, {}],
      iframe: [],
      "dialog, [role='dialog']": [],
      "button[type='submit'], input[type='submit']": [{}],
      "meta[http-equiv]": []
    };
    return table[selector] || [];
  }
};

function main() {
  fs.mkdirSync(OUTPUT, { recursive: true });
  const reputationPath = path.join(ROOT, "reputation", "threat-db.json");
  const reputationData = JSON.parse(fs.readFileSync(reputationPath, "utf8"));
  const reputation = createReputationDatabase(reputationData);
  const urls = [
    "https://example.com/",
    "https://accounts.example.com/login",
    "http://account-security-login-7392-x9.tenant.pages.dev/",
    "https://paypal.example@secure-login.test/account"
  ];
  const initial = collectPageSnapshotV4(documentFixture, urls[1], "initial");
  const late = collectPageSnapshotV4(documentFixture, urls[1], "late");
  const merged = mergePageSnapshotsV4(initial, late);
  const page = analyzePageV4(merged);
  const local = analyzeUrlV4(urls[1]);
  const reputationResult = checkExternalReputation(urls[1], reputation);

  const stages = [
    benchmark("url_analysis", (index) => analyzeUrlV4(urls[index % urls.length])),
    benchmark("reputation_lookup", (index) => checkExternalReputation(urls[index % urls.length], reputation)),
    benchmark("initial_snapshot", () => collectPageSnapshotV4(documentFixture, urls[1], "initial")),
    benchmark("late_snapshot", () => collectPageSnapshotV4(documentFixture, urls[1], "late")),
    benchmark("snapshot_merge", () => mergePageSnapshotsV4(initial, late)),
    benchmark("page_analysis", () => analyzePageV4(merged)),
    benchmark("evidence_integration", () => combineV4Evidence(local, page, reputationResult)),
    benchmark("complete_cpu_pipeline", (index) => {
      const url = urls[index % urls.length];
      const urlResult = analyzeUrlV4(url);
      const reputationValue = checkExternalReputation(url, reputation);
      const first = collectPageSnapshotV4(documentFixture, url, "initial");
      const second = collectPageSnapshotV4(documentFixture, url, "late");
      const pageResult = analyzePageV4(mergePageSnapshotsV4(first, second));
      combineV4Evidence(urlResult, pageResult, reputationValue);
    })
  ];
  const memory = process.memoryUsage();
  const result = {
    status: "development-benchmark",
    independent_validation: false,
    executed_at: new Date().toISOString(),
    timezone: "America/Bahia",
    repository_head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    environment: { node: process.version, platform: os.platform(), release: os.release(), architecture: os.arch() },
    configured_late_observation_delay_ms: V4_LATE_OBSERVATION_DELAY_MS,
    delay_excluded_from_cpu_pipeline: true,
    stages,
    memory_bytes: memory,
    reputation_database: {
      path: "reputation/threat-db.json",
      sha256: sha256File(reputationPath),
      bytes: fs.statSync(reputationPath).size,
      urls: reputationData.urls?.length || 0,
      domains: reputationData.domains?.length || 0
    },
    detector_hashes: Object.fromEntries([
      "analysis-v4.js", "page-analysis-v4.js", "combined-analysis-v4.js", "reputation.js"
    ].map((relative) => [relative, sha256File(path.join(ROOT, relative))]))
  };
  fs.writeFileSync(path.join(OUTPUT, "benchmark.json"), `${JSON.stringify(result, null, 2)}\n`);
  writeArtifactHashes(OUTPUT);
  console.log(JSON.stringify(result, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
