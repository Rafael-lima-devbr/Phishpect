const fs = require("node:fs");
const path = require("node:path");
const { analyzeUrlV4 } = require("../../analysis-v4.js");
const { parseCsv } = require("../v4/evaluation-lib.js");

const datasets = {
  A: "evaluation/datasets/dataset-a.csv",
  B: "evaluation/datasets/dataset-b.csv",
  C: "evaluation/datasets/dataset-c.csv",
  D: "evaluation/datasets/dataset-d.csv"
};

function phishing(label) {
  return ["1", "true", "phish", "phishing", "malicious", "fraudulent"].includes(String(label).toLowerCase());
}

function increment(object, key) {
  object[key] = (object[key] || 0) + 1;
}

function summarize(records) {
  const groups = { all: [], legitimate: [], phishing: [], false_positive: [], false_negative: [], true_positive: [], true_negative: [] };
  for (const record of records) {
    groups.all.push(record);
    groups[record.actual ? "phishing" : "legitimate"].push(record);
    const prefix = record.actual ? (record.predicted ? "true_positive" : "false_negative") : (record.predicted ? "false_positive" : "true_negative");
    groups[prefix].push(record);
  }
  return Object.fromEntries(Object.entries(groups).map(([name, rows]) => {
    const features = {}, categories = {}, combinations = {}, scoreBands = {};
    for (const row of rows) {
      for (const [key, value] of Object.entries(row.features)) if (value === true) increment(features, key);
      for (const category of row.categories) increment(categories, category);
      increment(combinations, row.categories.length ? row.categories.slice().sort().join("+") : "none");
      const band = `${Math.floor(row.score / 5) * 5}-${Math.floor(row.score / 5) * 5 + 4}`;
      increment(scoreBands, band);
    }
    const sorted = (value) => Object.fromEntries(Object.entries(value).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])));
    return [name, { count: rows.length, features: sorted(features), categories: sorted(categories), category_combinations: sorted(combinations), score_bands: sorted(scoreBands) }];
  }));
}

function urlRecord(row) {
  const result = analyzeUrlV4(row.url);
  const codes = new Set((result.contributions || []).map((item) => item.code));
  const featureNames = [
    "http", "shared_hosting", "auth_hostname", "auth_path", "nested_url", "redirect_parameter",
    "punycode", "brand_mismatch", "brand_typo", "long_url", "long_hostname", "many_subdomains",
    "many_hyphens", "high_digit_ratio", "high_entropy", "direct_ip", "unusual_port", "userinfo",
    "multiple_at", "long_path", "many_query_parameters", "encoded_url", "shortener"
  ];
  const mapping = {
    http: result.features?.protocol === "http",
    shared_hosting: result.signals?.uses_shared_hosting === true,
    auth_hostname: result.signals?.authentication_in_hostname === true,
    auth_path: result.signals?.authentication_in_pathname === true,
    nested_url: result.signals?.nested_url === true,
    redirect_parameter: result.signals?.redirect_parameter === true,
    punycode: result.signals?.punycode === true,
    brand_mismatch: result.signals?.brand_mismatch === true,
    direct_ip: result.signals?.uses_ip === true,
    unusual_port: result.signals?.unusual_port === true,
    userinfo: result.signals?.uses_userinfo === true,
    multiple_at: result.signals?.multiple_at === true,
    shortener: result.signals?.uses_shortener === true
  };
  for (const name of featureNames) if (!Object.hasOwn(mapping, name)) mapping[name] = codes.has(name);
  return { actual: phishing(row.label), predicted: result.level !== "safe", score: result.score,
    categories: result.evidence_groups || [], features: mapping };
}

const output = { generated_at: new Date().toISOString(), role: "V4.1 development error analysis; not independent validation", datasets: {} };
const combined = [];
for (const [name, file] of Object.entries(datasets)) {
  const records = parseCsv(fs.readFileSync(file, "utf8")).map(urlRecord);
  combined.push(...records);
  output.datasets[name] = summarize(records);
}
output.global = summarize(combined);

const pageRows = parseCsv(fs.readFileSync("evaluation/results/v4/development/page-regression/predictions.csv", "utf8"));
const pageRecords = pageRows.map((row) => ({
  actual: phishing(row.label), predicted: row.complete_v4 !== "safe", score: Number(row.score) || 0,
  categories: [...JSON.parse(row.url_groups || "[]").map((item) => `url.${item}`), ...JSON.parse(row.page_groups || "[]").map((item) => `page.${item}`)],
  features: Object.fromEntries(Object.entries({ ...JSON.parse(row.url_signals || "{}"), ...Object.fromEntries(Object.entries(JSON.parse(row.page_signals || "{}")).map(([key, value]) => [`page_${key}`, value])) }).map(([key, value]) => [key, value === true]))
}));
output.page_corpus = summarize(pageRecords);

const destination = "evaluation/results/v4.1/development/error-analysis.json";
fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.writeFileSync(destination, `${JSON.stringify(output, null, 2)}\n`);
console.log(destination);
