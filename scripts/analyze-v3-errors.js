const fs = require("node:fs");
const path = require("node:path");

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
      row.push(field); if (row.some(Boolean)) rows.push(row); row = []; field = "";
    } else field += character;
  }
  row.push(field); if (row.some(Boolean)) rows.push(row);
  return rows;
}

function readRecords(filePath) {
  const rows = parseCsv(fs.readFileSync(filePath, "utf8"));
  const columns = rows.shift();
  return rows.map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index] || ""])))
    .map((record) => ({
      ...record,
      score: Number(record.local_score),
      features: JSON.parse(record.local_features || "null") || {},
      signals: JSON.parse(record.local_signals || "{}"),
      contributions: JSON.parse(record.local_contributions || "[]")
    }));
}

function flagsFor(record) {
  const { features, signals, contributions } = record;
  const codes = new Set(contributions.map(({ code }) => code));
  return {
    http: features.protocol === "http",
    long_url: features.url_length > 150,
    long_path: features.pathname_length > 80,
    long_hostname: features.hostname_length > 60,
    many_subdomains: features.subdomain_count >= 3,
    many_hyphens: features.hyphen_count >= 3,
    many_digits: features.digit_count >= 4,
    high_digit_ratio: features.digit_count >= 4 && features.hostname_digit_ratio >= 0.2,
    auth_hostname: (features.hostname_authentication_terms || []).length > 0,
    auth_path: (features.pathname_authentication_terms || []).length > 0,
    exact_brand_mismatch: signals.brand_mismatch === true && signals.brand_match_type === "exact",
    possible_typosquatting: signals.brand_mismatch === true && signals.brand_match_type === "typo",
    shared_hosting: signals.uses_shared_hosting === true,
    shortener: codes.has("shortener"),
    punycode: signals.punycode === true,
    userinfo: codes.has("userinfo") || codes.has("brand_in_userinfo"),
    many_query_parameters: features.parameter_count >= 5,
    high_entropy: codes.has("high_entropy")
  };
}

function categoriesFor(flags) {
  return {
    identity: flags.exact_brand_mismatch || flags.possible_typosquatting || flags.userinfo,
    authentication: flags.auth_hostname,
    structure: flags.long_hostname || flags.many_subdomains || flags.many_hyphens ||
      flags.high_digit_ratio || flags.high_entropy,
    transport: flags.http,
    path_query: flags.long_url || flags.long_path || flags.auth_path || flags.many_query_parameters,
    infrastructure: flags.shared_hosting || flags.shortener
  };
}

function countFlags(records) {
  const sampleFlags = flagsFor(records[0] || { features: {}, signals: {}, contributions: [] });
  const counts = Object.fromEntries(Object.keys(sampleFlags).map((name) => [name, 0]));
  for (const record of records) {
    for (const [name, active] of Object.entries(flagsFor(record))) {
      if (active) counts[name] = (counts[name] || 0) + 1;
    }
  }
  return Object.fromEntries(Object.entries(counts).sort((left, right) => right[1] - left[1]));
}

function categoryPatterns(records) {
  const counts = new Map();
  for (const record of records) {
    const pattern = Object.entries(categoriesFor(flagsFor(record)))
      .filter(([, active]) => active)
      .map(([name]) => name)
      .sort()
      .join("+") || "none";
    counts.set(pattern, (counts.get(pattern) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((left, right) => right.count - left.count || left.pattern.localeCompare(right.pattern));
}

function categoryPairs(records) {
  const counts = new Map();
  for (const record of records) {
    const active = Object.entries(categoriesFor(flagsFor(record)))
      .filter(([, enabled]) => enabled)
      .map(([name]) => name)
      .sort();
    for (let left = 0; left < active.length; left += 1) {
      for (let right = left + 1; right < active.length; right += 1) {
        const pair = `${active[left]}+${active[right]}`;
        counts.set(pair, (counts.get(pair) || 0) + 1);
      }
    }
  }
  return Object.fromEntries([...counts.entries()].sort((left, right) => right[1] - left[1]));
}

function summarizeDataset(filePath) {
  const records = readRecords(filePath);
  const phishing = records.filter(({ label }) => label === "phishing");
  const legitimate = records.filter(({ label }) => label === "legitimate");
  const falseNegatives = phishing.filter(({ local_classification }) => local_classification === "safe");
  return {
    source: filePath,
    totals: { phishing: phishing.length, legitimate: legitimate.length, false_negatives: falseNegatives.length },
    false_negative_features: countFlags(falseNegatives),
    phishing_features: countFlags(phishing),
    legitimate_features: countFlags(legitimate),
    false_negative_category_patterns: categoryPatterns(falseNegatives),
    phishing_category_pairs: categoryPairs(phishing),
    legitimate_category_pairs: categoryPairs(legitimate)
  };
}

function main() {
  const [, , outputPath, ...inputPaths] = process.argv;
  if (!outputPath || inputPaths.length === 0) {
    throw new Error("Uso: node scripts/analyze-v3-errors.js saida.json resultado-v3.csv [...]");
  }
  const report = {
    generated_at: new Date().toISOString(),
    methodology: "Datasets A e B são dados de desenvolvimento da V3/V3.1.",
    datasets: inputPaths.map(summarizeDataset)
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
