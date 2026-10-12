const { performance } = require("node:perf_hooks");
const { analyzeUrl } = require("../analysis.js");
const { analyzePage } = require("../page-analysis.js");
const { combineAnalyses } = require("../combined-analysis.js");

const iterations = Number(process.argv.find((argument) => argument.startsWith("--iterations="))?.split("=")[1]) || 5_000;
const urls = [
  "https://example.com/",
  "https://accounts.example.com/login",
  "http://login-user-1234-a.example.com/",
  "https://demo.github.io/example-login"
];
const pageSnapshot = {
  page_url: "https://accounts.example.com/login",
  title: "Área do cliente",
  headings: ["Entrar"],
  image_alts: [],
  forms: [{
    method: "POST",
    action: "/session",
    fields: [
      { tag: "input", type: "email", name: "email", id: "", autocomplete: "email" },
      { tag: "input", type: "password", name: "password", id: "", autocomplete: "current-password" }
    ]
  }]
};

const startedAt = performance.now();
for (let index = 0; index < iterations; index += 1) {
  const localAnalysis = analyzeUrl(urls[index % urls.length]);
  const pageAnalysis = analyzePage(pageSnapshot);
  combineAnalyses({
    localAnalysis,
    finalClassification: localAnalysis.level,
    score: localAnalysis.score,
    reasons: localAnalysis.reasons,
    externalReputation: { listed: false, available: true }
  }, pageAnalysis);
}
const elapsed = performance.now() - startedAt;
console.log(JSON.stringify({
  iterations,
  elapsed_ms: Number(elapsed.toFixed(2)),
  average_ms: Number((elapsed / iterations).toFixed(4))
}, null, 2));
