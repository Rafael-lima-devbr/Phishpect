const assert = require("node:assert/strict");
const { analyzeUrlV41 } = require("../analysis-v41.js");

assert.equal(analyzeUrlV41("http://example.test/").level, "safe", "HTTP isolado deve permanecer safe");
assert.equal(analyzeUrlV41("http://tenant.pages.dev/").level, "suspicious", "HTTP + shared hosting deve corroborar risco");
assert.equal(analyzeUrlV41("https://tenant.pages.dev/").level, "safe", "shared hosting HTTPS isolado deve permanecer safe");
assert.equal(analyzeUrlV41("https://sensational-kitten-0c29a9.pages.dev/").level, "suspicious", "shared hosting + alta entropia deve ser suspicious");
assert.equal(analyzeUrlV41("https://docs.pages.dev/").level, "safe", "tenant simples em shared hosting deve permanecer safe");
assert.equal(analyzeUrlV41("https://project-2026.pages.dev/").level, "safe", "shared hosting + dígitos não deve decidir sozinho");
assert.equal(analyzeUrlV41("http://portal--access-2026.example.test/").level, "suspicious", "HTTP + estrutura anormal deve ser suspicious");
assert.equal(analyzeUrlV41("https://portal--access-2026.example.test/").level, "safe", "estrutura moderada em HTTPS não deve decidir sozinha");
assert.equal(analyzeUrlV41("https://login-user.pages.dev/").level, "suspicious", "auth no hostname + shared hosting deve ser suspicious");
assert.equal(analyzeUrlV41("https://tenant.pages.dev/login").level, "safe", "shared hosting + login normal no path deve permanecer safe");
assert.equal(analyzeUrlV41("http://example.test/login").level, "suspicious", "HTTP + auth path deve formar relação contextual");
assert.equal(analyzeUrlV41("https://example.test/login").level, "safe", "auth path HTTPS isolado deve permanecer safe");
assert.equal(analyzeUrlV41("https://paypal.example.test/").level, "safe", "brand mismatch exato isolado continua inelegível");
assert.equal(analyzeUrlV41("https://docs.github.io/paypal-sdk-reference/").level, "safe", "marca no path de documentação hospedada não deve decidir sozinha");
console.log("Análise contextual V4.1 de URL: OK");
