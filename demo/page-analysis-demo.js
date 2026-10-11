document.addEventListener("submit", (event) => event.preventDefault());

const demoUrl = document.querySelector('meta[name="phishpect-demo-url"]')?.content || window.location.href;
const snapshot = collectPageSnapshot(document, demoUrl);
const result = analyzePage(snapshot);
const output = document.createElement("section");
output.className = "analysis-result";

const heading = document.createElement("h2");
heading.textContent = `PAGE_ANALYSIS: ${result.level}`;
const summary = document.createElement("p");
summary.textContent = `Score ${result.score}/100 — categorias: ${result.evidence_categories.join(", ") || "nenhuma"}`;
const details = document.createElement("pre");
details.textContent = JSON.stringify(result, null, 2);

output.append(heading, summary, details);
document.body.append(output);
