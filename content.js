document.addEventListener("click", async (event) => {
  const link = event.target?.closest?.("a[href]");
  const decision = getNavigationDecision(event, link, window.location.href);
  if (!decision.intercept) return;
  const destination = decision.destination;

  event.preventDefault();
  event.stopImmediatePropagation();

  try {
    const response = await chrome.runtime.sendMessage({ type: "evaluate-url", url: destination });
    if (!response?.ok) throw new Error("Análise indisponível");

    const evaluation = response.evaluation;
    const nextUrl = evaluation.finalClassification === "safe"
      ? destination
      : buildWarningUrl(destination, evaluation);
    window.location.assign(nextUrl);
  } catch {
    try {
      const localAnalysis = analyzeUrl(destination);
      if (localAnalysis.level === "safe") {
        window.location.assign(destination);
        return;
      }
      window.location.assign(buildWarningUrl(destination, {
        finalClassification: localAnalysis.level,
        score: localAnalysis.score,
        reasons: localAnalysis.reasons,
        externalReputation: { listed: false, available: false }
      }));
    } catch {
      console.warn("Phishpect: análise de URL indisponível; navegação original restaurada");
      window.location.assign(destination);
    }
  }
}, true);

let postLoadAnalysisStarted = false;

async function runPostLoadAnalysis() {
  if (postLoadAnalysisStarted || !["http:", "https:"].includes(window.location.protocol)) return;
  postLoadAnalysisStarted = true;

  try {
    const snapshot = collectPageSnapshot(document, window.location.href);
    const pageAnalysis = analyzePage(snapshot);
    await chrome.runtime.sendMessage({
      type: "evaluate-page",
      url: window.location.href,
      pageAnalysis
    });
  } catch {
    // A análise pós-carregamento é complementar e nunca deve impedir a navegação.
    console.warn("Phishpect: análise pós-carregamento indisponível");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runPostLoadAnalysis, { once: true });
} else {
  runPostLoadAnalysis();
}

function buildWarningUrl(url, evaluation) {
  const warningUrl = new URL(chrome.runtime.getURL("warning.html"));
  warningUrl.searchParams.set("url", url);
  warningUrl.searchParams.set("level", evaluation.finalClassification);
  warningUrl.searchParams.set("score", String(evaluation.score));
  warningUrl.searchParams.set("reasons", JSON.stringify(evaluation.reasons));
  if (evaluation.externalReputation?.listed) {
    warningUrl.searchParams.set("externalSource", evaluation.externalReputation.source);
    warningUrl.searchParams.set("matchType", evaluation.externalReputation.matchType);
  }
  return warningUrl.href;
}
