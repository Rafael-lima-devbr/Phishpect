document.addEventListener("click", async (event) => {
  if (event.defaultPrevented || event.button !== 0) return;

  const link = event.target.closest("a[href]");
  if (!link || link.hasAttribute("download")) return;

  const destination = new URL(link.href, document.baseURI);
  if (!["http:", "https:"].includes(destination.protocol)) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  const openInNewTab = link.target === "_blank" || event.ctrlKey || event.metaKey || event.shiftKey;

  try {
    const response = await chrome.runtime.sendMessage({ type: "evaluate-url", url: destination.href });
    if (!response?.ok) throw new Error("Análise indisponível");

    const evaluation = response.evaluation;
    const nextUrl = evaluation.finalClassification === "safe"
      ? destination.href
      : buildWarningUrl(destination.href, evaluation);

    if (openInNewTab) {
      await chrome.runtime.sendMessage({ type: "open-result-url", url: nextUrl });
    } else {
      window.location.assign(nextUrl);
    }
  } catch {
    const localAnalysis = analyzeUrl(destination.href);
    if (localAnalysis.level === "safe") {
      if (openInNewTab) window.open(destination.href, "_blank", "noopener");
      else window.location.assign(destination.href);
      return;
    }
    window.location.assign(buildWarningUrl(destination.href, {
      finalClassification: localAnalysis.level,
      score: localAnalysis.score,
      reasons: localAnalysis.reasons,
      externalReputation: { listed: false }
    }));
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
  if (evaluation.externalReputation.listed) {
    warningUrl.searchParams.set("externalSource", evaluation.externalReputation.source);
    warningUrl.searchParams.set("matchType", evaluation.externalReputation.matchType);
  }
  return warningUrl.href;
}
