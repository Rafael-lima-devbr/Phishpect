document.addEventListener("click", async (event) => {
  const link = event.target?.closest?.("a[href]");
  const decision = getNavigationDecision(event, link, window.location.href);
  if (!decision.intercept) return;
  const destination = decision.destination;

  event.preventDefault();
  event.stopImmediatePropagation();

  try {
    const response = await chrome.runtime.sendMessage({ type: "evaluate-url-v4", url: destination });
    if (!response?.ok) throw new Error("Análise indisponível");
    window.location.assign(response.evaluation.finalClassification === "safe"
      ? destination
      : response.warningUrl);
  } catch {
    // Sem o background não é possível criar estado de aviso autenticado. A
    // navegação original é restaurada para não quebrar o comportamento nativo.
    try {
      const localAnalysis = analyzeUrlV4(destination);
      if (localAnalysis.level !== "safe") {
        console.warn("Phishpect: background indisponível; navegação original restaurada");
      }
    } catch {
      console.warn("Phishpect: análise de URL indisponível; navegação original restaurada");
    }
    window.location.assign(destination);
  }
}, true);

let postLoadAnalysisStarted = false;

function waitForLateObservation() {
  return new Promise((resolve) => setTimeout(resolve, V4_LATE_OBSERVATION_DELAY_MS));
}

async function runPostLoadAnalysisV4() {
  if (postLoadAnalysisStarted || !["http:", "https:"].includes(window.location.protocol)) return;
  postLoadAnalysisStarted = true;
  const observedUrl = window.location.href;

  try {
    const initial = collectPageSnapshotV4(document, observedUrl, "initial");
    await waitForLateObservation();
    if (window.location.href !== observedUrl) return;
    const late = collectPageSnapshotV4(document, observedUrl, "late");
    const pageAnalysis = analyzePageV4(mergePageSnapshotsV4(initial, late));
    await chrome.runtime.sendMessage({ type: "evaluate-page-v4", url: observedUrl, pageAnalysis });
  } catch {
    // A camada pós-carregamento é complementar e nunca impede a navegação.
    console.warn("Phishpect: análise pós-carregamento indisponível");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runPostLoadAnalysisV4, { once: true });
} else {
  runPostLoadAnalysisV4();
}
