importScripts("vendor/tldts.umd.min.js", "analysis.js", "reputation.js");

const pendingRedirects = new Map();
let reputationDatabasePromise;

function allowanceKey(tabId) {
  return `allowOnce:${tabId}`;
}

async function loadReputationDatabase() {
  if (!reputationDatabasePromise) {
    reputationDatabasePromise = fetch(chrome.runtime.getURL("reputation/threat-db.json"))
      .then((response) => {
        if (!response.ok) throw new Error("Base de reputação indisponível");
        return response.json();
      })
      .then(createReputationDatabase)
      .catch(() => createReputationDatabase());
  }
  return reputationDatabasePromise;
}

async function evaluateUrl(url) {
  const localAnalysis = analyzeUrl(url);
  const database = await loadReputationDatabase();
  const externalReputation = checkExternalReputation(url, database);
  let finalClassification = localAnalysis.level;
  const reasons = [...localAnalysis.reasons];

  if (externalReputation.listed) {
    finalClassification = "blocked";
    reasons.push("Esta URL foi identificada em uma base externa de reputação de phishing");
  }

  return {
    localAnalysis,
    externalReputation,
    finalClassification,
    score: localAnalysis.score,
    reasons
  };
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

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const evaluation = await evaluateUrl(details.url);
  if (evaluation.finalClassification === "safe") return;

  const key = allowanceKey(details.tabId);
  const stored = await chrome.storage.session.get(key);
  if (stored[key] === details.url && evaluation.finalClassification === "suspicious") {
    await chrome.storage.session.remove(key);
    return;
  }

  if (pendingRedirects.get(details.tabId) === details.url) return;
  pendingRedirects.set(details.tabId, details.url);
  try {
    await chrome.tabs.update(details.tabId, { url: buildWarningUrl(details.url, evaluation) });
  } finally {
    pendingRedirects.delete(details.tabId);
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "open-result-url" && sender.tab?.id) {
    const isWebUrl = /^https?:\/\//.test(message.url);
    const isWarningUrl = message.url.startsWith(chrome.runtime.getURL("warning.html"));
    if (isWebUrl || isWarningUrl) chrome.tabs.create({ url: message.url });
    return;
  }

  if (message?.type === "evaluate-url") {
    evaluateUrl(message.url)
      .then((evaluation) => sendResponse({ ok: true, evaluation }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type !== "continue-navigation" || !sender.tab?.id) return;

  evaluateUrl(message.url).then(async (evaluation) => {
    if (evaluation.finalClassification !== "suspicious") {
      sendResponse({ ok: false });
      return;
    }

    const tabId = sender.tab.id;
    const key = allowanceKey(tabId);
    await chrome.storage.session.set({ [key]: message.url });
    await chrome.tabs.update(tabId, { url: message.url });
    sendResponse({ ok: true });
  }).catch(() => sendResponse({ ok: false }));
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pendingRedirects.delete(tabId);
  chrome.storage.session.remove(allowanceKey(tabId));
});
