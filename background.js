importScripts("vendor/tldts.umd.min.js", "analysis.js", "reputation.js", "combined-analysis.js", "navigation-state.js");

const pendingRedirects = new Map();
const pendingRedirectTracker = createPendingRedirectTracker(pendingRedirects);
let reputationDatabasePromise;

function allowanceKey(tabId) { return `allowOnce:${tabId}`; }
function postLoadAllowanceKey(tabId) { return `allowPostLoadOnce:${tabId}`; }

function isWebUrl(value) {
  try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
}

async function loadReputationDatabase() {
  if (!reputationDatabasePromise) {
    reputationDatabasePromise = fetch(chrome.runtime.getURL("reputation/threat-db.json"))
      .then((response) => {
        if (!response.ok) throw new Error("Base de reputação indisponível");
        return response.json();
      })
      .then(createReputationDatabase)
      .catch(() => {
        console.warn("Phishpect: base de reputação indisponível");
        return createReputationDatabase(null);
      });
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
  return { localAnalysis, externalReputation, finalClassification, score: localAnalysis.score, reasons };
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

async function redirectToWarning(tabId, url, evaluation) {
  const token = pendingRedirectTracker.begin(tabId, url);
  try {
    await Promise.resolve();
    if (!pendingRedirectTracker.isCurrent(tabId, token)) return false;
    await chrome.tabs.update(tabId, { url: buildWarningUrl(url, evaluation) });
    return true;
  } finally {
    pendingRedirectTracker.finish(tabId, token);
  }
}

async function readAllowance(key, url) {
  const stored = await chrome.storage.session.get(key);
  const value = stored[key];
  if (matchesNavigationAllowance(value, url)) return true;
  if (value !== undefined) await chrome.storage.session.remove(key);
  return false;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    const evaluation = await evaluateUrl(details.url);
    const allowKey = allowanceKey(details.tabId);
    const postLoadKey = postLoadAllowanceKey(details.tabId);
    if (evaluation.finalClassification === "safe") {
      await chrome.storage.session.remove([allowKey, postLoadKey]);
      return;
    }
    if (evaluation.finalClassification === "suspicious" && await readAllowance(allowKey, details.url)) {
      await chrome.storage.session.remove(allowKey);
      await chrome.storage.session.set({ [postLoadKey]: createNavigationAllowance(details.url) });
      return;
    }
    await chrome.storage.session.remove(postLoadKey);
    if (evaluation.finalClassification !== "suspicious") await chrome.storage.session.remove(allowKey);
    const pending = pendingRedirectTracker.current(details.tabId);
    if (pending?.url === details.url) return;
    await redirectToWarning(details.tabId, details.url, evaluation);
  } catch {
    console.warn("Phishpect: verificação de navegação indisponível");
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "evaluate-url") {
    if (!isWebUrl(message.url)) { sendResponse({ ok: false }); return; }
    evaluateUrl(message.url)
      .then((evaluation) => sendResponse({ ok: true, evaluation }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "evaluate-page") {
    if (!sender.tab?.id || !isWebUrl(message.url) || !sameDocumentUrl(sender.url, message.url)) {
      sendResponse({ ok: false });
      return;
    }
    const tabId = sender.tab.id;
    evaluateUrl(message.url).then(async (urlAnalysis) => {
      const combined = combineAnalyses(urlAnalysis, message.pageAnalysis);
      const postLoadKey = postLoadAllowanceKey(tabId);
      if (await readAllowance(postLoadKey, message.url)) {
        await chrome.storage.session.remove(postLoadKey);
        if (combined.finalClassification !== "blocked") {
          sendResponse({ ok: true, evaluation: combined, redirected: false, allowed: true });
          return;
        }
      }
      const shouldRedirect = combined.finalClassification === "blocked" ||
        (combined.finalClassification === "suspicious" && combined.COMBINED_ANALYSIS.page_added_risk);
      if (!shouldRedirect || pendingRedirects.has(tabId)) {
        sendResponse({ ok: true, evaluation: combined, redirected: false });
        return;
      }
      const redirected = await redirectToWarning(tabId, message.url, combined);
      sendResponse({ ok: true, evaluation: combined, redirected });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type !== "continue-navigation") return;
  if (!sender.tab?.id || !isWebUrl(message.url) || !isWarningPageUrl(sender.url, chrome.runtime.getURL("warning.html"))) {
    sendResponse({ ok: false });
    return;
  }
  evaluateUrl(message.url).then(async (evaluation) => {
    if (evaluation.finalClassification !== "suspicious") { sendResponse({ ok: false }); return; }
    const tabId = sender.tab.id;
    const key = allowanceKey(tabId);
    await chrome.storage.session.set({ [key]: createNavigationAllowance(message.url) });
    try {
      await chrome.tabs.update(tabId, { url: message.url });
      sendResponse({ ok: true });
    } catch {
      await chrome.storage.session.remove(key);
      sendResponse({ ok: false });
    }
  }).catch(() => sendResponse({ ok: false }));
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pendingRedirectTracker.remove(tabId);
  chrome.storage.session.remove([allowanceKey(tabId), postLoadAllowanceKey(tabId)]);
});
