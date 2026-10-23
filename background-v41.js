importScripts(
  "vendor/tldts.umd.min.js",
  "analysis.js", "analysis-v4.js", "analysis-v41.js",
  "reputation.js",
  "page-analysis-v2.js", "page-analysis-v4.js",
  "combined-analysis-v4.js", "combined-analysis-v41.js",
  "navigation-state.js", "warning-state.js"
);

const pendingRedirects = new Map();
const pendingRedirectTracker = createPendingRedirectTracker(pendingRedirects);
let reputationDatabasePromise;

function allowanceKey(tabId) { return `allowOnce:${tabId}`; }
function postLoadAllowanceKey(tabId) { return `allowPostLoadOnce:${tabId}`; }
function warningStateKey(token) { return `warning:${token}`; }

function isWebUrl(value) {
  try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
}

function validSenderTab(sender) {
  return Number.isInteger(sender?.tab?.id) && sender.tab.id >= 0;
}

function createOpaqueToken() {
  if (globalThis.crypto?.randomUUID) return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
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

async function evaluateUrlV41(url) {
  const localAnalysis = analyzeUrlV41(url);
  const database = await loadReputationDatabase();
  const externalReputation = checkExternalReputation(url, database);
  return combineV41Evidence(localAnalysis, null, externalReputation);
}

async function createWarningUrl(url, evaluation) {
  const token = createOpaqueToken();
  await chrome.storage.session.set({ [warningStateKey(token)]: createWarningState(url, evaluation) });
  const warningUrl = new URL(chrome.runtime.getURL("warning.html"));
  warningUrl.searchParams.set("token", token);
  return warningUrl.href;
}

async function loadWarningState(token) {
  if (!validWarningToken(token)) return null;
  const key = warningStateKey(token);
  const stored = await chrome.storage.session.get(key);
  const state = normalizeWarningState(stored[key]);
  if (!state && stored[key] !== undefined) await chrome.storage.session.remove(key);
  return state;
}

async function redirectToWarning(tabId, url, evaluation) {
  const redirectToken = pendingRedirectTracker.begin(tabId, url);
  try {
    const warningUrl = await createWarningUrl(url, evaluation);
    if (!pendingRedirectTracker.isCurrent(tabId, redirectToken)) return false;
    await chrome.tabs.update(tabId, { url: warningUrl });
    return true;
  } finally {
    pendingRedirectTracker.finish(tabId, redirectToken);
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
  if (details.frameId !== 0 || !isWebUrl(details.url)) return;
  try {
    const evaluation = await evaluateUrlV41(details.url);
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
    if (pendingRedirectTracker.current(details.tabId)?.url === details.url) return;
    await redirectToWarning(details.tabId, details.url, evaluation);
  } catch {
    console.warn("Phishpect: verificação de navegação indisponível");
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "evaluate-url-v4") {
    if (!validSenderTab(sender) || !isWebUrl(message.url)) { sendResponse({ ok: false }); return; }
    evaluateUrlV41(message.url).then(async (evaluation) => {
      const warningUrl = evaluation.finalClassification === "safe" ? null : await createWarningUrl(message.url, evaluation);
      sendResponse({ ok: true, evaluation, warningUrl });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "evaluate-page-v4") {
    if (!validSenderTab(sender) || !isWebUrl(message.url) || !sameDocumentUrl(sender.url, message.url)) {
      sendResponse({ ok: false });
      return;
    }
    const tabId = sender.tab.id;
    evaluateUrlV41(message.url).then(async (urlEvaluation) => {
      const combined = combineV41Evidence(urlEvaluation.URL, message.pageAnalysis, urlEvaluation.REPUTATION);
      const postLoadKey = postLoadAllowanceKey(tabId);
      if (await readAllowance(postLoadKey, message.url)) {
        await chrome.storage.session.remove(postLoadKey);
        if (combined.finalClassification !== "blocked") {
          sendResponse({ ok: true, evaluation: combined, redirected: false, allowed: true });
          return;
        }
      }
      const pageAddedRisk = urlEvaluation.finalClassification === "safe" && combined.finalClassification !== "safe";
      const shouldRedirect = combined.finalClassification === "blocked" || pageAddedRisk;
      if (!shouldRedirect || pendingRedirects.has(tabId)) {
        sendResponse({ ok: true, evaluation: combined, redirected: false });
        return;
      }
      const redirected = await redirectToWarning(tabId, message.url, combined);
      sendResponse({ ok: true, evaluation: combined, redirected });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "get-warning-state") {
    if (!isWarningPageUrl(sender.url, chrome.runtime.getURL("warning.html")) || !validWarningToken(message.token)) {
      sendResponse({ ok: false });
      return;
    }
    loadWarningState(message.token)
      .then((state) => sendResponse(state ? { ok: true, state } : { ok: false }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type !== "continue-navigation-v4") return;
  if (!validSenderTab(sender) || !isWarningPageUrl(sender.url, chrome.runtime.getURL("warning.html")) || !validWarningToken(message.token)) {
    sendResponse({ ok: false });
    return;
  }
  loadWarningState(message.token).then(async (state) => {
    if (!state) { sendResponse({ ok: false }); return; }
    const evaluation = await evaluateUrlV41(state.url);
    if (evaluation.finalClassification !== "suspicious") { sendResponse({ ok: false }); return; }
    const tabId = sender.tab.id;
    const key = allowanceKey(tabId);
    await chrome.storage.session.set({ [key]: createNavigationAllowance(state.url) });
    try {
      await chrome.tabs.update(tabId, { url: state.url });
      await chrome.storage.session.remove(warningStateKey(message.token));
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
