const NAVIGATION_ALLOWANCE_TTL_MS = 60_000;

function createNavigationAllowance(url, now = Date.now(), ttl = NAVIGATION_ALLOWANCE_TTL_MS) {
  return { url: String(url), expiresAt: now + ttl };
}

function matchesNavigationAllowance(value, url, now = Date.now()) {
  return Boolean(
    value && typeof value === "object" &&
    typeof value.url === "string" && value.url === url &&
    Number.isFinite(value.expiresAt) && value.expiresAt > now
  );
}

function isExpiredNavigationAllowance(value, now = Date.now()) {
  return !value || typeof value !== "object" || !Number.isFinite(value.expiresAt) || value.expiresAt <= now;
}

function sameDocumentUrl(leftValue, rightValue) {
  try {
    const left = new URL(leftValue);
    const right = new URL(rightValue);
    left.hash = "";
    right.hash = "";
    return left.href === right.href;
  } catch {
    return false;
  }
}

function isWarningPageUrl(senderUrl, expectedWarningUrl) {
  try {
    const sender = new URL(senderUrl);
    const expected = new URL(expectedWarningUrl);
    return sender.protocol === expected.protocol && sender.hostname === expected.hostname &&
      sender.port === expected.port && sender.pathname === expected.pathname;
  } catch {
    return false;
  }
}

function createPendingRedirectTracker(storage = new Map()) {
  return {
    begin(tabId, url) {
      const token = { url };
      storage.set(tabId, token);
      return token;
    },
    current(tabId) { return storage.get(tabId); },
    isCurrent(tabId, token) { return storage.get(tabId) === token; },
    finish(tabId, token) {
      if (storage.get(tabId) === token) storage.delete(tabId);
    },
    remove(tabId) { storage.delete(tabId); }
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    NAVIGATION_ALLOWANCE_TTL_MS,
    createNavigationAllowance,
    matchesNavigationAllowance,
    isExpiredNavigationAllowance,
    sameDocumentUrl,
    isWarningPageUrl,
    createPendingRedirectTracker
  };
}
