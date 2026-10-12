function sameDocumentFragmentNavigation(currentValue, destinationValue) {
  try {
    const current = new URL(currentValue);
    const destination = new URL(destinationValue, current);
    if (current.origin !== destination.origin || current.pathname !== destination.pathname || current.search !== destination.search) {
      return false;
    }
    return Boolean(destination.hash);
  } catch {
    return false;
  }
}

function getNavigationDecision(event, link, currentUrl) {
  if (!event || event.defaultPrevented || event.button !== 0) return { intercept: false };
  if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return { intercept: false };
  if (!link || link.hasAttribute?.("download")) return { intercept: false };

  const target = String(link.getAttribute?.("target") || link.target || "").trim().toLowerCase();
  if (target && target !== "_self") return { intercept: false };

  try {
    const destination = new URL(link.href || link.getAttribute?.("href"), currentUrl);
    if (!["http:", "https:"].includes(destination.protocol)) return { intercept: false };
    if (sameDocumentFragmentNavigation(currentUrl, destination.href)) return { intercept: false };
    return { intercept: true, destination: destination.href };
  } catch {
    return { intercept: false };
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { getNavigationDecision, sameDocumentFragmentNavigation };
}
