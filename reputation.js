const REPUTATION_SOURCE = "Phishing.Database";

function normalizeDomain(value) {
  return value.trim().toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
}

function normalizeUrlForReputation(value) {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;

    parsed.hash = "";
    parsed.hostname = normalizeDomain(parsed.hostname);
    const sortedParameters = [...parsed.searchParams.entries()]
      .sort(([nameA, valueA], [nameB, valueB]) =>
        nameA.localeCompare(nameB) || valueA.localeCompare(valueB)
      );
    parsed.search = "";
    for (const [name, parameterValue] of sortedParameters) {
      parsed.searchParams.append(name, parameterValue);
    }

    const pathname = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, "");
    return `${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${pathname}${parsed.search}`;
  } catch {
    return null;
  }
}

function createReputationDatabase(data = null) {
  const available = Boolean(data && typeof data === "object" && Array.isArray(data.urls) && Array.isArray(data.domains));
  return {
    available,
    urls: new Set(available ? data.urls : []),
    domains: new Set(available ? data.domains : []),
    metadata: {
      generatedAt: available ? (data.generatedAt || null) : null,
      stats: available ? (data.stats || { urls: 0, domains: 0 }) : { urls: 0, domains: 0 }
    }
  };
}

function checkExternalReputation(url, database) {
  const normalizedUrl = normalizeUrlForReputation(url);
  let domain = null;
  try {
    domain = normalizeDomain(new URL(url).hostname);
  } catch {
    // URL inválida permanece responsabilidade da análise local.
  }

  if (normalizedUrl && database?.urls?.has(normalizedUrl)) {
    return { listed: true, available: Boolean(database?.available), source: REPUTATION_SOURCE, matchType: "exact-url" };
  }
  if (domain && database?.domains?.has(domain)) {
    return { listed: true, available: Boolean(database?.available), source: REPUTATION_SOURCE, matchType: "domain" };
  }
  return { listed: false, available: Boolean(database?.available), source: REPUTATION_SOURCE, matchType: null };
}

if (typeof module !== "undefined") {
  module.exports = {
    REPUTATION_SOURCE,
    normalizeDomain,
    normalizeUrlForReputation,
    createReputationDatabase,
    checkExternalReputation
  };
}
