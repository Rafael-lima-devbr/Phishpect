const WARNING_STATE_TTL_MS = 10 * 60_000;

function validWarningToken(value) {
  return typeof value === "string" && /^[a-f0-9-]{20,64}$/i.test(value);
}

function createWarningState(url, evaluation, now = Date.now(), ttl = WARNING_STATE_TTL_MS) {
  const parsed = new URL(url);
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Destino de aviso inválido");
  const input = evaluation && typeof evaluation === "object" ? evaluation : {};
  const level = input.finalClassification === "blocked" ? "blocked" : "suspicious";
  return {
    url: parsed.href,
    level,
    score: Number.isFinite(Number(input.score)) ? Math.max(0, Math.min(100, Number(input.score))) : 0,
    reasons: Array.isArray(input.reasons)
      ? input.reasons.filter((item) => typeof item === "string").slice(0, 100).map((item) => item.slice(0, 500))
      : [],
    groupedReasons: input.INTEGRATION?.grouped_reasons && typeof input.INTEGRATION.grouped_reasons === "object"
      ? Object.fromEntries(["url", "page", "reputation", "integration"].map((group) => [
        group,
        Array.isArray(input.INTEGRATION.grouped_reasons[group])
          ? input.INTEGRATION.grouped_reasons[group].filter((item) => typeof item === "string").slice(0, 40).map((item) => item.slice(0, 500))
          : []
      ]))
      : null,
    externalReputation: {
      listed: input.externalReputation?.listed === true,
      available: input.externalReputation?.available === true,
      source: typeof input.externalReputation?.source === "string" ? input.externalReputation.source.slice(0, 100) : null,
      matchType: ["exact-url", "domain"].includes(input.externalReputation?.matchType) ? input.externalReputation.matchType : null
    },
    expiresAt: now + ttl
  };
}

function normalizeWarningState(value, now = Date.now()) {
  if (!value || typeof value !== "object" || !Number.isFinite(value.expiresAt) || value.expiresAt <= now) return null;
  try {
    return createWarningState(value.url, {
      finalClassification: value.level,
      score: value.score,
      reasons: value.reasons,
      INTEGRATION: { grouped_reasons: value.groupedReasons },
      externalReputation: value.externalReputation
    }, now, value.expiresAt - now);
  } catch {
    return null;
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { WARNING_STATE_TTL_MS, validWarningToken, createWarningState, normalizeWarningState };
}
