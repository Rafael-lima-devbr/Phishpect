const PHISHPECT_PAGE_V4_VERSION = "4.0";
const V4_LATE_OBSERVATION_DELAY_MS = 1200;

function v4PageBaseModule() {
  if (typeof collectPageSnapshot === "function" && typeof analyzePage === "function") {
    return { collectPageSnapshot, analyzePage };
  }
  if (typeof require === "function") return require("./page-analysis-v2.js");
  throw new Error("PAGE_ANALYSIS 2.0 de referência indisponível");
}

function v4LimitedCount(documentObject, selector, limit) {
  try { return Math.min(documentObject.querySelectorAll(selector).length, limit); } catch { return 0; }
}

function v4MetaRefresh(documentObject, pageUrl) {
  const values = [];
  for (const element of [...documentObject.querySelectorAll("meta[http-equiv]")].slice(0, 8)) {
    if (String(element.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") continue;
    const content = String(element.getAttribute("content") || "").slice(0, 2048);
    const match = content.match(/url\s*=\s*['\"]?([^'\";]+)/i);
    if (!match) continue;
    try {
      const destination = new URL(match[1].trim(), pageUrl);
      if (["http:", "https:"].includes(destination.protocol)) values.push(destination.href);
    } catch {
      // Meta refresh inválido não é evidência.
    }
  }
  return values.slice(0, 4);
}

function collectPageSnapshotV4(documentObject, pageUrl, phase = "initial") {
  const base = v4PageBaseModule().collectPageSnapshot(documentObject, pageUrl);
  return {
    ...base,
    schema_version: 4,
    observation: {
      phase: phase === "late" ? "late" : "initial",
      scripts: v4LimitedCount(documentObject, "script", 200),
      iframes: v4LimitedCount(documentObject, "iframe", 50),
      dialogs: v4LimitedCount(documentObject, "dialog, [role='dialog']", 50),
      submit_controls: v4LimitedCount(documentObject, "button[type='submit'], input[type='submit']", 100),
      meta_refresh_targets: v4MetaRefresh(documentObject, pageUrl)
    }
  };
}

function v4StableKey(value) {
  const sorted = (input) => {
    if (Array.isArray(input)) return input.map(sorted);
    if (!input || typeof input !== "object") return input;
    return Object.fromEntries(Object.keys(input).sort().map((key) => [key, sorted(input[key])]));
  };
  return JSON.stringify(sorted(value));
}

function v4MergeUnique(left, right, maximum) {
  const output = [];
  const seen = new Set();
  for (const item of [...(Array.isArray(left) ? left : []), ...(Array.isArray(right) ? right : [])]) {
    const key = v4StableKey(item);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(item);
    if (output.length >= maximum) break;
  }
  return output;
}

function mergePageSnapshotsV4(initial, late) {
  const first = initial && typeof initial === "object" ? initial : {};
  const second = late && typeof late === "object" ? late : {};
  const initialForms = Array.isArray(first.forms) ? first.forms : [];
  const lateForms = Array.isArray(second.forms) ? second.forms : [];
  const initialFields = Array.isArray(first.orphan_fields) ? first.orphan_fields : [];
  const lateFields = Array.isArray(second.orphan_fields) ? second.orphan_fields : [];
  return {
    ...first,
    ...second,
    schema_version: 4,
    page_url: String(second.page_url || first.page_url || ""),
    title: String(second.title || first.title || "").slice(0, 240),
    identity_evidence: v4MergeUnique(first.identity_evidence, second.identity_evidence, 100),
    forms: v4MergeUnique(initialForms, lateForms, 40),
    orphan_fields: v4MergeUnique(initialFields, lateFields, 100),
    observations: [first.observation, second.observation].filter(Boolean).slice(0, 2),
    observation_delta: {
      forms_added: Math.max(0, lateForms.length - initialForms.length),
      orphan_fields_added: Math.max(0, lateFields.length - initialFields.length),
      identity_items_added: Math.max(0,
        (Array.isArray(second.identity_evidence) ? second.identity_evidence.length : 0) -
        (Array.isArray(first.identity_evidence) ? first.identity_evidence.length : 0))
    }
  };
}

function analyzePageV4(snapshot) {
  const base = v4PageBaseModule().analyzePage(snapshot);
  const observations = Array.isArray(snapshot?.observations)
    ? snapshot.observations.slice(0, 2)
    : (snapshot?.observation ? [snapshot.observation] : []);
  const delta = snapshot?.observation_delta && typeof snapshot.observation_delta === "object"
    ? snapshot.observation_delta
    : { forms_added: 0, orphan_fields_added: 0, identity_items_added: 0 };
  const metaRefreshTargets = [...new Set(observations.flatMap((item) =>
    Array.isArray(item?.meta_refresh_targets) ? item.meta_refresh_targets : []))].slice(0, 4);
  const lateContent = Number(delta.forms_added) > 0 || Number(delta.orphan_fields_added) > 0 || Number(delta.identity_items_added) > 0;
  const reasons = [...(base.reasons || [])];
  if (lateContent && base.level === "suspicious") reasons.push("Evidência contextual relevante apareceu na segunda observação limitada");
  return {
    ...base,
    version: PHISHPECT_PAGE_V4_VERSION,
    module: "page",
    reasons: [...new Set(reasons)],
    evidence_groups: [...(base.evidence_categories || [])],
    relationships: (base.contributions || []).filter((item) => [
      "external_credentials", "external_sensitive_data", "https_downgrade",
      "http_credentials", "brand_domain_mismatch"
    ].includes(item.code)).map((item) => ({
      code: item.code,
      groups: [item.category],
      reason: item.reason,
      strength: ["external_credentials", "brand_domain_mismatch", "http_credentials"].includes(item.code) ? "strong" : "moderate"
    })),
    signals: {
      ...(base.signals || {}),
      late_content_observed: lateContent,
      meta_refresh: metaRefreshTargets.length > 0
    },
    features: base.features ? {
      ...base.features,
      observation_count: observations.length,
      observation_delay_ms: observations.length > 1 ? V4_LATE_OBSERVATION_DELAY_MS : null,
      observation_delta: delta,
      structural_counts: {
        scripts: Math.max(0, ...observations.map((item) => Number(item?.scripts) || 0)),
        iframes: Math.max(0, ...observations.map((item) => Number(item?.iframes) || 0)),
        dialogs: Math.max(0, ...observations.map((item) => Number(item?.dialogs) || 0)),
        submit_controls: Math.max(0, ...observations.map((item) => Number(item?.submit_controls) || 0))
      },
      meta_refresh_targets: metaRefreshTargets
    } : null
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    PHISHPECT_PAGE_V4_VERSION,
    V4_LATE_OBSERVATION_DELAY_MS,
    collectPageSnapshotV4,
    mergePageSnapshotsV4,
    analyzePageV4
  };
}
