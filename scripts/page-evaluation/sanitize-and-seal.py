from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "evaluation" / "page-corpus"
ACQUISITION = CORPUS / "acquisition-manifest.json"
MANIFEST = CORPUS / "corpus-manifest.json"
SANITIZED = CORPUS / "sanitized"
SNAPSHOTS = CORPUS / "snapshots"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def clean_text(value: Any, maximum: int = 240) -> str:
    return " ".join(str(value or "").split())[:maximum]


def attr(tag: Any, name: str, maximum: int = 120) -> str:
    value = tag.attrs.get(name, "") if getattr(tag, "attrs", None) else ""
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    return clean_text(value, maximum)


def snapshot_from_html(raw: bytes, page_url: str) -> tuple[dict[str, Any], dict[str, int]]:
    soup = BeautifulSoup(raw, "html.parser")
    forms = []
    for form in soup.find_all("form", limit=30):
        fields = []
        for field in form.find_all(["input", "textarea", "select"], limit=80):
            tag_name = field.name.lower()
            fields.append({
                "tag": tag_name,
                "type": (attr(field, "type").lower() or "text") if tag_name == "input" else tag_name,
                "name": attr(field, "name"),
                "id": attr(field, "id"),
                "autocomplete": attr(field, "autocomplete").lower(),
            })
        forms.append({
            "method": (attr(form, "method").lower() or "get").upper(),
            "action": attr(form, "action", 2048),
            "fields": fields,
        })

    snapshot = {
        "page_url": page_url,
        "title": clean_text(soup.title.get_text(" ") if soup.title else ""),
        "headings": [
            text for text in (clean_text(tag.get_text(" ")) for tag in soup.find_all(["h1", "h2"], limit=12))
            if text
        ],
        "image_alts": [
            text for text in (clean_text(attr(tag, "alt")) for tag in soup.find_all("img", alt=True, limit=20))
            if text
        ],
        "forms": forms,
    }
    active_tags = ["script", "iframe", "frame", "object", "embed", "applet", "link", "style", "audio", "video", "source"]
    event_attributes = 0
    resource_attributes = 0
    for tag in soup.find_all(True):
        for name in tag.attrs:
            lower = str(name).lower()
            if lower.startswith("on"):
                event_attributes += 1
            if lower in {"src", "srcset", "href", "poster", "data"}:
                resource_attributes += 1
    transformations = {
        "active_or_resource_elements_omitted": sum(len(soup.find_all(name)) for name in active_tags),
        "event_handler_attributes_omitted": event_attributes,
        "resource_url_attributes_omitted": resource_attributes,
        "forms_made_inert": len(forms),
        "original_form_actions_preserved_in_snapshot_only": sum(1 for form in forms if form["action"]),
    }
    return snapshot, transformations


def sanitized_projection(snapshot: dict[str, Any]) -> bytes:
    parts = ["<!doctype html><html><head><meta charset=\"utf-8\"><title>", html.escape(snapshot["title"]), "</title></head><body>"]
    for heading in snapshot["headings"]:
        parts.extend(["<h1>", html.escape(heading), "</h1>"])
    for alt in snapshot["image_alts"]:
        parts.extend(["<img alt=\"", html.escape(alt, quote=True), "\">"])
    for form in snapshot["forms"]:
        parts.append('<form action="about:blank" method="get" autocomplete="off">')
        for field in form["fields"]:
            if field["tag"] == "textarea":
                parts.append("<textarea disabled></textarea>")
            elif field["tag"] == "select":
                parts.append("<select disabled></select>")
            else:
                parts.extend(["<input disabled type=\"", html.escape(field["type"], quote=True), "\">"])
        parts.append("</form>")
    parts.append("</body></html>\n")
    return "".join(parts).encode("utf-8")


def canonical_corpus_hash(samples: list[dict[str, Any]]) -> str:
    projection = [
        {
            "sample_id": sample["sample_id"],
            "label": sample["label"],
            "url": sample["url"],
            "original_sha256": sample["original_sha256"],
            "sanitized_sha256": sample["sanitized_sha256"],
            "snapshot_sha256": sample["snapshot_sha256"],
        }
        for sample in sorted(samples, key=lambda item: item["sample_id"])
    ]
    encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def main() -> None:
    if MANIFEST.exists():
        raise RuntimeError("Corpus is already sealed; refusing to replace it")
    acquisition = json.loads(ACQUISITION.read_text(encoding="utf-8"))
    if acquisition.get("detector_executed") is not False:
        raise RuntimeError("Acquisition manifest does not prove detector non-execution")
    samples = acquisition.get("samples", [])
    labels = {label: sum(1 for sample in samples if sample["label"] == label) for label in ("legitimate", "phishing")}
    if labels != {"legitimate": 120, "phishing": 120}:
        raise RuntimeError(f"Expected 120/120, got {labels}")
    domains = [sample["registrable_domain"] for sample in samples]
    if len(set(domains)) != 240:
        raise RuntimeError("Corpus must contain 240 distinct registrable domains")

    SANITIZED.mkdir(parents=True, exist_ok=True)
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    sealed_samples = []
    totals: dict[str, int] = {}
    for sample in samples:
        original_path = CORPUS / sample["original_path"]
        raw = original_path.read_bytes()
        if sha256_bytes(raw) != sample["original_sha256"]:
            raise RuntimeError(f"Original hash mismatch: {sample['sample_id']}")
        snapshot, transformations = snapshot_from_html(raw, sample["url"])
        sanitized = sanitized_projection(snapshot)
        snapshot_bytes = (json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        sanitized_rel = f"sanitized/{sample['sample_id']}.html"
        snapshot_rel = f"snapshots/{sample['sample_id']}.json"
        (CORPUS / sanitized_rel).write_bytes(sanitized)
        (CORPUS / snapshot_rel).write_bytes(snapshot_bytes)
        for name, count in transformations.items():
            totals[name] = totals.get(name, 0) + count
        sealed_samples.append({
            **sample,
            "sanitized_path": sanitized_rel,
            "sanitized_sha256": sha256_bytes(sanitized),
            "sanitized_bytes": len(sanitized),
            "snapshot_path": snapshot_rel,
            "snapshot_sha256": sha256_bytes(snapshot_bytes),
            "snapshot_bytes": len(snapshot_bytes),
            "sanitization_counts": transformations,
        })

    corpus_hash = canonical_corpus_hash(sealed_samples)
    manifest = {
        "schema_version": 1,
        "status": "sealed-not-evaluated",
        "sealed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"),
        "detector_executed": False,
        "seed": acquisition["seed"],
        "corpus_sha256": corpus_hash,
        "composition": {"total": 240, **labels, "unique_registrable_domains": 240, "shared_domains_between_classes": 0},
        "source": acquisition["source"],
        "acquisition_manifest": {
            "path": "acquisition-manifest.json",
            "sha256": sha256_bytes(ACQUISITION.read_bytes()),
        },
        "selection": acquisition["selection"],
        "acquisition": acquisition["acquisition"],
        "sanitization": {
            "parser": f"BeautifulSoup {__import__('bs4').__version__} with Python html.parser",
            "network_access": False,
            "javascript_execution": False,
            "external_resources_loaded": False,
            "description": "Static analyzer-observable projection; active/resource elements omitted; forms made inert; original action/method retained only in snapshot data.",
            "aggregate_counts": totals,
        },
        "samples": sealed_samples,
    }
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "corpus_sha256": corpus_hash, "composition": manifest["composition"]}, indent=2))


if __name__ == "__main__":
    main()
