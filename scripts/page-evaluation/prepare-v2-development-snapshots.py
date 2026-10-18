from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup, Tag


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "evaluation" / "page-corpus"
CORPUS_MANIFEST = CORPUS / "corpus-manifest.json"
OUTPUT = ROOT / "evaluation" / "results" / "page-analysis" / "development-v2"
SNAPSHOTS = OUTPUT / "derived-snapshots"
SNAPSHOT_MANIFEST = OUTPUT / "snapshot-manifest.json"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def clean_text(value: Any, maximum: int = 240) -> str:
    return " ".join(str(value or "").split())[:maximum]


def attr(tag: Tag, name: str, maximum: int = 120) -> str:
    value = tag.attrs.get(name, "")
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    return clean_text(value, maximum)


def region_for(tag: Tag | None) -> str:
    current = tag
    while isinstance(current, Tag):
        name = current.name.lower()
        if name in {"footer", "nav", "aside", "header", "main"}:
            return name
        current = current.parent
    return "other"


def auxiliary_text(value: str) -> bool:
    text = value.lower()
    store = re.search(r"\b(download|baixar|obtenha|get it|available on)\b", text) and re.search(r"\b(app store|google play)\b", text)
    social = re.search(r"\b(opens? in (a )?new window|follow us|siga-nos|social (link|media))\b", text)
    return bool(store or social)


def logo_like(tag: Tag) -> bool:
    metadata = " ".join(attr(tag, name) for name in ("class", "id", "role", "itemprop"))
    return bool(re.search(r"(^|[^a-z])(logo|brand|identity)([^a-z]|$)", metadata, re.I))


def identity_item(text: str, source: str, tag: Tag | None = None, region: str | None = None) -> dict[str, Any] | None:
    value = clean_text(text, 200)
    if not value:
        return None
    actual_region = region or region_for(tag)
    return {
        "text": value,
        "source": source,
        "tag": tag.name.lower() if isinstance(tag, Tag) else None,
        "region": actual_region,
        "logo_like": logo_like(tag) if isinstance(tag, Tag) else False,
        "auxiliary": actual_region in {"footer", "nav", "aside"} or auxiliary_text(value),
    }


def field_metadata(field: Tag) -> dict[str, str]:
    tag_name = field.name.lower()
    return {
        "tag": tag_name,
        "type": (attr(field, "type").lower() or "text") if tag_name == "input" else tag_name,
        "name": attr(field, "name"),
        "id": attr(field, "id"),
        "autocomplete": attr(field, "autocomplete").lower(),
        "placeholder": attr(field, "placeholder"),
        "aria_label": attr(field, "aria-label"),
    }


def context_source(tag: Tag, prefix: str) -> str:
    if tag.name == "img":
        return f"{prefix}_image_alt"
    if tag.name in {"h1", "h2", "h3"}:
        return f"{prefix}_heading"
    if tag.name == "legend":
        return f"{prefix}_legend"
    if tag.name == "label":
        return f"{prefix}_label"
    return f"{prefix}_button"


def context_items(container: Tag, prefix: str, maximum: int) -> list[dict[str, Any]]:
    result = []
    for node in container.find_all(["h1", "h2", "h3", "legend", "label", "button", "img"], limit=maximum * 2):
        if node.name == "img" and not node.has_attr("alt"):
            continue
        text = attr(node, "alt", 200) if node.name == "img" else clean_text(node.get_text(" "), 200)
        item = identity_item(text, context_source(node, prefix), node)
        if item:
            result.append(item)
        if len(result) >= maximum:
            break
    return result


def nearest_section(form: Tag) -> Tag | None:
    for parent in form.parents:
        if not isinstance(parent, Tag):
            continue
        role = attr(parent, "role").lower()
        if parent.name in {"section", "article", "fieldset"} or role in {"form", "dialog"}:
            return parent
        if parent.name in {"body", "html"}:
            break
    return None


def form_snapshot(form: Tag) -> dict[str, Any]:
    context = context_items(form, "form", 12)
    section = nearest_section(form)
    if section is not None and section is not form:
        context.extend(context_items(section, "section", 8))
    unique = []
    seen: set[tuple[str, str]] = set()
    for item in context:
        key = (item["source"], item["text"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
        if len(unique) >= 16:
            break
    return {
        "method": (attr(form, "method").lower() or "get").upper(),
        "action": attr(form, "action", 2048),
        "region": region_for(form),
        "context": unique,
        "fields": [field_metadata(field) for field in form.find_all(["input", "textarea", "select"], limit=80)],
    }


def snapshot_from_html(raw: bytes, page_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(raw, "html.parser")
    title = clean_text(soup.title.get_text(" ") if soup.title else "")
    identity = []
    title_item = identity_item(title, "title", region="document")
    if title_item:
        identity.append(title_item)
    for heading in soup.find_all(["h1", "h2"], limit=16):
        item = identity_item(heading.get_text(" "), "heading", heading)
        if item:
            identity.append(item)
    for image in soup.find_all("img", alt=True, limit=30):
        item = identity_item(attr(image, "alt", 200), "image_alt", image)
        if item:
            identity.append(item)
    forms = [form_snapshot(form) for form in soup.find_all("form", limit=30)]
    orphan_fields = []
    orphan_groups: dict[int, str] = {}
    for field in soup.find_all(["input", "textarea", "select"], limit=200):
        if field.find_parent("form") is None:
            container = field.find_parent(["section", "article", "fieldset"], attrs={})
            if container is None:
                container = field.parent if isinstance(field.parent, Tag) else field
            key = id(container)
            if key not in orphan_groups:
                orphan_groups[key] = f"group-{len(orphan_groups) + 1}"
            orphan_fields.append({**field_metadata(field), "region": region_for(field), "group_id": orphan_groups[key]})
        if len(orphan_fields) >= 80:
            break
    return {
        "schema_version": 2,
        "page_url": page_url,
        "title": title,
        "identity_evidence": identity,
        "forms": forms,
        "orphan_fields": orphan_fields,
    }


def main() -> None:
    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("corpus_sha256") != "29574db70b518a4efffafca3d0451b4d3eae26c9d6abe283be54d9030479adab":
        raise RuntimeError("Unexpected development corpus hash")
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    records = []
    for sample in manifest["samples"]:
        original = CORPUS / sample["original_path"]
        raw = original.read_bytes()
        if sha256_bytes(raw) != sample["original_sha256"]:
            raise RuntimeError(f"Original hash mismatch: {sample['sample_id']}")
        snapshot = snapshot_from_html(raw, sample["url"])
        encoded = (json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        relative = f"derived-snapshots/{sample['sample_id']}.json"
        target = OUTPUT / relative
        if target.exists() and target.read_bytes() != encoded:
            raise RuntimeError(f"Refusing to replace a different derived snapshot: {sample['sample_id']}")
        target.write_bytes(encoded)
        records.append({
            "sample_id": sample["sample_id"],
            "label": sample["label"],
            "source_original_sha256": sample["original_sha256"],
            "snapshot_path": relative,
            "snapshot_sha256": sha256_bytes(encoded),
            "snapshot_bytes": len(encoded),
        })
    result = {
        "schema_version": 1,
        "status": "development-derivative-prepared",
        "source_corpus_sha256": manifest["corpus_sha256"],
        "network_access": False,
        "javascript_execution": False,
        "detector_executed": False,
        "description": "Schema-v2 structural snapshots derived inertly from the sealed corpus originals; the sealed corpus and official results are unchanged.",
        "samples": records,
    }
    encoded_manifest = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if SNAPSHOT_MANIFEST.exists() and SNAPSHOT_MANIFEST.read_bytes() != encoded_manifest:
        raise RuntimeError("Refusing to replace a different development snapshot manifest")
    SNAPSHOT_MANIFEST.write_bytes(encoded_manifest)
    print(json.dumps({"status": result["status"], "samples": len(records), "manifest_sha256": sha256_bytes(encoded_manifest)}, indent=2))


if __name__ == "__main__":
    main()
