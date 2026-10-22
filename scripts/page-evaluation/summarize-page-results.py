from __future__ import annotations

import csv
import json
import statistics
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evaluation" / "results" / "page-analysis" / "official"


def load_csv(name: str) -> list[dict]:
    with (RESULTS / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_prediction_rows(name: str) -> list[dict]:
    rows = load_csv(name)
    for row in rows:
        row["score"] = float(row["score"])
        row["categories"] = json.loads(row["categories"])
        row["signals"] = json.loads(row["signals"])
        row["reasons"] = json.loads(row["reasons"])
        try:
            row["diversity"] = json.loads(row["diversity"])
        except json.JSONDecodeError:
            row["diversity"] = int(row["diversity"])
    return rows


def score_summary(rows: list[dict]) -> dict:
    result = {}
    for label in ("legitimate", "phishing"):
        values = sorted(row["score"] for row in rows if row["true_label"] == label)
        result[label] = {
            "minimum": min(values),
            "median": statistics.median(values),
            "mean": statistics.fmean(values),
            "maximum": max(values),
            "zero": sum(value == 0 for value in values),
        }
    return result


def signal_keys(signals: dict) -> list[str]:
    result = []
    for key, value in signals.items():
        if value is True:
            result.append(key)
        elif isinstance(value, list):
            result.extend(f"{key}:{item}" for item in value)
    return result


def main() -> None:
    url_rows = parse_prediction_rows("predictions-url.csv")
    page_rows = parse_prediction_rows("predictions-page.csv")
    combined_rows = parse_prediction_rows("predictions-combined.csv")
    transitions = load_csv("transition-analysis.csv")
    by_id_page = {row["sample_id"]: row for row in page_rows}

    url_fn = [row for row in url_rows if row["outcome"] == "FN"]
    url_fn_characteristics = {
        "total": len(url_fn),
        "score_zero": sum(row["score"] == 0 for row in url_fn),
        "score_below_10": sum(row["score"] < 10 for row in url_fn),
        "zero_categories": sum(len(row["categories"]) == 0 for row in url_fn),
        "one_category": sum(len(row["categories"]) == 1 for row in url_fn),
        "shared_hosting": sum(row["signals"].get("uses_shared_hosting") is True for row in url_fn),
        "http_signal": sum(any("utiliza HTTP" in reason for reason in row["reasons"]) for row in url_fn),
        "no_brand_mismatch": sum(row["signals"].get("brand_mismatch") is not True for row in url_fn),
        "no_authentication_hostname": sum(row["signals"].get("authentication_in_hostname") is not True for row in url_fn),
        "no_authentication_path": sum(row["signals"].get("authentication_in_pathname") is not True for row in url_fn),
    }

    recovered = [row for row in transitions if row["transition"] == "FN->TP"]
    introduced = [row for row in transitions if row["transition"] == "TN->FP"]
    page_fp = [row for row in page_rows if row["outcome"] == "FP"]
    page_fn = [row for row in page_rows if row["outcome"] == "FN"]
    summary = {
        "score_distribution": {
            "url": score_summary(url_rows),
            "page": score_summary(page_rows),
            "combined": score_summary(combined_rows),
        },
        "url_false_negative_characteristics": url_fn_characteristics,
        "transitions": dict(Counter(row["transition"] for row in transitions)),
        "recovered_false_negatives": {
            "count": len(recovered),
            "share_of_url_false_negatives": len(recovered) / len(url_fn),
            "share_of_all_phishing": len(recovered) / 120,
            "sample_ids": [row["sample_id"] for row in recovered],
            "page_categories": dict(Counter(category for row in recovered for category in json.loads(row["page_categories"]))),
            "page_signals": dict(Counter(signal for row in recovered for signal in json.loads(row["page_signals"]))),
        },
        "introduced_false_positives": {
            "count": len(introduced),
            "share_of_url_true_negatives": len(introduced) / 120,
            "share_of_all_legitimate": len(introduced) / 120,
            "sample_ids": [row["sample_id"] for row in introduced],
            "page_categories": dict(Counter(category for row in introduced for category in json.loads(row["page_categories"]))),
            "page_signals": dict(Counter(signal for row in introduced for signal in json.loads(row["page_signals"]))),
        },
        "page_false_positives": [
            {"sample_id": row["sample_id"], "url": row["url"], "score": row["score"], "categories": row["categories"], "signals": signal_keys(row["signals"]), "reasons": row["reasons"]}
            for row in page_fp
        ],
        "page_false_negatives": {
            "count": len(page_fn),
            "score_zero": sum(row["score"] == 0 for row in page_fn),
            "zero_categories": sum(len(row["categories"]) == 0 for row in page_fn),
            "password_fields": sum(row["signals"].get("password_fields") is True for row in page_fn),
            "credential_bundle": sum(row["signals"].get("credential_bundle") is True for row in page_fn),
            "external_form": sum(row["signals"].get("external_form") is True for row in page_fn),
            "brand_mismatch": sum(row["signals"].get("brand_mismatch") is True for row in page_fn),
        },
        "combined_cross_layer_suspicious": sum(
            row["signals"].get("cross_layer_suspicious") is True for row in combined_rows
        ),
        "page_signals_by_label": {
            label: dict(Counter(signal for row in page_rows if row["true_label"] == label for signal in signal_keys(row["signals"])))
            for label in ("legitimate", "phishing")
        },
        "page_category_combinations_by_label": {
            label: dict(Counter("+".join(sorted(row["categories"])) or "(none)" for row in page_rows if row["true_label"] == label))
            for label in ("legitimate", "phishing")
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
