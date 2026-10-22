from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

try:
    import duckdb  # type: ignore
    if not hasattr(duckdb, "connect"):
        import _duckdb as duckdb  # type: ignore
except ImportError:
    import _duckdb as duckdb  # type: ignore


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("parquet", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit-per-class", type=int, default=500)
    args = parser.parse_args()
    files = [Path(item).resolve() for item in args.parquet]
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect()
    placeholders = ",".join("?" for _ in files)
    source_expression = f"read_parquet([{placeholders}], filename=true)"
    counts = connection.execute(
        f"SELECT label, count(*) FROM {source_expression} GROUP BY label ORDER BY label",
        [str(item) for item in files],
    ).fetchall()
    rows = []
    for label in ("benign", "phish"):
        query = f"""
            SELECT sha256, url, label, target, CAST(date AS VARCHAR), lang, lang_score, html, filename
            FROM {source_expression}
            WHERE label = ?
            ORDER BY sha256
            LIMIT ?
        """
        rows.extend(connection.execute(query, [*(str(item) for item in files), label, args.limit_per_class]).fetchall())
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            record = {
                "sha256": row[0], "url": row[1], "label": row[2], "target": row[3],
                "date": row[4], "lang": row[5], "lang_score": row[6], "html": row[7],
                "source_parquet": Path(row[8]).name,
            }
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    report = {
        "source_files": [
            {"path": os.path.relpath(item, Path.cwd()).replace("\\", "/"), "sha256": sha256_file(item), "bytes": item.stat().st_size}
            for item in files
        ],
        "source_counts": dict(counts),
        "limit_per_class": args.limit_per_class,
        "exported_rows": len(rows),
        "output": os.path.relpath(output, Path.cwd()).replace("\\", "/"),
        "output_sha256": sha256_file(output),
        "output_bytes": output.stat().st_size,
    }
    report_path = output.with_suffix(output.suffix + ".manifest.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
