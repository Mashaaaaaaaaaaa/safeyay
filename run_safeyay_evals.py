#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the local model against safe/tampered PKGBUILD fixtures and retain all output."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import sys

import safeyay_scanner as scanner

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "eval" / "fixtures"
RESULTS = ROOT / "eval" / "results"


def main() -> int:
    output_dir = RESULTS / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir.mkdir(parents=True)
    runs = []
    failures = 0
    selected = set(sys.argv[1:])
    fixtures = sorted(
        fixture for fixture in FIXTURES.glob("*/PKGBUILD")
        if not (fixture.parent / ".disabled").exists()
    )
    if selected:
        fixtures = [fixture for fixture in fixtures if fixture.parent.name in selected]
        missing = selected - {fixture.parent.name for fixture in fixtures}
        if missing:
            print(f"Unknown fixtures: {', '.join(sorted(missing))}", file=sys.stderr)
            return 2
    for fixture in fixtures:
        name = fixture.parent.name
        run_dir = output_dir / name
        run_dir.mkdir()
        inputs = scanner.candidate_files([str(fixture)])
        for input_path in inputs:
            shutil.copy2(input_path, run_dir / input_path.name)
        raw_path = run_dir / "ollama-raw.json"
        search_path = run_dir / "search-evidence.json"
        console = io.StringIO()
        expected = "unlabeled" if (fixture.parent / ".unlabeled").exists() else ("suspicious" if "tampered" in name else "clean")
        record = {"fixture": name, "model": scanner.MODEL, "expected": expected}
        try:
            with redirect_stdout(console), redirect_stderr(console):
                print(f"Reviewing {name} with {scanner.MODEL}")
                review = scanner.analyze(scanner.read_sources(inputs), raw_path, search_path)
                print(json.dumps(review, indent=2))
            (run_dir / "review.json").write_text(json.dumps(review, indent=2) + "\n")
            record["reported"] = "suspicious" if review["suspicious"] else "clean"
            record["matched_expected"] = None if expected == "unlabeled" else record["reported"] == expected
        except Exception as exc:
            failures += 1
            record.update({"reported": "error", "matched_expected": False, "error": str(exc)})
            print(f"ERROR: {exc}", file=console)
        (run_dir / "console.txt").write_text(console.getvalue())
        runs.append(record)
        print(f"{name}: {record['reported']} (expected {record['expected']})")
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backend": scanner.BACKEND,
        "model": scanner.MODEL,
        "base_url": scanner.CONFIG.get("base_url", ""),
        "fixture_labels_exposed_to_model": False,
        "runs": runs,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"All outputs: {output_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
