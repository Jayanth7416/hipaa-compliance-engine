"""CLI entrypoint for running compliance scans on local files or directories.

Usage:
    python -m src.services.scanner --input data/ --output results/
"""

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List

from src.services.phi_scanner import PHIScanner


async def run_cli_scan(input_path: Path, output_path: Path) -> Dict[str, Any]:
    scanner = PHIScanner()
    files: List[Path] = []
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = [p for p in input_path.rglob("*") if p.is_file()]

    summary: Dict[str, Any] = {
        "files_scanned": len(files),
        "total_findings": 0,
        "results": [],
    }

    for file_path in files:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        findings = await scanner.scan_text(content)
        summary["total_findings"] += len(findings)
        summary["results"].append(
            {
                "file": str(file_path),
                "findings_count": len(findings),
                "findings": [f.model_dump() for f in findings],
            }
        )

    output_path.mkdir(parents=True, exist_ok=True)
    report_file = output_path / "scan_report.json"
    report_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="HIPAA Compliance Engine PHI Scanner CLI")
    parser.add_argument("--input", "-i", required=True, help="Input file or directory")
    parser.add_argument("--output", "-o", required=True, help="Output directory for scan results")
    args = parser.parse_args()

    result = asyncio.run(run_cli_scan(Path(args.input), Path(args.output)))
    print(
        f"Scan complete: {result['files_scanned']} file(s) scanned, "
        f"{result['total_findings']} PHI finding(s) written to {args.output}/scan_report.json"
    )


if __name__ == "__main__":
    main()
