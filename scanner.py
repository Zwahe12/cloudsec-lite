from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

from rules import RULES


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    recommendation: str


SEVERITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10,
}


def iter_terraform_files(target: Path) -> Iterable[Path]:
    if target.is_file() and target.suffix == ".tf":
        yield target
        return

    if target.is_dir():
        yield from sorted(target.rglob("*.tf"))


def scan_file(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings: list[Finding] = []

    for rule in RULES:
        for match in re.finditer(rule["pattern"], text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL):
            line = text[:match.start()].count("\n") + 1
            evidence = match.group(0).strip().replace("\n", " ")
            evidence = re.sub(r"\s+", " ", evidence)[:180]

            findings.append(
                Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    file=str(path),
                    line=line,
                    evidence=evidence,
                    recommendation=rule["recommendation"],
                )
            )

    return findings


def scan(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for tf_file in iter_terraform_files(target):
        findings.extend(scan_file(tf_file))
    return findings


def risk_score(findings: list[Finding]) -> int:
    raw = sum(SEVERITY_SCORE[f.severity] for f in findings)
    return min(raw, 100)


def print_human(findings: list[Finding]) -> None:
    if not findings:
        print("✅ No matching cloud security misconfigurations found.")
        return

    print(f"\nCloudSec Lite found {len(findings)} issue(s)")
    print("=" * 72)

    for f in findings:
        print(f"[{f.severity}] {f.rule_id} — {f.title}")
        print(f"  {f.file}:{f.line}")
        print(f"  Evidence: {f.evidence}")
        print(f"  Fix: {f.recommendation}\n")

    print(f"Risk score: {risk_score(findings)}/100")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Terraform files for common cloud security misconfigurations."
    )
    parser.add_argument("target", help="Terraform file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Return exit code 2 when this severity or higher is found",
    )
    args = parser.parse_args()

    findings = scan(Path(args.target))

    if args.json:
        print(json.dumps({
            "risk_score": risk_score(findings),
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    else:
        print_human(findings)

    if args.fail_on:
        threshold = SEVERITY_SCORE[args.fail_on]
        if any(SEVERITY_SCORE[f.severity] >= threshold for f in findings):
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
