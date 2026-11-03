#!/usr/bin/env python3
"""
triage.py — Read Prowler OCSF JSON output and produce a ranked, deduplicated triage report.

Usage:
    python scripts/triage.py --input "output/*.json" --top 10
"""

import argparse
import glob
import json
from collections import Counter, defaultdict


SEVERITY_MAP = {
    5: "Critical",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Informational",
}


def load_findings(pattern):
    """Load all findings from Prowler OCSF JSON file(s)."""
    findings = []
    for path in glob.glob(pattern):
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            findings.extend(data)
        elif isinstance(data, dict) and "findings" in data:
            findings.extend(data["findings"])
    return findings


def normalize(finding):
    """Pull out the fields we care about from a Prowler OCSF finding."""
    severity_id = finding.get("severity_id", 0)
    if isinstance(severity_id, str):
        severity_id = int(severity_id) if severity_id.isdigit() else 0

    analytic = finding.get("finding_info", {}).get("analytic", {})
    resources = finding.get("resources") or [{}]

    return {
        "title": finding.get("finding_info", {}).get("title", "untitled"),
        "description": finding.get("finding_info", {}).get("desc", ""),
        "check_id": analytic.get("uid", "unknown"),
        "service": analytic.get("category", "unknown"),
        "severity": SEVERITY_MAP.get(severity_id, "Unknown"),
        "severity_id": severity_id,
        "resource": resources[0].get("uid", "unknown"),
        "region": finding.get("cloud", {}).get("region", "unknown"),
        "status": finding.get("status_code", "unknown"),
    }


def group_by_check(findings):
    """Group findings by check_id. One group = one unique problem."""
    grouped = defaultdict(list)
    for f in findings:
        grouped[f["check_id"]].append(f)
    return grouped


def print_report(findings, groups, top_n):
    print("=" * 80)
    print("PROWLER TRIAGE REPORT")
    print("=" * 80)
    print(f"Total FAIL findings:   {len(findings)}")
    print(f"Unique check failures: {len(groups)}")
    print()
    print("NOTE: Prowler check titles describe the SECURE state.")
    print("A FAIL means that secure condition is NOT met.")
    print()

    # Sort groups by severity of first finding, then by number of affected resources
    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: (-kv[1][0]["severity_id"], -len(kv[1])),
    )

    print("=" * 80)
    print(f"TOP {top_n} UNIQUE CHECKS (ranked by severity, then affected resources)")
    print("=" * 80)

    for i, (check_id, items) in enumerate(sorted_groups[:top_n], 1):
        first = items[0]
        print(f"\n{i}. [{first['severity']}] {first['title']}")
        print(f"   Service:            {first['service']}")
        print(f"   Check:              {check_id}")
        print(f"   Affected resources: {len(items)}")

        for item in items[:3]:
            print(f"     - {item['resource']} ({item['region']})")
        if len(items) > 3:
            print(f"     ... and {len(items) - 3} more")

    # Service breakdown (by unique checks, not raw findings)
    service_counts = Counter(first[0]["service"] for first in groups.values())

    print("\n" + "=" * 80)
    print("UNIQUE FAILURES BY SERVICE")
    print("=" * 80)
    for service, count in service_counts.most_common():
        print(f"  {count:4d}  {service}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="output/*.json",
                        help="Glob pattern for Prowler JSON output files")
    parser.add_argument("--top", type=int, default=10,
                        help="Number of unique checks to show")
    args = parser.parse_args()

    raw = load_findings(args.input)
    if not raw:
        print(f"[!] No findings found in: {args.input}")
        print("    Check that the scan finished and the output/ folder exists.")
        return

    findings = [normalize(f) for f in raw if f.get("status_code") == "FAIL"]
    if not findings:
        print("[!] No FAIL findings found. Your account may be clean.")
        return

    groups = group_by_check(findings)
    print_report(findings, groups, args.top)


if __name__ == "__main__":
    main()
