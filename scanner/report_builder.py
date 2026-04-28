"""
MCPGuard — Report Builder Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Combines findings from all scanner modules into a unified security report.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Literal

from scanner.dependency_audit import Finding


# Score thresholds
SCORE_THRESHOLDS = {
    "CRITICAL": {"critical": 1},   # Any critical finding → CRITICAL
    "HIGH": {"high": 1},           # Any high finding → HIGH
    "MEDIUM": {"medium": 3},       # 3+ medium findings → MEDIUM
    "LOW": {"low": 5},             # 5+ low findings → LOW
}


def calculate_overall_score(findings: list[Finding]) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
    """
    Calculate the overall security score based on findings.

    Rules:
    - Any CRITICAL finding → CRITICAL
    - Any HIGH finding → HIGH
    - 3+ MEDIUM findings → MEDIUM
    - 5+ LOW findings → LOW
    - Otherwise → SAFE
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    if counts["CRITICAL"] >= 1:
        return "CRITICAL"
    if counts["HIGH"] >= 1:
        return "HIGH"
    if counts["MEDIUM"] >= 3:
        return "MEDIUM"
    if counts["LOW"] >= 5:
        return "LOW"
    return "SAFE"


def build_report(
    findings: list[Finding],
    target_url: str,
    target_type: str,
    scan_duration_ms: int | None = None,
) -> dict:
    """
    Build a structured JSON report from all scanner findings.

    Args:
        findings: Combined list of findings from all scanner modules.
        target_url: The scanned target URL or package name.
        target_type: Type of target (github, npm, local).
        scan_duration_ms: Total scan duration in milliseconds.

    Returns:
        A dictionary suitable for storing as result_json in the scans table.
    """
    overall_score = calculate_overall_score(findings)

    # Group findings by category
    by_category: dict[str, list[dict]] = {}
    for f in findings:
        cat = f.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(asdict(f))

    # Group findings by severity
    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        sev = f.severity
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(asdict(f))

    # Summary counts
    severity_counts = {
        "critical": len(by_severity.get("CRITICAL", [])),
        "high": len(by_severity.get("HIGH", [])),
        "medium": len(by_severity.get("MEDIUM", [])),
        "low": len(by_severity.get("LOW", [])),
        "info": len(by_severity.get("INFO", [])),
    }

    report = {
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "url": target_url,
            "type": target_type,
        },
        "overall_score": overall_score,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "scan_duration_ms": scan_duration_ms,
        "categories": {
            cat: {
                "count": len(items),
                "findings": items,
            }
            for cat, items in by_category.items()
        },
        "findings_by_severity": {
            sev: items
            for sev, items in by_severity.items()
        },
    }

    return report


def format_report_text(report: dict) -> str:
    """
    Format the report as human-readable text for CLI output.
    """
    lines = []
    lines.append("=" * 60)
    lines.append(f"  MCPGuard Security Report")
    lines.append(f"  Target: {report['target']['url']}")
    lines.append(f"  Type: {report['target']['type']}")
    lines.append(f"  Generated: {report['generated_at']}")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Overall Score: {report['overall_score']}")
    lines.append("")

    counts = report["severity_counts"]
    lines.append(f"  Critical: {counts['critical']}  |  High: {counts['high']}  |  Medium: {counts['medium']}  |  Low: {counts['low']}  |  Info: {counts['info']}")
    lines.append("")
    lines.append("-" * 60)

    for cat, data in report.get("categories", {}).items():
        lines.append(f"\n  [{cat.upper()}] — {data['count']} finding(s)")
        for f in data["findings"]:
            sev = f["severity"]
            lines.append(f"    [{sev}] {f['title']}")
            if f.get("file_path"):
                loc = f["file_path"]
                if f.get("line_number"):
                    loc += f":{f['line_number']}"
                lines.append(f"           File: {loc}")
            lines.append(f"           {f['description'][:120]}")
            if f.get("remediation"):
                lines.append(f"           Fix: {f['remediation'][:120]}")
            lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
