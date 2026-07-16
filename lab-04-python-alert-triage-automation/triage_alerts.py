#!/usr/bin/env python3
"""
Lab 04: Python Alert Triage Automation

Reads security alerts from a CSV file, assigns a risk score and priority,
adds an analyst recommendation, and exports triaged results and a summary.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SEVERITY_SCORES = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 65,
}

ASSET_SCORES = {
    "low": 0,
    "medium": 10,
    "high": 20,
}

ALERT_TYPE_SCORES = {
    "malware detection": 25,
    "password spray": 25,
    "privilege escalation": 20,
    "impossible travel": 15,
    "powershell execution": 15,
    "failed login": 5,
    "successful login": 0,
}


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    alert_type: str
    severity: str
    username: str
    source_ip: str
    failed_attempts: int
    asset_criticality: str
    description: str


@dataclass
class TriagedAlert:
    alert: Alert
    risk_score: int
    priority: str
    recommendation: str


def normalize(value: str) -> str:
    return value.strip().lower()


def parse_nonnegative_int(value: str, field_name: str, row_number: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(
            f"Row {row_number}: {field_name} must be an integer."
        ) from exc

    if parsed < 0:
        raise ValueError(
            f"Row {row_number}: {field_name} cannot be negative."
        )

    return parsed


def read_alerts(path: Path) -> list[Alert]:
    required_fields = {
        "alert_id",
        "timestamp",
        "alert_type",
        "severity",
        "username",
        "source_ip",
        "failed_attempts",
        "asset_criticality",
        "description",
    }

    alerts: list[Alert] = []

    with path.open("r", encoding="utf-8-sig", newline="") as file_handle:
        reader = csv.DictReader(file_handle)

        if reader.fieldnames is None:
            raise ValueError("The input CSV does not contain a header row.")

        missing_fields = required_fields.difference(reader.fieldnames)
        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(f"Missing required CSV columns: {missing}")

        for row_number, row in enumerate(reader, start=2):
            alerts.append(
                Alert(
                    alert_id=row["alert_id"].strip(),
                    timestamp=row["timestamp"].strip(),
                    alert_type=row["alert_type"].strip(),
                    severity=normalize(row["severity"]),
                    username=row["username"].strip(),
                    source_ip=row["source_ip"].strip(),
                    failed_attempts=parse_nonnegative_int(
                        row["failed_attempts"],
                        "failed_attempts",
                        row_number,
                    ),
                    asset_criticality=normalize(row["asset_criticality"]),
                    description=row["description"].strip(),
                )
            )

    return alerts


def calculate_risk(alert: Alert) -> int:
    score = 0

    score += SEVERITY_SCORES.get(alert.severity, 0)
    score += ASSET_SCORES.get(alert.asset_criticality, 0)
    score += ALERT_TYPE_SCORES.get(normalize(alert.alert_type), 0)

    if alert.failed_attempts >= 15:
        score += 25
    elif alert.failed_attempts >= 5:
        score += 15
    elif alert.failed_attempts >= 2:
        score += 5

    if normalize(alert.username) in {"administrator", "admin", "root"}:
        score += 10

    return min(score, 100)


def get_priority(score: int) -> str:
    if score >= 80:
        return "P1 - Critical"
    if score >= 60:
        return "P2 - High"
    if score >= 35:
        return "P3 - Medium"
    return "P4 - Low"


def get_recommendation(alert: Alert, priority: str) -> str:
    alert_type = normalize(alert.alert_type)

    if alert_type == "malware detection":
        return "Isolate the endpoint, preserve evidence, and escalate immediately."
    if alert_type == "password spray":
        return "Block the source, review targeted accounts, and check for successful logins."
    if alert_type == "privilege escalation":
        return "Validate the privilege change and review related account and process activity."
    if alert_type == "impossible travel":
        return "Confirm user activity, review MFA, and revoke sessions if unauthorized."
    if alert_type == "powershell execution":
        return "Review the command line, parent process, user context, and endpoint activity."
    if alert_type == "failed login" and alert.failed_attempts >= 5:
        return "Review the source IP, targeted account, and surrounding authentication events."
    if priority == "P4 - Low":
        return "Document as low priority and monitor for repeated or related activity."

    return "Review supporting evidence and correlate with related security events."


def triage_alerts(alerts: Iterable[Alert]) -> list[TriagedAlert]:
    triaged: list[TriagedAlert] = []

    for alert in alerts:
        score = calculate_risk(alert)
        priority = get_priority(score)

        triaged.append(
            TriagedAlert(
                alert=alert,
                risk_score=score,
                priority=priority,
                recommendation=get_recommendation(alert, priority),
            )
        )

    return sorted(triaged, key=lambda item: item.risk_score, reverse=True)


def write_triaged_csv(path: Path, alerts: Iterable[TriagedAlert]) -> None:
    fieldnames = [
        "alert_id",
        "timestamp",
        "alert_type",
        "severity",
        "username",
        "source_ip",
        "failed_attempts",
        "asset_criticality",
        "risk_score",
        "priority",
        "recommendation",
        "description",
    ]

    with path.open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()

        for item in alerts:
            alert = item.alert
            writer.writerow(
                {
                    "alert_id": alert.alert_id,
                    "timestamp": alert.timestamp,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "username": alert.username,
                    "source_ip": alert.source_ip,
                    "failed_attempts": alert.failed_attempts,
                    "asset_criticality": alert.asset_criticality,
                    "risk_score": item.risk_score,
                    "priority": item.priority,
                    "recommendation": item.recommendation,
                    "description": alert.description,
                }
            )


def write_summary_csv(path: Path, alerts: Iterable[TriagedAlert]) -> None:
    alerts_list = list(alerts)
    priority_counts = Counter(item.priority for item in alerts_list)

    with path.open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_alerts", len(alerts_list)])

        for priority in [
            "P1 - Critical",
            "P2 - High",
            "P3 - Medium",
            "P4 - Low",
        ]:
            writer.writerow([priority, priority_counts.get(priority, 0)])


def print_summary(alerts: list[TriagedAlert]) -> None:
    print("\nAlert triage completed.\n")
    print(f"{'Alert ID':<10} {'Type':<22} {'Score':<7} {'Priority'}")
    print("-" * 65)

    for item in alerts:
        print(
            f"{item.alert.alert_id:<10} "
            f"{item.alert.alert_type:<22} "
            f"{item.risk_score:<7} "
            f"{item.priority}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prioritize security alerts from a CSV file."
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to the input alert CSV file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for generated CSV reports.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if not args.input_csv.exists():
            raise FileNotFoundError(
                f"Input file was not found: {args.input_csv}"
            )

        alerts = read_alerts(args.input_csv)
        triaged = triage_alerts(alerts)

        args.output_dir.mkdir(parents=True, exist_ok=True)

        triaged_path = args.output_dir / "triaged-alerts.csv"
        summary_path = args.output_dir / "triage-summary.csv"

        write_triaged_csv(triaged_path, triaged)
        write_summary_csv(summary_path, triaged)
        print_summary(triaged)

        print(f"\nDetailed report: {triaged_path.resolve()}")
        print(f"Summary report:  {summary_path.resolve()}")
        return 0

    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
