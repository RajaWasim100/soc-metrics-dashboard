#!/usr/bin/env python3
"""Stream Microsoft's GUIDE benchmark into transparent incident-level metrics.

The large source CSV is downloaded by the user from Kaggle and must not be
committed. This script reads it locally and emits aggregates only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

DATASET_NAME = "Microsoft GUIDE (Kaggle Microsoft Security Incident Prediction)"
DATASET_VERSION = "2"
DATASET_URL = "https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction"
LICENSE = "CDLA-Permissive-2.0; include license terms when redistributing source data"
REQUIRED = {"Id", "IncidentId", "AlertId", "Timestamp", "Category", "IncidentGrade", "EntityType", "EvidenceRole", "MitreTechniques", "ActionGrouped", "ActionGranular"}
VALID_GRADES = {"TruePositive", "FalsePositive", "BenignPositive"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _majority_grade(votes: Counter) -> str:
    return max(votes, key=lambda value: (votes[value], value == "TruePositive", value == "BenignPositive"))


def summarize(path: Path, cohort_size: int = 25) -> dict:
    if not path.is_file():
        raise FileNotFoundError(path)
    if cohort_size < 1:
        raise ValueError("cohort_size must be a positive integer")

    incidents: dict[str, Counter] = defaultdict(Counter)
    alert_ids: set[str] = set()
    categories: Counter = Counter()
    rows = 0
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"GUIDE CSV missing required fields: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            if any(row.get(field) is None for field in REQUIRED):
                raise ValueError(f"Malformed GUIDE CSV row {row_number}")
            incident_id = row["IncidentId"].strip()
            alert_id = row["AlertId"].strip()
            grade = row["IncidentGrade"].strip()
            category = row["Category"].strip() or "(missing)"
            if not incident_id or not alert_id:
                raise ValueError(f"Missing incident/alert identifier on row {row_number}")
            if grade not in VALID_GRADES:
                raise ValueError(f"Unexpected IncidentGrade {grade!r} on row {row_number}")
            incidents[incident_id][grade] += 1
            alert_ids.add(alert_id)
            categories[category] += 1
            rows += 1

    grade_counts: Counter = Counter()
    tied_incidents = 0
    for votes in incidents.values():
        maximum = max(votes.values())
        winners = [grade for grade, count in votes.items() if count == maximum]
        if len(winners) > 1:
            tied_incidents += 1
        grade_counts[_majority_grade(votes)] += 1

    # Select bounded deterministic cohorts. IDs are used only for local joins;
    # public artifacts contain cohort-level counts/labels, never source IDs.
    selected: dict[str, set[str]] = {}
    for grade in ("TruePositive", "BenignPositive", "FalsePositive"):
        candidates = [incident_id for incident_id, votes in incidents.items()
                      if _majority_grade(votes) == grade]
        selected[grade] = set(sorted(
            candidates, key=lambda incident_id: hashlib.sha256(incident_id.encode("utf-8")).hexdigest()
        )[:cohort_size])

    aggregates = {
        grade: {"incident_ids": set(), "alert_ids": set(), "evidence_rows_per_incident": Counter(),
                "categories": Counter(), "entity_types": Counter(), "evidence_roles": Counter(),
                "mitre_techniques": Counter(), "action_grouped": Counter(), "action_granular": Counter()}
        for grade in selected
    }
    selected_grade = {incident_id: grade for grade, ids in selected.items() for incident_id in ids}
    with path.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            incident_id = row["IncidentId"].strip()
            grade = selected_grade.get(incident_id)
            if grade is None:
                continue
            aggregate = aggregates[grade]
            aggregate["incident_ids"].add(incident_id)
            aggregate["alert_ids"].add(row["AlertId"].strip())
            aggregate["evidence_rows_per_incident"][incident_id] += 1
            aggregate["categories"][row["Category"].strip() or "(missing)"] += 1
            aggregate["entity_types"][row["EntityType"].strip() or "(missing)"] += 1
            aggregate["evidence_roles"][row["EvidenceRole"].strip() or "(missing)"] += 1
            for technique in row["MitreTechniques"].split(";"):
                if technique := technique.strip():
                    aggregate["mitre_techniques"][technique] += 1
            if action := row["ActionGrouped"].strip():
                aggregate["action_grouped"][action] += 1
            if action := row["ActionGranular"].strip():
                aggregate["action_granular"][action] += 1

    def top_counts(counter: Counter, limit: int = 8) -> dict[str, int]:
        return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit])

    profiles = []
    for grade in ("TruePositive", "BenignPositive", "FalsePositive"):
        aggregate = aggregates[grade]
        evidence_counts = sorted(aggregate["evidence_rows_per_incident"].values())
        middle = len(evidence_counts) // 2
        median = (evidence_counts[middle] if len(evidence_counts) % 2 else
                  (evidence_counts[middle - 1] + evidence_counts[middle]) / 2) if evidence_counts else None
        profiles.append({
            "profile_label": f"De-identified {grade} cohort",
            "majority_vote_grade": grade,
            "incident_count": len(aggregate["incident_ids"]),
            "distinct_alert_count": len(aggregate["alert_ids"]),
            "total_evidence_rows": sum(evidence_counts),
            "median_evidence_rows_per_incident": median,
            "top_evidence_categories": top_counts(aggregate["categories"]),
            "top_entity_types": top_counts(aggregate["entity_types"]),
            "evidence_roles": dict(sorted(aggregate["evidence_roles"].items())),
            "top_mitre_techniques": top_counts(aggregate["mitre_techniques"]),
            "grouped_response_actions": dict(sorted(aggregate["action_grouped"].items())),
            "top_granular_response_actions": top_counts(aggregate["action_granular"]),
        })

    return {
        "label": "PUBLISHED REAL-WORLD BENCHMARK — NOT USER'S SOC ACTIVITY",
        "dataset": DATASET_NAME,
        "dataset_version": DATASET_VERSION,
        "source_url": DATASET_URL,
        "license": LICENSE,
        "input_file": path.name,
        "input_bytes": path.stat().st_size,
        "input_sha256": sha256_file(path),
        "unit_of_analysis": "Distinct incident (IncidentId); source rows are evidence-level and can repeat/conflict on incident grade.",
        "row_count": rows,
        "distinct_alert_count": len(alert_ids),
        "distinct_incident_count": len(incidents),
        "incident_grade_counts_majority_vote": dict(sorted(grade_counts.items())),
        "incidents_with_grade_ties": tied_incidents,
        "evidence_rows_by_category": dict(sorted(categories.items())),
        "deidentified_incident_profiles": profiles,
        "profile_selection_method": f"For each majority-vote grade, select up to {cohort_size} incidents by ascending SHA-256 of source IncidentId, then summarize cohort-level evidence and response-action attributes. Source IDs are not exported. This deterministic cohort is not a random, representative, or inferential sample.",
        "limitations": [
            "GUIDE is published Microsoft customer-derived security benchmark data; it is not the user's employer, tenant, or personal SOC work.",
            "Input is GUIDE_Test.csv; this descriptive report performs no train/test modeling or operational alert response.",
            "A single incident can have multiple evidence rows and conflicting row-level IncidentGrade labels. Incident counts use majority vote with a declared TruePositive > BenignPositive > FalsePositive tie-break; tied cases are counted.",
            "The data is observational and product/customer-specific; results do not establish general detection quality, SLA performance, causation, or analyst skill. Selected cohorts are illustrative, not representative cases.",
            "ActionGrouped and ActionGranular are published benchmark labels, not proof of actions performed by the user or instructions to take action.",
            "Do not publish raw entity data from the source. Keep source files in the ignored data/raw directory; exported profiles contain aggregates only, with no source incident, alert, account, IP, device, file, URL, or message identifiers.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Locally downloaded GUIDE_Test.csv (do not commit)")
    parser.add_argument("--out", type=Path, default=Path("reports/guide-summary.json"))
    parser.add_argument("--cohort-size", type=int, default=25, help="Maximum selected incidents per grade, for aggregate practice profiles")
    args = parser.parse_args()
    result = summarize(args.input, args.cohort_size)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Summarized {result['row_count']} published GUIDE evidence rows across {result['distinct_incident_count']} incidents, with de-identified aggregate cohorts. Not your SOC activity. Output: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
