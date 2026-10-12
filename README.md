# SOC Metrics Dashboard Lab

**Published dataset analysis · no live SIEM connection · not the user's SOC activity**

A Python workflow and interactive dashboard for transparent descriptive analysis of Microsoft's published GUIDE security-incident benchmark. GUIDE is genuine research-released customer-derived cybersecurity data, but it is not the user's employer/tenant telemetry, personal SOC work, or proof of performing any incident response. The page has no live Sentinel or Defender connection.

## Run locally

Python 3.10+, standard library only. Download the published test split as described in [`data/README.md`](data/README.md) (about 1.09 GB; raw source remains git-ignored), then run:

```bash
python data/benchmark.py data/raw/GUIDE_Test.csv --out reports/guide-summary.json
python -m unittest discover -s tests -v
```

The committed [`reports/guide-summary.json`](reports/guide-summary.json) contains source-verified aggregate benchmark counts from GUIDE v2 `GUIDE_Test.csv`, with byte size and SHA-256 recorded. No raw source rows, entity values, or source identifiers are committed. The report also contains deterministic, de-identified aggregate profiles for up to 25 incidents per majority-vote grade, generated from the complete local GUIDE source. Profiles summarize evidence categories, entity types, roles, MITRE references and published action fields; no source IDs or raw entity values are exported. The script checks required columns and class labels, streams CSV rows, counts distinct alert/incident IDs, aggregates evidence-row grades to incidents by majority vote, and declares a stable tie-break.

## What this dataset supports (and does not)

- **Real published benchmark:** Microsoft describes GUIDE as real-world security incidents with alert/evidence records and triage labels. The selected test file contains 4,147,992 evidence rows, 637,320 distinct AlertIds, and 236,267 IncidentIds.
- **Incident-grade summaries:** labels are `TruePositive`, `FalsePositive`, and `BenignPositive`. Multiple evidence rows for an incident may disagree; majority aggregation and 2,993 tied incidents are reported, not hidden.
- **De-identified evidence cohorts:** the checked-in report includes aggregate patterns for 25 deterministically selected incidents per grade, including evidence counts/categories, entity-type mix, roles, MITRE technique references, and action fields (empty for these selected cohorts where the source has no values). These are cohort summaries, not narratives, representative samples, or personal investigations.
- **Not response-time metrics:** GUIDE fields used here do not establish trustworthy `occurred_at`, `detected_at`, or `first_response_at` intervals. This project does not claim TTD/TTR, SLA attainment, analyst performance, or remediation success.
- **Not a personal portfolio log:** counts and label distributions describe a published Microsoft benchmark, not work you did.
- **No Microsoft tenant access:** example KQL in the triage tab is unexecuted. Telemetry access requires suitable products, licenses, connectors, permissions, and retention.

## Provenance, license, and privacy

Microsoft GUIDE v2: [official Kaggle dataset](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction), [paper](https://arxiv.org/html/2407.09017v2), released under [CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/). If redistributing source data, include the agreement text; this repository intentionally excludes raw data. The local ignored source CSV contains rich entity columns: do not upload it, extract row examples to HTML, or assume every derived entity value is safe for public sharing.

The CISA/NVD terms do not apply to GUIDE, and GUIDE license terms do not apply to phishing/vulnerability repositories. See [`data/README.md`](data/README.md) for data-acquisition details and [`kql/README.md`](kql/README.md) for separately sourced query examples.

## Alert triage & investigation exercises

The **Alert triage** tab adds three clearly fictional case-based exercises: an unfamiliar sign-in pattern, a suspicious endpoint process chain, and a user-reported credential lure. Each separates supplied facts from hypotheses and unknowns, gives a scoped investigation plan, presents an illustrative KQL pivot, and lets you compare a disposition choice against the training rationale. A local-only worksheet helps structure observations, evidence references, next steps, and a proposed disposition; it is not saved or transmitted.

The KQL snippets are unexecuted examples—not evidence, detection results, an integration, or proof of Sentinel/Defender experience. GUIDE benchmark aggregates are real published data, clearly separated from the fictional case exercises. Query table availability depends on actual Microsoft product telemetry, workspace configuration, licensing, permissions, and retention. See [`kql/README.md`](kql/README.md) and the linked Microsoft Learn references for schema/context. Never perform containment or query real tenant data without authorization.

## Data and privacy

The dashboard aggregates published GUIDE benchmark rows. The triage-case narratives remain explicitly fictional exercises. Keep downloaded raw source and any private operational exports outside Git; security records can expose identities, indicators, and weaknesses.
