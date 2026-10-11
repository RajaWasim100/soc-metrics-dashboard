# SOC Metrics Dashboard Lab

**Portfolio scaffold · all included data is synthetic · no SIEM connection**

A small Python/SQLite workflow for analyzing a synthetic security-alert queue, producing operational KPIs and a CSV summary. The interactive front page is [index.html](index.html). It is intended to demonstrate data handling and careful metric definitions—not real SOC performance, Microsoft Sentinel integration, or production detection quality.

## Run locally

Python 3.10+, standard library only.

```bash
python build_metrics.py
python -m unittest discover -s tests -v
```

Inputs are `data/alerts.csv` and `data/incidents.csv`. The pipeline loads only the rows in the selected source CSVs into SQLite at `data/soc-metrics.sqlite` on every run (so changed/deleted input rows are reflected), computes KPI summaries, and writes `reports/metrics.json` and `reports/metrics-summary.csv`. Timestamps must be ISO 8601 with an explicit timezone; values normalize to UTC, while naive/malformed timestamps and bad headers are rejected.

## Definitions and caveats

- **Alert volume:** number of alert records by type and disposition in the selected dataset. Duplicate and informational records have not been deduplicated unless explicitly represented.
- **Time to detect (TTD):** `detected_at - occurred_at` for incidents with both valid timestamps. Missing values are excluded and counted; negative intervals are rejected from the average and counted as invalid.
- **Time to respond (TTR):** `first_response_at - detected_at`, defined as first human/automated response logged, not containment or recovery. Missing values are excluded and counted.
- **Resolution time:** `resolved_at - detected_at`; not equivalent to response time. Not currently reported as TTR.
- **Percentiles/averages:** synthetic sample only; tiny samples are unstable and should not be used to compare teams.
- **SLA attainment:** not claimed; no real policy target is configured.

Never represent the sample's counts or times as real operations. A real dashboard requires agreed event definitions, source-of-truth timestamps, deduplication, timezone normalization, retention/privacy controls, and stakeholder validation. Do not commit live security telemetry or identifiers.

## Data and privacy

Rows are invented records with fake IDs, reserved `.invalid` domains, and documentation IP ranges. Security operations data may disclose detection coverage, identities, and system weaknesses; keep real exports private and redact only under approved rules.
