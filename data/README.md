# Published Microsoft GUIDE benchmark data

The default dashboard files are **published real-world benchmark data**, not the user's work or tenant. The benchmark report explicitly identifies the source. Do not copy raw source files, identifiers, IPs, URLs, or other entity-level fields into GitHub or the browser UI.

## Obtain GUIDE test data (about 1.09 GB)

Download the official public dataset, version 2:

- Dataset: [Microsoft Security Incident Prediction (GUIDE)](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction)
- Paper: [AI-Driven Guided Response for Security Operation Centers](https://arxiv.org/html/2407.09017v2)
- License: [CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/) — may be used, modified, and shared; if redistributing source data, include the license agreement text with it. This project does not redistribute the source file.
- Test file: `GUIDE_Test.csv` (large; version 2 endpoint URL below)

Download into the ignored `data/raw/` directory and run the report (the downloader is a single command with no non-standard dependencies):

```bash
python -c "from urllib.request import urlretrieve; from pathlib import Path; p=Path('data/raw'); p.mkdir(parents=True, exist_ok=True); urlretrieve('https://www.kaggle.com/api/v1/datasets/download/Microsoft/microsoft-security-incident-prediction?datasetVersionNumber=2&fileName=GUIDE_Test.csv', p/'GUIDE_Test.csv')"
python data/benchmark.py data/raw/GUIDE_Test.csv --out reports/guide-summary.json
```

The current version-2 `GUIDE_Test.csv` has 4,147,992 evidence rows, 637,320 distinct alert IDs, and 236,267 incident IDs. Row labels conflict within some incidents: the report groups by `IncidentId`, uses the majority row label, declares a deterministic tie-break, and reports the number of tied incidents. These are dataset-level descriptive counts, not incident-handling performance or the user's SOC experience. The program scans the CSV incrementally for validation but keeps incident counters/IDs in memory; it is suitable for this 1.09 GB test split on a normal workstation with several GB free RAM, not for the multi-GB full training file without profiling.

## Included safe aggregate report

`reports/guide-summary.json` was computed from the official test file after checking its 1,087,963,831-byte size. SHA-256: `fdfd7523efd6e3c26bd0290ba6acbcb237196cf923dd56a28e96802035db35a3`. It contains source-verified aggregate counts and bounded profiles for up to 25 incidents per majority-vote grade. Profiles include evidence counts/categories, entity-type mix, evidence roles, MITRE references, and response action labels where present. No source incident IDs or raw entity values are exported. Deterministic cohorts are illustrative, not random or representative. Reproduce the report with the command above. Dataset versions may change; compare the source checksum and update the report when intentionally refreshing.

GUIDE contains product/customer-derived real-world security events and triage labels, but it is not a user-owned lab, an employer tenant, an individual analyst's work, or evidence that the user performed a response action. Its product/customer mix and label semantics limit generalization. Do not claim Sentinel integration: this offline pipeline reads a published CSV, not live Sentinel or Defender.

## Official source schema references

GUIDE v2 fields used by this summary and optional local cohort profiles include `Id`, `IncidentId`, `AlertId`, `Timestamp`, `Category`, `IncidentGrade`, `EntityType`, `EvidenceRole`, and `MitreTechniques`. Other source columns contain sensitive entity attributes and are not exported. The published table has an evidence-level unit of analysis: multiple rows may relate to one alert or incident. For Defender query schema and service availability, see Microsoft Learn [`DeviceProcessEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [`EmailEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table), and the [advanced hunting schema overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables). Those service tables are not the GUIDE CSV schema.
