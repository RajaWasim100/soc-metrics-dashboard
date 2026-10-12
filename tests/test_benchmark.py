import csv
import tempfile
import unittest
from pathlib import Path

from data.benchmark import summarize


class GuideBenchmarkTests(unittest.TestCase):
    def test_groups_evidence_rows_by_incident_and_labels_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'GUIDE_Test.csv'
            fields = [
                'Id', 'IncidentId', 'AlertId', 'Timestamp', 'Category', 'IncidentGrade',
                'EntityType', 'EvidenceRole', 'MitreTechniques', 'ActionGrouped', 'ActionGranular'
            ]
            with source.open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows([
                    {'Id': '1', 'IncidentId': 'i-1', 'AlertId': 'a-1', 'Timestamp': '2024-01-01T00:00:00Z', 'Category': 'Execution', 'IncidentGrade': 'TruePositive', 'EntityType': 'Process', 'EvidenceRole': 'Impacted', 'MitreTechniques': 'T1059', 'ActionGrouped': 'Quarantine', 'ActionGranular': 'Isolate machine'},
                    {'Id': '2', 'IncidentId': 'i-1', 'AlertId': 'a-2', 'Timestamp': '2024-01-01T00:01:00Z', 'Category': 'Execution', 'IncidentGrade': 'TruePositive', 'EntityType': 'User', 'EvidenceRole': 'Related', 'MitreTechniques': 'T1059;T1059', 'ActionGrouped': 'Quarantine', 'ActionGranular': 'Collect investigation package'},
                    {'Id': '3', 'IncidentId': 'i-2', 'AlertId': 'a-3', 'Timestamp': '2024-01-01T00:02:00Z', 'Category': 'InitialAccess', 'IncidentGrade': 'FalsePositive', 'EntityType': 'Ip', 'EvidenceRole': 'Impacted', 'MitreTechniques': '', 'ActionGrouped': '', 'ActionGranular': ''},
                    {'Id': '4', 'IncidentId': 'i-2', 'AlertId': 'a-4', 'Timestamp': '2024-01-01T00:03:00Z', 'Category': 'InitialAccess', 'IncidentGrade': 'BenignPositive', 'EntityType': 'Machine', 'EvidenceRole': 'Related', 'MitreTechniques': 'T1110', 'ActionGrouped': '', 'ActionGranular': ''},
                    {'Id': '5', 'IncidentId': 'i-3', 'AlertId': 'a-5', 'Timestamp': '2024-01-01T00:04:00Z', 'Category': 'Discovery', 'IncidentGrade': 'FalsePositive', 'EntityType': 'Machine', 'EvidenceRole': 'Impacted', 'MitreTechniques': 'T1087', 'ActionGrouped': 'Investigate', 'ActionGranular': 'Review activity'},
                ])
            result = summarize(source)
            self.assertEqual(result['row_count'], 5)
            self.assertEqual(result['distinct_alert_count'], 5)
            self.assertEqual(result['distinct_incident_count'], 3)
            self.assertEqual(result['incident_grade_counts_majority_vote'], {
                'BenignPositive': 1, 'FalsePositive': 1, 'TruePositive': 1,
            })
            self.assertEqual(result['evidence_rows_by_category'], {
                'Discovery': 1, 'Execution': 2, 'InitialAccess': 2,
            })
            self.assertEqual(result['incidents_with_grade_ties'], 1)
            self.assertIn('NOT USER', result['label'])
            self.assertEqual(len(result['input_sha256']), 64)
            self.assertEqual(len(result['deidentified_incident_profiles']), 3)
            profile = next(p for p in result['deidentified_incident_profiles'] if p['majority_vote_grade'] == 'TruePositive')
            self.assertEqual(profile['total_evidence_rows'], 2)
            self.assertEqual(profile['distinct_alert_count'], 2)
            self.assertEqual(profile['median_evidence_rows_per_incident'], 2)
            self.assertEqual(profile['top_entity_types'], {'Process': 1, 'User': 1})
            self.assertEqual(profile['top_mitre_techniques'], {'T1059': 3})
            self.assertEqual(profile['grouped_response_actions'], {'Quarantine': 2})
            self.assertEqual(profile['top_granular_response_actions'], {
                'Collect investigation package': 1, 'Isolate machine': 1,
            })
            false_positive = next(p for p in result['deidentified_incident_profiles'] if p['majority_vote_grade'] == 'FalsePositive')
            self.assertEqual(false_positive['top_granular_response_actions'], {'Review activity': 1})
            serialized = repr(result)
            for forbidden in ("'incident_id':", "'IncidentId':", "'alert_id':", "'AlertId':", "'IpAddress':", "'DeviceName':", "'AccountUpn':", 'i-1', 'i-2', 'i-3', 'a-1', 'a-2', 'a-3', 'a-4', 'a-5'):
                self.assertNotIn(forbidden, serialized)

    def test_bad_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'bad.csv'
            source.write_text('IncidentId,IncidentGrade\ni-1,Unknown\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'missing required fields'):
                summarize(source)

    def test_unknown_grade_is_not_silently_counted(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'bad.csv'
            source.write_text(
                'Id,IncidentId,AlertId,Timestamp,Category,IncidentGrade,EntityType,EvidenceRole,MitreTechniques,ActionGrouped,ActionGranular\n'
                '1,i-1,a-1,2024-01-01T00:00:00Z,Execution,Unknown,Process,Impacted,T1059,,\n',
                encoding='utf-8'
            )
            with self.assertRaisesRegex(ValueError, 'Unexpected IncidentGrade'):
                summarize(source)


if __name__ == '__main__':
    unittest.main()
