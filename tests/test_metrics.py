import csv
import sqlite3
import tempfile
import unittest
from pathlib import Path
from build_metrics import SCHEMA,build,load_csv,minutes
ROOT=Path(__file__).parents[1]

class MetricsTests(unittest.TestCase):
    def test_timezone_normalization(self):
        value,state=minutes('2026-10-04T12:00:00-04:00','2026-10-04T16:30:00Z')
        self.assertEqual((value,state),(30.0,'valid'))

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'must include a timezone'):
            minutes('2026-10-01T08:00:00','2026-10-01T08:05:00Z')

    def test_missing_and_negative_intervals_are_excluded(self):
        self.assertEqual(minutes('','2026-01-01T00:00:00Z'),(None,'missing'))
        self.assertEqual(minutes('2026-01-02T00:00:00Z','2026-01-01T00:00:00Z'),(None,'invalid'))

    def test_dataset_metrics_and_data_quality(self):
        with tempfile.TemporaryDirectory() as td:
            conn=sqlite3.connect(Path(td)/'metrics.sqlite');conn.executescript(SCHEMA)
            try:
                load_csv(conn,ROOT/'data/alerts.csv',ROOT/'data/incidents.csv')
                result=build(conn)
                self.assertEqual(result['alert_record_count'],12)
                self.assertEqual(result['incident_count'],7)
                self.assertEqual(result['time_to_detect']['count'],6)
                self.assertEqual(result['time_to_detect']['mean_minutes'],29.67)
                self.assertEqual(result['time_to_first_response']['count'],6)
                self.assertEqual(result['missing_interval_count']['ttr'],1)
                self.assertEqual(result['invalid_negative_interval_count']['ttd'],1)
                self.assertTrue(result['label'].startswith('SYNTHETIC'))
                # Re-running with same source replaces rather than duplicates.
                load_csv(conn,ROOT/'data/alerts.csv',ROOT/'data/incidents.csv')
                again=build(conn)
                self.assertEqual(again['alert_record_count'],12)
                self.assertEqual(again['time_to_detect'],result['time_to_detect'])
            finally:
                conn.close()

    def test_empty_database_returns_null_not_division_error(self):
        conn=sqlite3.connect(':memory:');conn.executescript(SCHEMA)
        result=build(conn)
        self.assertIsNone(result['time_to_detect']['mean_minutes'])
        self.assertEqual(result['alert_record_count'],0)
        conn.close()

    def test_malformed_timestamp_rejected_before_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            db=sqlite3.connect(Path(td)/'db.sqlite');db.executescript(SCHEMA)
            alerts=Path(td)/'alerts.csv';incidents=Path(td)/'incidents.csv'
            alerts.write_text('alert_id,created_at,alert_type,severity,disposition,source\nA-1,not-a-time,Other,Low,Open,Test\n',encoding='utf-8')
            incidents.write_text('incident_id,alert_id,occurred_at,detected_at,first_response_at,resolved_at,category,outcome\n',encoding='utf-8')
            with self.assertRaises(ValueError):load_csv(db,alerts,incidents)
            db.close()

    def test_missing_required_csv_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            db=sqlite3.connect(Path(td)/'db.sqlite');db.executescript(SCHEMA)
            alerts=Path(td)/'alerts.csv';incidents=Path(td)/'incidents.csv'
            alerts.write_text('alert_id,created_at\n',encoding='utf-8')
            incidents.write_text('incident_id,alert_id,occurred_at,detected_at,first_response_at,resolved_at,category,outcome\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'missing required CSV columns'):load_csv(db,alerts,incidents)
            db.close()

    def test_duplicate_key_rolls_back_full_refresh(self):
        with tempfile.TemporaryDirectory() as td:
            db=sqlite3.connect(Path(td)/'db.sqlite');db.executescript(SCHEMA)
            alerts=Path(td)/'alerts.csv';incidents=Path(td)/'incidents.csv'
            alerts.write_text('alert_id,created_at,alert_type,severity,disposition,source\nA-1,2026-10-01T00:00:00Z,One,Low,Open,Test\n',encoding='utf-8')
            incidents.write_text('incident_id,alert_id,occurred_at,detected_at,first_response_at,resolved_at,category,outcome\n',encoding='utf-8')
            load_csv(db,alerts,incidents)
            alerts.write_text('alert_id,created_at,alert_type,severity,disposition,source\nA-2,2026-10-01T00:00:00Z,Two,Low,Open,Test\nA-2,2026-10-01T00:00:00Z,Two,Low,Open,Test\n',encoding='utf-8')
            with self.assertRaises(sqlite3.IntegrityError):load_csv(db,alerts,incidents)
            self.assertEqual(db.execute('select alert_id from alerts').fetchall(),[('A-1',)])
            db.close()

if __name__=='__main__':unittest.main()
