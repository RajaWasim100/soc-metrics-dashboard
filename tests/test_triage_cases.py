import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
CASE_FILE = ROOT / 'data' / 'triage-cases.json'


class TriageCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(CASE_FILE.read_text(encoding='utf-8'))
        cls.cases = cls.payload['cases']

    def test_case_narratives_are_separate_from_published_benchmark(self):
        self.assertIn('fictional', self.payload['notice'].lower())
        self.assertIn('not been run', self.payload['notice'].lower())
        self.assertEqual({case['id'] for case in self.cases}, {
            'identity-signin', 'endpoint-powershell', 'reported-phish'
        })
        combined = '\n'.join(case['kql'] for case in self.cases)
        for table in ('SigninLogs', 'DeviceProcessEvents', 'EmailEvents'):
            self.assertIn(table, combined)

    def test_each_case_has_evidence_hypotheses_and_safe_response_decisions(self):
        required = {
            'title', 'source', 'severity', 'alert', 'entities', 'facts',
            'hypotheses', 'investigate', 'query_context', 'kql',
            'recommended_action', 'actions', 'closure_criteria',
            'safety_boundary', 'references'
        }
        for case in self.cases:
            with self.subTest(case=case['id']):
                self.assertTrue(required.issubset(case))
                self.assertGreaterEqual(len(case['facts']), 2)
                self.assertGreaterEqual(len(case['hypotheses']), 2)
                self.assertIn('unexecuted', case['query_context'].lower())
                self.assertIn('take ', case['kql'].lower())
                self.assertEqual({action['id'] for action in case['actions']}, {
                    'investigate', 'escalate', 'close'
                })
                self.assertIn(case['recommended_action'], {
                    action['id'] for action in case['actions']
                })
                self.assertEqual(len(case['references']), 2)
                for reference in case['references']:
                    self.assertTrue(reference['url'].startswith('https://learn.microsoft.com/'))

    def test_browser_interface_is_wired_to_case_file_and_keyboard_accessible(self):
        html = (ROOT / 'index.html').read_text(encoding='utf-8')
        self.assertIn('data-id="triage"', html)
        self.assertIn("fetch('data/triage-cases.json')", html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('textContent', html)


if __name__ == '__main__':
    unittest.main()
