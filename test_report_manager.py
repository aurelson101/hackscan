import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_advisor import ai_advice
from report_manager import delete_reports, export_report_list, list_reports, parse_selection, preview_prune, prune_reports


def make_report(root, name, started):
    folder = root / name
    folder.mkdir()
    (folder / 'report.json').write_text(json.dumps({
        'target': 'https://example.invalid', 'started_utc': started, 'status': 'terminé',
        'summary': {'severity_counts': {'Haute': 1}},
    }), encoding='utf-8')
    return folder


class ReportManagerTests(unittest.TestCase):
    def test_list_and_priorities_only_include_valid_direct_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_report(root, 'valid', '2026-01-01T00:00:00Z')
            (root / 'other').mkdir()
            reports = list_reports(root)
            self.assertEqual([r['name'] for r in reports], ['valid'])
            self.assertEqual(reports[0]['priorities']['Haute'], 1)

    def test_prune_keeps_ten_and_preserves_non_report_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for number in range(12):
                make_report(root, f'report-{number:02}', f'2026-01-{number + 1:02}T00:00:00Z')
            (root / 'notes').mkdir()
            removed = prune_reports(root, 10)
            self.assertEqual(removed, ['report-01', 'report-00'])
            self.assertTrue((root / 'notes').exists())
            self.assertEqual(len(list_reports(root)), 10)

    def test_delete_rejects_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_report(root, 'valid', '2026-01-01T00:00:00Z')
            os.symlink(root / 'valid', root / 'link')
            for unsafe in ('../valid', 'link'):
                with self.assertRaises(ValueError):
                    delete_reports(root, [unsafe])

    def test_selection_accepts_ranges(self):
        self.assertEqual(parse_selection('1,3-4', 4), [1, 3, 4])

    def test_metadata_is_resilient_and_reports_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); report = make_report(root, 'valid', '2026-01-01T00:00:00Z')
            report_file = report / 'report.json'
            import hashlib
            digest = hashlib.sha256(report_file.read_bytes()).hexdigest()
            (report / 'manifest.sha256').write_text(digest + '  report.json\n', encoding='utf-8')
            item = list_reports(root)[0]
            self.assertEqual(item['integrity'], 'valide')
            self.assertEqual(item['top_priority'], 'Haute')
            self.assertGreaterEqual(item['size_bytes'], report_file.stat().st_size)

    def test_filters_machine_exports_and_prune_preview(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for number in range(3):
                report = make_report(root, f'report-{number}', f'2026-01-0{number + 1}T00:00:00Z')
                if number == 0:
                    data = json.loads((report / 'report.json').read_text())
                    data['target'] = 'https://filtered.invalid\nunsafe'
                    data['status'] = 'incomplet'
                    (report / 'report.json').write_text(json.dumps(data))
            filtered = list_reports(root, target='filtered', status='incomplet')
            self.assertEqual(len(filtered), 1)
            self.assertNotIn('\n', filtered[0]['target'])
            self.assertIn('"name"', export_report_list(filtered, 'json'))
            self.assertIn('name,started_utc', export_report_list(filtered, 'csv'))
            self.assertEqual(preview_prune(root, 2), ['report-0'])


class AiProviderTests(unittest.TestCase):
    report = {'status': 'terminé', 'findings': [{'title': 'HSTS', 'severity': 'Faible',
              'confidence': 'observé', 'remediation': 'Configurer'}], 'limitations': []}

    def test_openai_uses_responses_structured_output_without_retaining_key(self):
        class Response:
            def raise_for_status(self): pass
            def json(self): return {'output_text': json.dumps({'summary': 'S', 'priorities': ['P'], 'questions': []})}
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'temporary-secret'}), \
             patch('ai_advisor.requests.Session.post', return_value=Response()) as post:
            result = ai_advice(self.report, 'openai')
        self.assertEqual(post.call_args.args[0], 'https://api.openai.com/v1/responses')
        self.assertEqual(post.call_args.kwargs['json']['text']['format']['type'], 'json_schema')
        self.assertNotIn('temporary-secret', json.dumps(result))

    def test_mistral_uses_json_mode(self):
        class Response:
            def raise_for_status(self): pass
            def json(self): return {'choices': [{'message': {'content': json.dumps(
                {'summary': 'S', 'priorities': [], 'questions': []})}}]}
        with patch.dict(os.environ, {'MISTRAL_API_KEY': 'temporary-secret'}), \
             patch('ai_advisor.requests.Session.post', return_value=Response()) as post:
            result = ai_advice(self.report, 'mistral')
        self.assertEqual(result['status'], 'proposition à valider')
        self.assertEqual(post.call_args.kwargs['json']['response_format'], {'type': 'json_object'})

    def test_missing_cloud_key_is_cleanly_reported(self):
        with patch.dict(os.environ, {}, clear=True):
            result = ai_advice(self.report, 'openai')
        self.assertEqual(result['status'], 'indisponible')
        self.assertNotIn('Bearer', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
