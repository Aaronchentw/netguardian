import csv
import tempfile
import unittest
from pathlib import Path
from netguardian import analyze, evaluate, fit, load_rows, write_report
from make_data import FIELDS, generate


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.model = fit(list(generate(120, 11)))

    def test_held_out_synthetic_scenarios(self):
        results = [analyze(r, self.model) for r in generate(60, 29, True)]
        self.assertEqual(evaluate(results), dict(tp=30, fp=0, fn=0, tn=30, precision=1.0, recall=1.0))
        for kind in ('dns', 'scan', 'upload'):
            self.assertTrue(all(r['flagged'] and r['next_steps'] for r in results if r['label'] == kind))

    def test_labels_never_change_predictions(self):
        row = next(generate(1, 42))
        a = analyze(row, self.model)
        b = analyze({**row, 'label': 'scan'}, self.model)
        self.assertEqual((a['score'], a['flagged']), (b['score'], b['flagged']))

    def test_zero_denominators_and_unknown_anomaly(self):
        row = next(generate(1, 42))
        row.update(dns_queries=0, dns_failures=0, syn_packets=0, synack_packets=0, distinct_ports=100)
        result = analyze(row, self.model)
        self.assertTrue(result['flagged'])
        self.assertIn('No matched diagnostic pattern', result['evidence'][0])

    def test_invalid_counts_rejected(self):
        for value in ('nan', 'inf', '-1', '1.5', 'oops'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'bad.csv'
                row = next(generate(1, 1))
                row['bytes_out'] = value
                with path.open('w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=FIELDS)
                    writer.writeheader()
                    writer.writerow(row)
                with self.assertRaises(ValueError):
                    load_rows(path)

    def test_report_escapes_imported_host(self):
        row = next(generate(1, 1))
        row['host'] = '<script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'report.html'
            write_report([analyze(row, self.model)], path)
            report = path.read_text(encoding='utf-8')
            self.assertNotIn('<script>', report)
            self.assertIn('&lt;script&gt;', report)


if __name__ == '__main__':
    unittest.main()
