from pathlib import Path
import tempfile
import unittest

import score


class ScoreTests(unittest.TestCase):
    def test_metric_preserves_true_and_false_outcomes(self):
        result = score.metric("APO999", "Test", [(True, True), (True, False), (False, True), (False, False)])
        self.assertEqual((result["tp"], result["fn"], result["fp"], result["tn"]), (1, 1, 1, 1))
        self.assertEqual((result["precision"], result["recall"], result["false_positive_rate"]), (0.5, 0.5, 0.5))

    def test_owasp_scoring_uses_unique_labeled_files(self):
        with tempfile.TemporaryDirectory() as directory:
            labels = Path(directory) / "labels.csv"
            labels.write_text("# header\nBenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,cmdi,false,78\n", encoding="utf-8")
            report = {"findings": [
                {"rule_id": "APO005", "path": "BenchmarkTest00001.java"},
                {"rule_id": "APO005", "path": "BenchmarkTest00001.java"},
                {"rule_id": "APO005", "path": "BenchmarkTest00002.java"},
            ]}
            result = score.owasp_metrics(report, labels)[0]
            self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (1, 1, 0, 0))


if __name__ == "__main__":
    unittest.main()
