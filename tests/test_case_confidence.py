"""Check adapter admission without running a target or starting Docker."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('controller', ROOT/'scripts/run_case_sandbox.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
class ConfidenceTests(unittest.TestCase):
    def test_flow_tiers_preserve_authorization_and_candidate_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'app.py').write_text('# inert fixture\n')
            case=dict(schema='apollyon.case/v1',status='candidate',scope=dict(authorized=True),
                      claim=dict(affected_locations=[dict(path='app.py')]),
                      evidence=dict(discovery=[dict(rule_id='APO004',confidence='reachable')]))
            for confidence in ['reachable','tainted']:
                case['evidence']['discovery'][0]['confidence']=confidence
                self.assertEqual(controller.safe_location(case,root)[1],root/'app.py')
            case['evidence']['discovery'][0]['confidence']='candidate'
            with self.assertRaises(ValueError): controller.safe_location(case,root)
            case['evidence']['discovery'][0]['confidence']='reachable'
            case['scope']['authorized']=False
            with self.assertRaises(ValueError): controller.safe_location(case,root)
if __name__=='__main__': unittest.main()
