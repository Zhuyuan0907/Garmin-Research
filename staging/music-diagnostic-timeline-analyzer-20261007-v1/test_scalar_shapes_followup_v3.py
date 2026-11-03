#!/usr/bin/env python3
"""New three safe-scalar/protocol interpretation controls, file-only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/analyze_garmin_music_diagnostics.py'
spec=importlib.util.spec_from_file_location('final_timeline',SOURCE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ThreeNewControls(unittest.TestCase):
    def setUp(self):
        folder=HERE/'fixtures/test_observed_change_with_shared_interval'
        self.data={role:[json.loads(line) for line in (folder/name).read_text().splitlines()] for role,name in [('phone_input','phone.jsonl'),('garmin_output','output.jsonl'),('volume','volume.jsonl')]}
        self.folder=HERE/'scalar-shape-fixtures'/self._testMethodName
        self.folder.mkdir(parents=True,exist_ok=True)

    def analyze(self,pipeline=None):
        paths=[]
        for role in ['phone_input','garmin_output','volume']:
            path=self.folder/(role+'.jsonl');path.write_text(''.join(json.dumps(row)+'\n' for row in self.data[role]));paths.append(path)
        if pipeline is not None:
            path=self.folder/'pipeline.json';path.write_text(json.dumps(pipeline));paths.append(path)
        return module.analyze(*paths)

    def test_nonstring_stop_reason_normalizes_without_traceback(self):
        self.data['garmin_output'][-1]['stop_reason']={'synthetic_private':'not_public'}
        result=self.analyze()
        self.assertEqual(result['meter_summaries']['garmin_output']['stop_kind'],'missing_or_other_error')
        self.assertNotIn('synthetic_private',json.dumps(result))

    def test_nonscalar_pipeline_role_and_error_class_do_not_escape(self):
        result=self.analyze({'supervision':{'children':[{'role':{'synthetic_private':'not_public'},'critical':True,'returncode':1}],'optional_start_failures':[{'role':'volume_observer','error_kind':{'synthetic_private':'not_public'}}],'optional_observer_failures':[{'synthetic_private':'not_public'}]}})
        self.assertEqual(result['pipeline_summary']['optional_start_failures'][0]['error_kind'],'other')
        self.assertNotIn('synthetic_private',json.dumps(result))

    def test_typed_mono_high_gain_is_held_protocol_not_bad_shape(self):
        row=self.data['volume'][1];row['volume']={'raw_q':0xc2ff,'channels':[{'index':1,'gain_0_127':66,'mute':True}]};row['codec']='Opus'
        result=self.analyze();garmin=next(e for e in result['timeline'] if e['role']=='garmin')
        self.assertEqual(garmin['state']['raw_q'],0xc2ff)
        self.assertEqual(garmin['state']['codec'],'opus')
        self.assertIn('held_SCO',garmin['state']['protocol_interpretation'])
        self.assertEqual(result['causal_verdict'],'not_available')


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ThreeNewControls))
    receipt={'tests':result.testsRun,'success':result.wasSuccessful(),'failures':len(result.failures),'errors':len(result.errors),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'earlier20_plus4_not_rerun':True,'live_operations':0}
    (HERE/'scalar-shape-test-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
