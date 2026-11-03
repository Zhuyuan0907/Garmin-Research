#!/usr/bin/env python3
"""Four new final-observer reconciliation controls; first20 not rerun."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/analyze_garmin_music_diagnostics.py'
spec=importlib.util.spec_from_file_location('new_timeline',SOURCE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class FourObserverControls(unittest.TestCase):
    def setUp(self):
        original=HERE/'fixtures/test_observed_change_with_shared_interval'
        self.data={role:[json.loads(line) for line in (original/name).read_text().splitlines()] for role,name in [('phone_input','phone.jsonl'),('garmin_output','output.jsonl'),('volume','volume.jsonl')]}
        self.folder=HERE/'observer-final-fixtures'/self._testMethodName
        self.folder.mkdir(parents=True,exist_ok=True)

    def analyze(self,suffix=''):
        paths=[]
        for role in ['phone_input','garmin_output','volume']:
            path=self.folder/(role+suffix+'.jsonl')
            path.write_text(''.join(json.dumps(row,separators=(',',':'))+'\n' for row in self.data[role]));paths.append(path)
        return module.analyze(*paths)

    def test_exact_final_summary_cap_counters_are_gaps(self):
        final=self.data['volume'][-1]
        final.pop('rows_written');final.pop('rows_skipped')
        final.update(events_written=3,events_dropped=9,polls=2,output_cap_reached=True)
        result=self.analyze();self.assertEqual(result['volume_summary']['summary_counters']['events_dropped'],9)
        self.assertIn('volume_rows_dropped_at_cap',result['volume_summary']['gaps'])
        self.assertIn('volume_output_cap_reached',result['volume_summary']['gaps'])

    def test_mono_unused_low_byte_is_metadata_not_second_channel_gain(self):
        garmin=self.data['volume'][1];garmin['volume']['raw_q']|=0x55
        later=copy.deepcopy(garmin);later.update(event='snapshot_change',monotonic_ns=1600000000)
        later['volume']['raw_q']=(15<<8)|0xaa
        self.data['volume'].insert(3,later)
        result=self.analyze();change=next(e for e in result['timeline'] if e['classification']=='ignored_mono_low_byte_metadata_change_only')
        self.assertEqual(change['changed_fields'],[])
        self.assertEqual(change['state']['channel_count'],1)
        self.assertTrue(change['state']['unused_mono_low_byte_nonzero'])

    def test_optional_SoftVolume_and_Codec_never_default_false(self):
        self.data['volume'][0].pop('soft_volume');self.data['volume'][0].pop('codec')
        self.data['volume'][2]['volume']=copy.deepcopy(self.data['volume'][0]['volume'])
        result=self.analyze();initial=result['timeline'][0]
        self.assertIsNone(initial['state']['soft_volume']);self.assertEqual(initial['state']['codec'],'absent')
        discovery=next(e for e in result['timeline'] if e['classification']=='optional_metadata_availability_change_only')
        self.assertEqual(discovery['changed_fields'],[])
        self.assertEqual(result['volume_summary']['control_changes'],0)

    def test_one_row_missing_clock_or_run_disables_binding(self):
        self.data['volume'][2].pop('diagnostic_run_id')
        result=self.analyze('-missing-run')
        self.assertFalse(result['clock_provenance']['cross_file_monotonic_binding'])
        self.assertEqual(result['clock_provenance']['source_clocks'][2]['rows_without_run_id'],1)
        self.data['volume'][2]['diagnostic_run_id']='synthetic_shared_run'
        self.data['garmin_output'][1].pop('monotonic_ns')
        result=self.analyze('-missing-mono')
        self.assertFalse(result['clock_provenance']['cross_file_monotonic_binding'])
        self.assertEqual(result['clock_provenance']['source_clocks'][1]['rows_without_monotonic'],1)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FourObserverControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    receipt={'schema':'music-timeline-final-observer-followup-controls/v2','tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'success':result.wasSuccessful(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'first20_closed_controls_not_rerun':True,'scope':'Only four concrete final-schema differences identified by source reviewer; JSONL fabricated scalar fields, no PCM/Bluetooth/audio.','live_operations':0}
    (HERE/'observer-followup-test-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
