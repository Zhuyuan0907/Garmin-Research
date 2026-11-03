#!/usr/bin/env python3
"""Synthetic scalar-log controls, ordinary files only; never raw/live audio."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/analyze_garmin_music_diagnostics.py'
spec=importlib.util.spec_from_file_location('timeline_only',SOURCE)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
FIXTURES=HERE/'fixtures'
FIXTURES.mkdir(exist_ok=True)


def dump(path,value,jsonl=True):
    raw=(''.join(json.dumps(row,separators=(',',':'),allow_nan=False)+'\n' for row in value) if jsonl else json.dumps(value)).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def meter(role,channels,rate,rms):
    base={'clock_kind':'host_monotonic_ns','diagnostic_run_id':'synthetic_shared_run'}
    start=dict(base,type='start',schema=module.METER_SCHEMA,label=role,utc='2026-10-07T10:00:00+00:00',monotonic_ns=0,sampling=rate,channels=channels,format='s16le')
    levels={'frames':rate,'channels':[{'rms_s16':rms,'peak_s16':1000,'mean_s16':0,'full_scale_sample_count':0} for _ in range(channels)]}
    if channels==2:levels['equal_weight_mono_rms_s16']=500
    window=dict(base,type='window',index=1,utc='2026-10-07T10:00:01+00:00',monotonic_ns=2100000000,start_frame=0,end_frame=rate,arrival_begin_monotonic_ns=1000000000,arrival_end_monotonic_ns=2000000000,forward_end_monotonic_ns=2050000000,levels=levels)
    summary=dict(base,type='summary',label=role,utc='2026-10-07T10:00:02+00:00',monotonic_ns=3000000000,returncode=0,stop_reason='input_eof',input_bytes=rate*channels*2,forwarded_bytes=rate*channels*2,unmeasured_frame_tail_bytes=0,input_bytes_not_in_levels=0,windows_total=1,diagnostic_rows_skipped_at_byte_cap=0,maximum_pipe_forward_wait_ms=0,total_pipe_forward_wait_ms=0)
    return [start,window,summary]


def volume_row(role,event,time,value=127,soft=True):
    raw=(value<<8)|value if role=='phone' else value<<8
    channels=[{'index':1,'gain_0_127':value,'mute':False}]
    if role=='phone':channels.append({'index':2,'gain_0_127':value,'mute':False})
    row={'schema':module.VOLUME_SCHEMA,'role':role,'event':event,'state':'ok','timestamp_utc':'2026-10-07T10:00:01+00:00','monotonic_ns':time,'clock_kind':'host_monotonic_ns','diagnostic_run_id':'synthetic_shared_run','volume':{'raw_q':raw,'channels':channels},'soft_volume':soft,'codec':'sbc' if role=='phone' else 'cvsd'}
    return row


def volume():
    return [volume_row('phone','initial',100000000),volume_row('garmin','initial',200000000,15,False),volume_row('phone','snapshot_change',1500000000,63),{'schema':module.VOLUME_SCHEMA,'event':'final_summary','role':'observer','timestamp_utc':'2026-10-07T10:00:02+00:00','monotonic_ns':2700000000,'clock_kind':'host_monotonic_ns','diagnostic_run_id':'synthetic_shared_run','rows_written':3,'rows_skipped':0}]


class TimelineControls(unittest.TestCase):
    def setUp(self):
        self.name=self._testMethodName
        self.folder=FIXTURES/self.name
        self.folder.mkdir(exist_ok=True)
        self.phone=meter('phone_input',2,44100,1000)
        self.output=meter('garmin_output',1,8000,250)
        self.volume=volume()

    def paths(self,pipeline=None):
        paths=[self.folder/'phone.jsonl',self.folder/'output.jsonl',self.folder/'volume.jsonl']
        for path,rows in zip(paths,[self.phone,self.output,self.volume]):dump(path,rows)
        if pipeline is not None:
            extra=self.folder/'pipeline.json';dump(extra,pipeline,False);paths.append(extra)
        return paths

    def result(self,pipeline=None):
        return module.analyze(*self.paths(pipeline))

    def test_observed_change_with_shared_interval(self):
        result=self.result()
        self.assertTrue(result['clock_provenance']['cross_file_monotonic_binding'])
        self.assertEqual(result['volume_summary']['control_changes'],1)
        change=next(e for e in result['timeline'] if e['classification']=='observed_control_change')
        self.assertEqual(change['measurement_windows']['phone_input']['windows'][0]['distance_ns'],0)
        self.assertEqual(result['causal_verdict'],'not_available')

    def test_no_change_is_not_pumping(self):
        self.volume[2]=volume_row('phone','snapshot',1500000000)
        result=self.result()
        self.assertEqual(result['volume_summary']['control_changes'],0)
        self.assertFalse(result['speaker_improvement_proved'])

    def test_missing_state_resets_prior_comparison(self):
        absent=dict(self.volume[2]);absent['event']='role_missing';absent['state']='missing';absent.pop('volume');absent.pop('soft_volume')
        self.volume.insert(2,absent)
        result=self.result()
        self.assertIn('role_missing',result['volume_summary']['gaps'])
        self.assertEqual(result['volume_summary']['control_changes'],0)
        self.assertTrue(any(e['classification']=='reported_change_without_previous_state' for e in result['timeline']))

    def test_ambiguous_overlapping_host_intervals(self):
        for rows in [self.phone,self.output]:
            new=copy.deepcopy(rows[1]);new['index']=2;new['start_frame']=new['end_frame'];new['end_frame']*=2
            rows.insert(2,new);rows[-1]['windows_total']=2
        result=self.result()
        change=next(e for e in result['timeline'] if e['classification']=='observed_control_change')
        self.assertTrue(change['measurement_windows']['garmin_output']['ambiguous_multiple_windows'])

    def test_old_UTC_only_is_weak(self):
        for rows in [self.phone,self.output,self.volume]:
            for row in rows:
                row.pop('monotonic_ns',None);row.pop('clock_kind',None);row.pop('diagnostic_run_id',None)
        result=self.result();self.assertFalse(result['clock_provenance']['cross_file_monotonic_binding'])
        self.assertEqual(result['timeline'][0]['measurement_windows']['phone_input']['quality'],'weak_UTC_emit_time_only')

    def test_null_run_id_does_not_bind(self):
        for row in self.phone:row['diagnostic_run_id']=None
        self.assertFalse(self.result()['clock_provenance']['cross_file_monotonic_binding'])

    def test_different_run_id_does_not_bind(self):
        for row in self.output:row['diagnostic_run_id']='synthetic_other_run'
        self.assertFalse(self.result()['clock_provenance']['cross_file_monotonic_binding'])

    def test_clock_reset_disables_monotonic_combination(self):
        self.volume[-1]['monotonic_ns']=1
        result=self.result();self.assertFalse(result['clock_provenance']['cross_file_monotonic_binding'])
        self.assertTrue(result['clock_provenance']['source_clocks'][2]['monotonic_reset'])

    def test_read_order_only_without_UTC(self):
        for rows in [self.phone,self.output,self.volume]:
            for row in rows:
                row.pop('utc',None);row.pop('timestamp_utc',None);row.pop('diagnostic_run_id',None)
        result=self.result()
        self.assertEqual(result['timeline'][0]['measurement_windows']['phone_input']['quality'],'read_order_only_no_cross_file_alignment')

    def test_endpoints_tail_and_stall_are_not_packetloss(self):
        self.output[1]['levels']['channels'][0]['full_scale_sample_count']=5
        self.output[-1].update(returncode=2,stop_reason='truncated_sample_frame',unmeasured_frame_tail_bytes=1,input_bytes_not_in_levels=1,maximum_pipe_forward_wait_ms=350)
        result=self.result();summary=result['meter_summaries']['garmin_output']
        self.assertEqual(summary['full_scale_endpoint_counts'],[5]);self.assertIn('unmeasured_frame_tail_bytes',summary['gaps'])
        self.assertEqual(summary['summary_flags']['maximum_pipe_forward_wait_ms'],350)

    def test_row_cap_drop_and_missing_summary_reported(self):
        self.output[-1].update(diagnostic_rows_skipped_at_byte_cap=7,windows_total=8)
        self.phone.pop();self.volume.pop()
        result=self.result()
        self.assertIn('diagnostic_rows_skipped_at_byte_cap',result['meter_summaries']['garmin_output']['gaps'])
        self.assertIn('missing_volume_final_summary',result['volume_summary']['gaps'])

    def test_frame_equality_alone_never_unlocks_ratio(self):
        result=self.result()
        self.assertEqual(result['descriptive_ratios']['pairs'],[])

    def test_pinned_content_mapping_unlocks_only_descriptive_ratio(self):
        paths=self.paths()
        alignment={'schema':'garmin-music-diagnostic-alignment/v1','source_sha256':{'phone_input':hashlib.sha256(paths[0].read_bytes()).hexdigest(),'garmin_output':hashlib.sha256(paths[1].read_bytes()).hexdigest()},'window_pairs':[{'phone_input_index':1,'garmin_output_index':1,'source_content_verified':True,'resampling_mapping_verified':True,'complete_source_sample_spans':True,'relation':'same_source_sample_span','input_basis':'equal_weight_mono','mono_mode':'average'}]}
        result=self.result({'diagnostic_alignment':alignment})
        self.assertEqual(result['descriptive_ratios']['pairs'][0]['RMS_ratio'],0.5)
        self.assertEqual(result['causal_verdict'],'not_available')

    def test_alignment_wrong_hash_refused(self):
        with self.assertRaisesRegex(module.DataError,'alignment_input_hash_mismatch'):
            self.result({'diagnostic_alignment':{'schema':'garmin-music-diagnostic-alignment/v1','source_sha256':{},'window_pairs':[]}})

    def test_partial_windows_hold_ratio_even_with_metadata(self):
        self.phone[1]['partial_window']=True
        paths=self.paths();alignment={'schema':'garmin-music-diagnostic-alignment/v1','source_sha256':{r:hashlib.sha256(p.read_bytes()).hexdigest() for r,p in zip(('phone_input','garmin_output'),paths)},'window_pairs':[{'phone_input_index':1,'garmin_output_index':1,'source_content_verified':True,'resampling_mapping_verified':True,'complete_source_sample_spans':True,'relation':'same_source_sample_span'}]}
        self.assertEqual(self.result({'diagnostic_alignment':alignment})['descriptive_ratios']['pairs'][0]['status'],'held_incomplete_windows')

    def test_mismatched_format_and_packed_bits_refused(self):
        self.phone[0]['format']='f32le'
        with self.assertRaisesRegex(module.DataError,'meter_format'):self.result()
        self.phone[0]['format']='s16le';self.volume[0]['volume']['raw_q']=0
        with self.assertRaisesRegex(module.DataError,'packed_volume_decode_mismatch'):self.result()

    def test_nonfinite_and_duplicate_JSON_refused(self):
        paths=self.paths();paths[0].write_text('{"x":NaN}\n')
        with self.assertRaisesRegex(module.DataError,'nonfinite_JSON'):module.read_input(paths[0],'phone_input')
        paths[0].write_text('{"x":1,"x":2}\n')
        with self.assertRaisesRegex(module.DataError,'duplicate_JSON_key'):module.read_input(paths[0],'phone_input')

    def test_regular_nosymlink_and_cap_preopen_guards(self):
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            folder=Path(temporary);large=folder/'oversize.jsonl'
            with large.open('wb') as f:f.truncate(module.MAX_BYTES+1)
            with self.assertRaisesRegex(module.DataError,'input_byte_cap'):module.read_input(large,'phone_input')
            link=folder/'link';link.symlink_to(large)
            with self.assertRaisesRegex(module.DataError,'not_regular_or_symlink'):module.read_input(link,'phone_input')
            fifo=folder/'fifo';os.mkfifo(fifo)
            with self.assertRaisesRegex(module.DataError,'not_regular_or_symlink'):module.read_input(fifo,'phone_input')

    def test_metadata_optional_failure_privacy(self):
        private='AA:BB:CC:DD:EE:FF private-device-path'
        self.output[-1]['stop_reason']='OSError:'+private
        self.volume[0]['codec']=private
        pipeline={'supervision':{'children':[{'role':'player','critical':True,'returncode':0},{'role':'volume_observer','critical':False,'returncode':2}],'optional_start_failures':[{'role':'volume_observer','error_kind':'FileNotFoundError','error':private}],'optional_observer_failures':['volume_observer'],'cleanup_errors':[private],'error':private,'returncode':0}}
        result=self.result(pipeline);encoded=json.dumps(result)
        self.assertNotIn(private,encoded);self.assertNotIn('AA:BB',encoded)
        self.assertEqual(result['pipeline_summary']['critical_nonzero_roles'],[])
        self.assertEqual(result['pipeline_summary']['optional_nonzero_roles'],['volume_observer'])
        self.assertEqual(result['pipeline_summary']['cleanup_error_count'],1)

    def test_real_CLI_new_output_no_overwrite(self):
        paths=self.paths();output=self.folder/'analysis.json';output.unlink(missing_ok=True)
        command=[sys.executable,str(SOURCE),'--phone-input',str(paths[0]),'--garmin-output',str(paths[1]),'--volume',str(paths[2]),'--output',str(output)]
        first=subprocess.run(command,capture_output=True,text=True,timeout=10)
        self.assertEqual(first.returncode,0,first.stdout+first.stderr)
        original=output.read_bytes();second=subprocess.run(command,capture_output=True,text=True,timeout=10)
        self.assertEqual(second.returncode,2);self.assertEqual(output.read_bytes(),original)
        self.assertIn('output_already_exists',second.stdout)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TimelineControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    receipt={'schema':'music-offline-timeline-synthetic-controls/v1','tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'success':result.wasSuccessful(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'fixture_scope':'Fabricated scalar/protocol metadata JSONL, not PCM/phone/device captures. Oversize/FIFO/symlink guards used own temporary normal artifacts, removed after test. CLI only our new metadata analyzer.','live_Bluetooth_DBus_PCM_audio_service_guest_operations':0}
    (HERE/'test-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
