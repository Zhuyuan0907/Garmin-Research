#!/usr/bin/env python3
"""Inert fake-provider/trace tests only; no actual D-Bus or audio."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import garmin_audio_volume_observer as observer
ROWS=[]
PRIVATE='AA:BB:CC:DD:EE:FF /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF /private/source'


def props(volume=0x141e,channels=2,**extra):return {'Volume':volume,'Channels':channels,**extra}


class Frames:
    def __init__(self,frames,stop):self.frames=frames;self.stop=stop;self.index=0
    def read_snapshot(self):
        frame=self.frames[self.index];self.index+=1
        if self.index==len(self.frames):self.stop.set()
        if isinstance(frame,Exception):raise frame
        return frame


def collect_frames(frames,max_bytes=1048576,token=None):
    stop=threading.Event()
    with tempfile.TemporaryDirectory(prefix='volume-fake-') as name:
        file=Path(name)/'out.jsonl';writer=observer.BoundedWriter(file,max_bytes)
        summary=observer.collect(Frames(frames,stop),writer,duration_seconds=1,interval_seconds=.01,stop_event=stop,diagnostic_run_id=token)
        raw=file.read_bytes();mode=stat.S_IMODE(file.stat().st_mode)
        rows=[json.loads(line) for line in raw.splitlines()]
    return rows,summary,raw,mode


class Tests(unittest.TestCase):
    def test01_high_low_volume_bits_and_mono(self):
        stereo=observer.decode_properties(props(0xc205,SoftVolume=False,Codec='SBC'))
        self.assertEqual(stereo['volume']['channels'],[{'index':1,'gain_0_127':66,'mute':True},{'index':2,'gain_0_127':5,'mute':False}])
        mono=observer.decode_properties(props(0xc2ff,channels=1))
        self.assertEqual(mono['volume']['channels'],[{'index':1,'gain_0_127':66,'mute':True}])
        ROWS.append({'case':'highbyte_ch1_lowbyte_ch2_mute_gain_mono_absence','passed':True})

    def test02_strict_scalars_and_privacy_codec(self):
        bad=[props(True),props(-1),props(65536),props('200'),props(channels=True),props(channels=3),props(SoftVolume='false'),props(Codec=['SBC'])]
        for value in bad:self.assertEqual(observer.normalize_role({'candidates':[value]}),{'state':'parse_error'})
        safe=observer.decode_properties(props(Codec=PRIVATE,Device=PRIVATE,SoftVolume=True))
        self.assertEqual(safe['codec'],'other');self.assertNotIn(PRIVATE,json.dumps(safe))
        ROWS.append({'case':'invalid_scalar_types_and_unknown_codec_redacted','passed':True,'invalid_cases':len(bad)})

    def test03_explicit_fake_DBus_wrappers_no_string_bool_cast(self):
        class Q(int):pass
        class Y(int):pass
        class B(int):pass
        class S(str):pass
        types={'Volume':Q,'Channels':Y,'SoftVolume':B,'Codec':S}
        safe=observer.sanitize_pcm_properties({'Volume':Q(0x141e),'Channels':Y(2),'SoftVolume':B(0),'Codec':S('mSBC')},types)
        self.assertIs(safe['soft_volume'],False);self.assertEqual(safe['codec'],'mSBC')
        with self.assertRaises(ValueError):observer.sanitize_pcm_properties({'Volume':Q(1),'Channels':Y(1),'SoftVolume':'false'},types)
        ROWS.append({'case':'explicit_fake_signature_wrappers_boolean_false','passed':True,'actual_dbus_import':False})

    def test04_exact_authorized_selector_and_no_first_ambiguous(self):
        exact='/org/bluez/hci0/dev_11_22_33_44_55_66'
        base={**props(),'Device':exact,'Transport':'A2DP-sink','Mode':'source'}
        objects={str(n):{'org.bluealsa.PCM1':{**base,**edit}} for n,edit in enumerate(({}, {'Device':'other'}, {'Transport':'HFP-AG'},{'Mode':'sink'}))}
        self.assertEqual(observer.select_candidates(objects,exact,'A2DP-sink','source'),[base])
        objects['duplicate']={'org.bluealsa.PCM1':dict(base)}
        matches=observer.select_candidates(objects,exact,'A2DP-sink','source')
        self.assertEqual(len(matches),2);self.assertEqual(observer.normalize_role({'candidates':matches}),{'state':'role_ambiguous'})
        ROWS.append({'case':'exact_device_transport_mode_and_ambiguous_hold','passed':True,'actual_service_queries':0})

    def test05_fake_managers_read_only_bounded_RPC(self):
        class Q(int):pass
        class Y(int):pass
        class B(int):pass
        class S(str):pass
        calls=[]
        class Manager:
            def __init__(self,reply=None,fail=False):self.reply=reply;self.fail=fail
            def GetManagedObjects(self,**kwargs):
                calls.append(kwargs)
                if self.fail:raise RuntimeError(PRIVATE)
                return self.reply
        device='fake-exact-device';value={'Volume':Q(0x141e),'Channels':Y(2),'SoftVolume':B(0),'Codec':S('SBC'),
                                          'Device':device,'Transport':'A2DP-sink','Mode':'source'}
        fake=observer.LiveProvider.__new__(observer.LiveProvider)
        fake.dbus=SimpleNamespace(UInt16=Q,Byte=Y,Boolean=B,String=S);fake.devices={'phone':device,'garmin':device};fake.rpc_timeout=.1
        fake.managers={'phone':Manager({'fake-object':{'org.bluealsa.PCM1':value}}),'garmin':Manager(fail=True)}
        result=fake.read_snapshot()
        self.assertEqual(observer.normalize_role(result['phone'])['state'],'ok')
        self.assertEqual(result['garmin'],{'status':'rpc_unavailable'});self.assertEqual(calls,[{'timeout':.1},{'timeout':.1}])
        self.assertNotIn(PRIVATE,json.dumps(result))
        ROWS.append({'case':'fake_GetManagedObjects_only_explicit_timeout','passed':True,'actual_config_or_bus_construction':False})

    def test06_reconnect_changes_missing_ambiguous_errors(self):
        good={'candidates':[props(SoftVolume=True,Codec='SBC')]}
        frames=[{'phone':good,'garmin':good},
                {'phone':{'candidates':[]},'garmin':good},
                {'phone':{'candidates':[props(0x151f,SoftVolume=False,Codec='SBC')]},'garmin':good},
                {'phone':{'candidates':[props(),props()]},'garmin':good},
                {'phone':{'candidates':[props(Volume=PRIVATE)]},'garmin':good},
                RuntimeError(PRIVATE),{'phone':good,'garmin':good}]
        rows,summary,raw,mode=collect_frames(frames,token='fixture_run_1')
        events=[row['event'] for row in rows if row['role']=='phone']
        self.assertEqual(events,['initial','role_missing','snapshot_change','role_ambiguous','parse_error','rpc_unavailable','snapshot_change'])
        self.assertNotIn(PRIVATE,raw.decode());self.assertEqual(mode,0o600)
        self.assertTrue(all(row['clock_kind']=='host_monotonic_ns' and row['diagnostic_run_id']=='fixture_run_1' for row in rows))
        self.assertTrue(all(type(row['monotonic_ns']) is int and row['timestamp_utc'].endswith('+00:00') for row in rows))
        self.assertEqual(summary['polls'],7)
        ROWS.append({'case':'reconnect_and_property_timeline_fake_provider','events':events,'output_bytes':len(raw),'mode':'0600','private_text_absent':True})

    def test07_cap_reserves_parseable_tail_summary(self):
        frame={role:{'candidates':[props(SoftVolume=True,Codec='SBC')]} for role in observer.ROLES}
        rows,summary,raw,mode=collect_frames([frame]*20,max_bytes=2048)
        self.assertLessEqual(len(raw),2048);self.assertEqual(rows[-1]['event'],'final_summary')
        self.assertTrue(summary['output_cap_reached']);self.assertGreater(summary['events_dropped'],0)
        ROWS.append({'case':'2048byte_cap_tail_summary_and_nonfatal_continuation','bytes':len(raw),'dropped':summary['events_dropped'],'polls':summary['polls']})

    def CLI(self,trace,out,*extra,guarded=False):
        args=[str(ROOT/'scripts/garmin_audio_volume_observer.py'),'--trace-input',str(trace),'--output',str(out),'--duration','.05','--interval','.01',*extra]
        if not guarded:return [sys.executable,'-B',*args]
        guard="""import builtins,io,runpy,socket,sys
orig_import=builtins.__import__;orig_open=builtins.open;orig_io=io.open
def checked_import(name,*a,**k):
 if name=='dbus' or name.startswith('dbus.'):raise RuntimeError('Forbidden D-Bus import')
 return orig_import(name,*a,**k)
def checked_open(file,*a,**k):
 if '/evidence/' in str(file):raise RuntimeError('Forbidden private configuration read')
 return orig_open(file,*a,**k)
def checked_io(file,*a,**k):
 if '/evidence/' in str(file):raise RuntimeError('Forbidden private configuration read')
 return orig_io(file,*a,**k)
builtins.__import__=checked_import;builtins.open=checked_open;io.open=checked_io
socket.socket=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Forbidden socket'))
path=sys.argv[1];sys.argv=sys.argv[1:];runpy.run_path(path,run_name='__main__')
"""
        return [sys.executable,'-B','-c',guard,*args]

    def test08_actual_trace_CLI_no_dbus_config_socket_stdout(self):
        with tempfile.TemporaryDirectory(prefix='observer-cli-') as name:
            directory=Path(name);trace=directory/'trace.json';out=directory/'out.jsonl'
            trace.write_text(json.dumps({'frames':[{'phone':{'candidates':[props(Codec=PRIVATE,Device=PRIVATE)]},'garmin':{'candidates':[]}}]}))
            result=subprocess.run(self.CLI(trace,out,'--diagnostic-run-id','offline_1',guarded=True),capture_output=True,text=True,timeout=2)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'');self.assertEqual(result.stderr,'')
            raw=out.read_text();self.assertNotIn(PRIVATE,raw);self.assertNotIn('/org/bluez',raw);self.assertNotIn('/private',raw)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o600)
            parsed=[json.loads(line) for line in raw.splitlines()];self.assertEqual(parsed[-1]['event'],'final_summary')
            ROWS.append({'case':'real_inert_trace_CLI_import_config_socket_barriers','exit_code':0,'bytes':out.stat().st_size,'stdout_stderr_bytes':0})

    def test09_actual_SIGTERM_summary_and_zero_exit(self):
        with tempfile.TemporaryDirectory(prefix='observer-sigterm-') as name:
            directory=Path(name);trace=directory/'trace.json';out=directory/'out.jsonl'
            trace.write_text(json.dumps({'frames':[{'phone':{'candidates':[props()]},'garmin':{'candidates':[props(channels=1)]}}]}))
            cmd=self.CLI(trace,out,'--duration','1.5','--diagnostic-run-id','signal_fixture')
            child=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+1
                while time.monotonic()<deadline:
                    if out.exists() and out.stat().st_size>0:break
                    time.sleep(.005)
                self.assertTrue(out.exists());child.send_signal(signal.SIGTERM)
                stdout,stderr=child.communicate(timeout=1)
                self.assertEqual(child.returncode,0,stderr);self.assertEqual(stdout,b'');self.assertEqual(stderr,b'')
                last=json.loads(out.read_bytes().splitlines()[-1]);self.assertEqual(last['stop_reason'],'sigterm')
                with self.assertRaises(ProcessLookupError):os.kill(child.pid,0)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=1)
            ROWS.append({'case':'real_inert_observer_SIGTERM','exit_code':0,'final_stop_reason':'sigterm','PID_reaped':True})

    def test10_unavailable_trace_and_error_nonfatal_redacted(self):
        with tempfile.TemporaryDirectory(prefix='observer-unavailable-') as name:
            directory=Path(name);out=directory/'out.jsonl';trace=directory/'missing-AA_BB_CC_DD_EE_FF.json'
            result=subprocess.run(self.CLI(trace,out,guarded=True),capture_output=True,text=True,timeout=2)
            self.assertEqual(result.returncode,0);self.assertEqual(result.stdout+result.stderr,'')
            parsed=[json.loads(line) for line in out.read_bytes().splitlines()]
            self.assertEqual(parsed[0]['state'],'rpc_unavailable');self.assertEqual(parsed[-1]['event'],'final_summary')
            self.assertNotIn(str(trace),out.read_text())
            ROWS.append({'case':'missing_offline_backend_is_nonfatal_fixed_status','exit_code':0,'private_path_absent':True})

    def test11_existing_and_symlink_output_no_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='observer-output-') as name:
            directory=Path(name);trace=directory/'trace.json';trace.write_text('{"frames":[{}]}')
            real=directory/'existing.jsonl';real.write_bytes(b'keep');link=directory/'link.jsonl';link.symlink_to(real.name)
            for out in (real,link):
                result=subprocess.run(self.CLI(trace,out),capture_output=True,text=True,timeout=2)
                self.assertEqual(result.returncode,2);self.assertEqual(result.stdout+result.stderr,'');self.assertEqual(real.read_bytes(),b'keep')
            ROWS.append({'case':'new_output_only_existing_and_symlink_refusals','expected_exit_code':2,'existing_bytes_preserved':True})

    def test12_no_unbound_clock_token_invention(self):
        frame={role:{'candidates':[props()]} for role in observer.ROLES}
        rows,summary,raw,mode=collect_frames([frame])
        self.assertTrue(all('diagnostic_run_id' not in row for row in rows))
        with tempfile.TemporaryDirectory(prefix='observer-token-') as name:
            file=Path(name)/'out.jsonl';writer=observer.BoundedWriter(file)
            try:
                with self.assertRaises(ValueError):observer.collect(observer.UnavailableProvider(),writer,duration_seconds=.01,diagnostic_run_id=PRIVATE)
            finally:writer.file.close()
        ROWS.append({'case':'anonymous_ASCII_run_token_optional_no_boot_or_deviceID','no_token_means_unbound_epoch':True,'invalid_token_refused':True})


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    source=(ROOT/'scripts/garmin_audio_volume_observer.py').read_bytes()
    proof={'schema':'music-readonly-volume-observer-inert-controls/v1','all_assigned_checks_passed':result.wasSuccessful(),
        'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'failure_details':[str(item) for item in result.failures+result.errors],'cases':ROWS,
        'source_bytes':len(source),'source_sha256':hashlib.sha256(source).hexdigest(),
        'actual_dbus_BlueZ_PCM_device_service_config_queries':False,'live_provider_constructed':False,
        'fake_live_provider_read_method_tested':True,'native_guest_firmware_map_or_sound':False}
    (HERE/'host-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    sys.exit(0 if result.wasSuccessful() else 1)
