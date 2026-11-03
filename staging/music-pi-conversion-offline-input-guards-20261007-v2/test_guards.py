#!/usr/bin/env python3
"""Small normal host guard correction; prior PCM tests remain unchanged."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import garmin_audio_conversion as conversion
ROWS=[]


class Tests(unittest.TestCase):
    def test01_true_FIFO_refused_before_open(self):
        with tempfile.TemporaryDirectory(prefix='garmin-fifo-guard-') as name:
            directory=Path(name);fifo=directory/'source.fifo';os.mkfifo(fifo)
            with patch.object(conversion.os,'open',side_effect=RuntimeError('Must not open FIFO')) as opener:
                with self.assertRaisesRegex(ValueError,'特殊檔案'):
                    conversion.offline_raw_to_wav(fifo,directory/'out.wav',conversion.conversion_plan(input_rate=8000,input_channels=1),1)
                self.assertEqual(opener.call_count,0)
            self.assertEqual(list(directory.iterdir()),[fifo])
            ROWS.append({'check':'actual_local_FIFO_lstat_reject_before_open','open_calls':0,'source_content_bytes':0,'output_created':False})

    def test02_true_symlink_refused_before_open(self):
        with tempfile.TemporaryDirectory(prefix='garmin-symlink-guard-') as name:
            directory=Path(name);source=directory/'source.s16le';source.write_bytes(b'\0\0');link=directory/'link.s16le';link.symlink_to(source.name)
            with patch.object(conversion.os,'open',side_effect=RuntimeError('Must not open symlink')) as opener:
                with self.assertRaisesRegex(ValueError,'symlink'):
                    conversion.offline_raw_to_wav(link,directory/'out.wav',conversion.conversion_plan(input_rate=8000,input_channels=1),1)
                self.assertEqual(opener.call_count,0)
            ROWS.append({'check':'actual_local_symlink_lstat_reject_before_open','open_calls':0,'fixture_bytes':2,'output_created':False})

    def test03_actual_regular_open_flags_and_identity(self):
        with tempfile.TemporaryDirectory(prefix='garmin-regular-guard-') as name:
            directory=Path(name);source=directory/'source.s16le';source.write_bytes(b'\0\0'*80);out=directory/'out.wav'
            opener=conversion.os.open;calls=[]
            def checked(path,flags,*args,**kwargs):
                if Path(path)==source:
                    calls.append(flags)
                    for required in (os.O_NOFOLLOW,os.O_NONBLOCK,os.O_NOCTTY):self.assertEqual(flags&required,required)
                return opener(path,flags,*args,**kwargs)
            with patch.object(conversion.os,'open',checked):
                receipt=conversion.offline_raw_to_wav(source,out,conversion.conversion_plan(input_rate=8000,input_channels=1),.01)
            self.assertEqual(len(calls),1);self.assertGreater(receipt['bytes'],0)
            self.assertFalse(any(directory.glob('.garmin-convert-*')))
            ROWS.append({'check':'actual_10ms_FFmpeg_regular_file_with_flags','source_open_flags':calls[0],
                         'input_bytes':160,'output_bytes':receipt['bytes'],'output_sha256':receipt['sha256'],'temporary_files_removed':True})

    def test04_CLI_modes_mutually_exclusive_no_dbus(self):
        cases=[('garmin_phone_audio_bridge.py',['--plan-conversion','--offline-only']),
               ('garmin_phone_audio_bridge.py',['--plan-conversion','--check-only']),
               ('garmin_phone_audio_bridge.py',['--offline-only','--check-only']),
               ('garmin_music_player.py',['--plan-conversion','--prepare-only'])]
        for script,flags in cases:
            result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts'/script),*flags],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,2);self.assertIn('not allowed with argument',result.stderr)
        ROWS.append({'check':'four_actual_argparse_conflict_refusals','expected_exit_code':2,'no_device_or_dbus_branch':True})

    def test05_preserved_PCM_math_and_live_defaults_AST(self):
        def functions(path):return {x.name:ast.dump(x,include_attributes=False) for x in ast.parse(path.read_text()).body if isinstance(x,ast.FunctionDef)}
        old=functions(ROOT/'staging/music-pi-conversion-baseline-20261007-v1/current-garmin_audio_conversion.py')
        new=functions(ROOT/'scripts/garmin_audio_conversion.py')
        for name in ('conversion_plan','raw_ffmpeg_command','plan_for_track'):self.assertEqual(old[name],new[name])
        self.assertEqual(conversion.raw_ffmpeg_command(conversion.conversion_plan(.5,input_rate=44100,input_channels=2))[19],'volume=0.5')
        ROWS.append({'check':'three_unchanged_PCM_plan_functions_AST','functions':['conversion_plan','raw_ffmpeg_command','plan_for_track'],
                     'old11_and3_suites_replayed':False,'host_input_guard_changed':True})


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (HERE/'host-guard-proof.json').write_text(json.dumps({'schema':'music-pi-offline-input-guard-controls/v2',
        'all_assigned_checks_passed':result.wasSuccessful(),'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'failure_details':[str(x) for x in result.failures+result.errors],'checks':ROWS,
        'baseline_PCM_suite_replayed':False,'real_device_paths_opened':False,'BlueZ_DBus_PCM_services_playback_guest':False},indent=2)+'\n')
    sys.exit(0 if result.wasSuccessful() else 1)
