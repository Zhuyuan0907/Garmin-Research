#!/usr/bin/env python3
"""Additional finite controls for the newly added file-channel guard."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import wave
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'scripts'))
import garmin_audio_conversion as conversion
ROWS=[]


class Tests(unittest.TestCase):
    def test01_auto_does_not_probe(self):
        plan=conversion.conversion_plan()
        with patch.object(conversion.subprocess,'run',side_effect=RuntimeError('Probe forbidden for unchanged default')):
            self.assertIs(conversion.plan_for_track(plan,'not-opened'),plan)
        ROWS.append({'check':'default_auto_no_new_dependency_or_file_read','passed':True})

    def test02_true_mono_metadata_rejects_missing_channel(self):
        with tempfile.TemporaryDirectory(prefix='garmin-mono-guard-') as name:
            file=Path(name)/'mono.wav'
            with wave.open(str(file),'wb') as wav:
                wav.setparams((1,2,8000,0,'NONE','not compressed'));wav.writeframes(b'\0\0'*8000)
            for mode in ('right','average'):
                with self.assertRaisesRegex(ValueError,'雙聲道'):
                    conversion.plan_for_track(conversion.conversion_plan(mono_mode=mode),file)
            left=conversion.plan_for_track(conversion.conversion_plan(mono_mode='left'),file)
            self.assertEqual(left['input']['channels'],1)
            ROWS.append({'check':'actual_ffprobe_mono_rejects_right_average_accepts_left','fixture_bytes':file.stat().st_size,'fixture_seconds':1,'passed':True})

    def test03_true_stereo_metadata_accepts_selection(self):
        with tempfile.TemporaryDirectory(prefix='garmin-stereo-guard-') as name:
            file=Path(name)/'stereo.wav'
            with wave.open(str(file),'wb') as wav:
                wav.setparams((2,2,8000,0,'NONE','not compressed'));wav.writeframes(b'\0'*32000)
            for mode in ('left','right','average'):
                plan=conversion.plan_for_track(conversion.conversion_plan(mono_mode=mode),file)
                self.assertEqual(plan['input']['channels'],2)
            ROWS.append({'check':'actual_ffprobe_stereo_accepts_opt_in_selection','fixture_bytes':file.stat().st_size,'fixture_seconds':1,'passed':True})


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (HERE/'channel-guard-proof.json').write_text(json.dumps({'schema':'music-pi-conversion-channel-guard-proof/v1',
        'all_assigned_checks_passed':result.wasSuccessful(),'methods':result.testsRun,'failures':len(result.failures),
        'errors':len(result.errors),'failure_details':[str(x) for x in result.failures+result.errors],
        'checks':ROWS,'old11method_suite_replayed':False,'fixture_files_removed':True,
        'BlueZ_DBus_PCM_device_services_or_playback':False},indent=2)+'\n')
    sys.exit(0 if result.wasSuccessful() else 1)
