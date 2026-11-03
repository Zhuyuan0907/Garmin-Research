#!/usr/bin/env python3
"""Short, actual Linux FFmpeg tests. No Bluetooth/device/native APIs."""
import array
import ast
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import wave

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import garmin_audio_conversion as conversion

ROWS = []
COMMANDS = []
FAILURES = []
SHA = lambda b: hashlib.sha256(b).hexdigest()


def pcm(rate=44100, seconds=1, frequency=1000, phase='same', music=False):
    samples = array.array('h')
    for i in range(int(rate * seconds)):
        t = i / rate
        if music:
            level = (0.2, 0.8, 0.2)[min(2, int(t))]
            x = round(level * (9000 * math.sin(2*math.pi*440*t) + 4000 * math.sin(2*math.pi*880*t) + 3000 * math.sin(2*math.pi*1500*t)))
        else:
            x = round(12000 * math.sin(2 * math.pi * frequency * t))
        samples.extend((0 if phase == 'right-only' else x,
                        -x if phase == 'inverse' else 0 if phase == 'left-only' else x))
    if sys.byteorder != 'little':
        samples.byteswap()
    return samples.tobytes()


def values(raw):
    out = array.array('h'); out.frombytes(raw)
    if sys.byteorder != 'little': out.byteswap()
    return out


def rms(samples):
    return math.sqrt(sum(x*x for x in samples) / len(samples))


def steady(raw):
    return values(raw)[400:-400]


def run_conversion(raw, plan, chunks=False):
    command = conversion.raw_ffmpeg_command(plan)
    if chunks:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        errors = []
        def feed():
            try:
                offset = 0; sizes = (4, 148, 4096, 16384, 2044); n = 0
                while offset < len(raw):
                    amount = sizes[n % len(sizes)]; process.stdin.write(raw[offset:offset+amount]); process.stdin.flush()
                    offset += amount; n += 1
                process.stdin.close()
            except Exception as exc: errors.append(repr(exc))
        thread = threading.Thread(target=feed); thread.start()
        output = process.stdout.read(); stderr = process.stderr.read(); code = process.wait(timeout=15); thread.join(timeout=5)
        if errors or thread.is_alive(): raise RuntimeError(str(errors))
    else:
        result = subprocess.run(command, input=raw, capture_output=True, timeout=15)
        output, stderr, code = result.stdout, result.stderr, result.returncode
    COMMANDS.append({'command': command, 'input_bytes': len(raw), 'input_sha256': SHA(raw),
                     'output_bytes': len(output), 'output_sha256': SHA(output), 'chunked': chunks,
                     'exit_code': code, 'stderr': stderr.decode(errors='replace')})
    if code: raise RuntimeError(stderr.decode(errors='replace'))
    return output


class Tests(unittest.TestCase):
    def plan(self, rate=44100, volume=0.5, mode='auto', headroom=0):
        return conversion.conversion_plan(volume, headroom, mode, rate, 2)

    def test01_original_phone_command_defaults_exact(self):
        expected = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error', '-probesize', '32', '-analyzeduration', '0', '-blocksize', '4096', '-f', 's16le', '-ar', '44100', '-ac', '2', '-i', 'pipe:0', '-filter:a', 'volume=0.5', '-ar', '8000', '-ac', '1', '-f', 's16le', '-flush_packets', '1', 'pipe:1']
        self.assertEqual(conversion.raw_ffmpeg_command(self.plan()), expected)
        self.assertEqual(conversion.conversion_plan(1.0)['filter'], 'volume=1.0')
        ROWS.append({'check': 'default_fixed_filter_and_phone_argv_unchanged', 'passed': True})

    def test02_music_volume_curve(self):
        raw = pcm(seconds=3, music=True)
        full = run_conversion(raw, self.plan(volume=1.0)); half = run_conversion(raw, self.plan())
        vfull, vhalf = values(full), values(half)
        a = [rms(vfull[int((n+.2)*8000):int((n+.8)*8000)]) for n in range(3)]
        b = [rms(vhalf[int((n+.2)*8000):int((n+.8)*8000)]) for n in range(3)]
        gains = [y/x for x, y in zip(a, b)]
        for gain in gains: self.assertAlmostEqual(gain, 0.5, delta=0.0002)
        self.assertAlmostEqual(b[1]/b[0], 4, delta=0.002)
        self.assertAlmostEqual(b[2]/b[0], 1, delta=0.002)
        ROWS.append({'check': 'low_high_low_music_envelope_preserved', 'full_rms': a, 'half_rms': b,
                     'per_segment_gain': gains, 'pumping_detected_in_this_fixture': False})

    def test03_frequency_transfer(self):
        measurements=[]
        for hz in (100, 440, 1000, 3000, 3400, 3900, 4500, 6000):
            out=run_conversion(pcm(frequency=hz),self.plan())
            val=steady(out); energy=rms(val)
            measurements.append({'hz':hz,'output_rms':energy,'relative_to_ideal_gain':energy/(12000/math.sqrt(2)*.5),'peak':max(map(abs,val))})
        self.assertAlmostEqual(measurements[2]['relative_to_ideal_gain'],1,delta=.001)
        self.assertLess(measurements[-1]['relative_to_ideal_gain'],.001)
        ROWS.append({'check':'8k_frequency_transfer','input_rate':44100,'measurements':measurements,'Garmin_DSP_observed':False})

    def test04_stereo_phase_and_explicit_selection(self):
        inverse=pcm(phase='inverse')
        results={}
        for mode in conversion.MONO_MODES:
            out=run_conversion(inverse,self.plan(mode=mode));results[mode]=rms(steady(out))
        self.assertEqual(results['auto'],0);self.assertEqual(results['average'],0)
        self.assertGreater(results['left'],4000);self.assertAlmostEqual(results['left'],results['right'],delta=.1)
        same=rms(steady(run_conversion(pcm(),self.plan())))
        only=rms(steady(run_conversion(pcm(phase='left-only'),self.plan())))
        right=rms(steady(run_conversion(pcm(phase='left-only'),self.plan(mode='right'))))
        self.assertAlmostEqual(only/same,.5,delta=.001);self.assertEqual(right,0)
        ROWS.append({'check':'phase_cancellation_and_opt_in_selection','antiphase_rms':results,
                     'one_channel_to_same_phase_ratio':only/same,'selected_right_of_left_only_rms':right,
                     'single_channel_loses_other_channel_content':True})

    def test05_fixed_headroom(self):
        raw=pcm(seconds=3,music=True)
        ordinary=run_conversion(raw,self.plan());reduced=run_conversion(raw,self.plan(headroom=3))
        a,b=values(ordinary),values(reduced)
        ratios=[]
        for n in range(3):
            sl=slice(int((n+.2)*8000),int((n+.8)*8000));ratio=rms(b[sl])/rms(a[sl]);ratios.append(ratio)
            self.assertAlmostEqual(ratio,10**(-3/20),delta=.0003)
        self.assertLess(max(map(abs,b)),max(map(abs,a)))
        ROWS.append({'check':'3dB_headroom_is_fixed_not_AGC','segment_gain_ratios':ratios,'peak_before':max(map(abs,a)),'peak_after':max(map(abs,b))})

    def test06_irregular_chunking_default_and_selection(self):
        raw=pcm(seconds=3,music=True)
        pairs=[]
        for mode in ('auto','left'):
            plan=self.plan(mode=mode,headroom=3 if mode=='left' else 0)
            whole=run_conversion(raw,plan);chunked=run_conversion(raw,plan,chunks=True)
            self.assertEqual(whole,chunked)
            pairs.append({'mode':mode,'same_all_bytes':True,'frames':len(whole)//2,'sha256':SHA(whole)})
        ROWS.append({'check':'one_process_chunking_invariant','pairs':pairs,'resampler_restarted_per_chunk':False})

    def test07_48k_sample_count(self):
        out=run_conversion(pcm(rate=48000),self.plan(rate=48000))
        self.assertEqual(len(out),16000)
        ROWS.append({'check':'48000_to_8000_frame_count','input_frames':48000,'output_frames':8000})

    def test08_finite_gain_and_mono_guards(self):
        for bad in (float('nan'),float('inf'),-1,1.1):
            with self.assertRaises(ValueError):conversion.conversion_plan(bad)
        for bad in (float('nan'),float('inf'),-1,25):
            with self.assertRaises(ValueError):conversion.conversion_plan(headroom_db=bad)
        for mode in ('right','average'):
            with self.assertRaises(ValueError):conversion.conversion_plan(mono_mode=mode,input_rate=8000,input_channels=1)
        ROWS.append({'check':'finite_gain_and_known_mono_guards','passed':True})

    def test09_plan_CLIs_without_dbus_import(self):
        guard="import builtins,runpy,sys; orig=builtins.__import__; blocked=[]\ndef checked(name,*a,**k):\n if name=='dbus' or name.startswith('dbus.'): blocked.append(name); raise RuntimeError('D-Bus forbidden offline')\n return orig(name,*a,**k)\nbuiltins.__import__=checked; sys.path.insert(0,sys.argv[1]); path=sys.argv[2];sys.argv=[path]+sys.argv[3:];runpy.run_path(path,run_name='__main__')"
        for name in ('garmin_phone_audio_bridge.py','garmin_music_player.py'):
            result=subprocess.run([sys.executable,'-B','-c',guard,str(ROOT/'scripts'),str(ROOT/'scripts'/name),'--plan-conversion'],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            plan=json.loads(result.stdout);self.assertFalse(plan['live_transport_negotiated'])
        ROWS.append({'check':'both_plan_CLIs_no_dbus_import','passed':True,'live_operations':0})

    def test10_offline_bridge_actual_ffmpeg_and_no_replace(self):
        with tempfile.TemporaryDirectory(prefix='garmin-offline-conversion-') as name:
            base=Path(name);source=base/'short.s16le';output=base/'short.wav';source.write_bytes(pcm())
            command=[sys.executable,'-B',str(ROOT/'scripts/garmin_phone_audio_bridge.py'),'--offline-only','--offline-input',str(source),'--offline-output',str(output),'--max-seconds','1','--mono-mode','left']
            result=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr);receipt=json.loads(result.stdout)
            with wave.open(str(output),'rb') as wav:
                self.assertEqual((wav.getnchannels(),wav.getsampwidth(),wav.getframerate(),wav.getnframes()),(1,2,8000,8000))
                saved=wav.readframes(8000)
            self.assertEqual(saved,run_conversion(source.read_bytes(),self.plan(mode='left')))
            before=output.read_bytes();refusal=subprocess.run(command,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(refusal.returncode,0);self.assertEqual(output.read_bytes(),before)
            self.assertFalse(any(base.glob('.garmin-convert-*')))
            ROWS.append({'check':'offline_actual_raw_to_wav_no_replace','first_exit':result.returncode,'existing_output_exit':refusal.returncode,
                         'input_bytes':source.stat().st_size,'output_bytes':receipt['bytes'],'output_sha256':receipt['sha256'],'frames':8000,
                         'temporary_files_cleaned':True,'played':False})

    def test11_player_default_filter_order_real_ffmpeg(self):
        raw=pcm();plan=self.plan(volume=1.0)
        phone=run_conversion(raw,plan)
        command=['ffmpeg','-nostdin','-hide_banner','-loglevel','error','-f','s16le','-ar','44100','-ac','2','-i','pipe:0',
                 '-t','1','-vn','-ac','1','-ar','8000','-filter:a',plan['filter'],'-c:a','pcm_s16le','-f','s16le','pipe:1']
        result=subprocess.run(command,input=raw,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(phone,result.stdout)
        ROWS.append({'check':'player_original_filter_order_equal_phone_pcm','same_all_bytes':True,'sha256':SHA(phone)})


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    version=subprocess.run(['ffmpeg','-version'],capture_output=True,text=True,timeout=10).stdout.splitlines()[0]
    proof={'schema':'music-pi-conversion-offline-host-proof/v1','all_assigned_checks_passed':result.wasSuccessful(),
           'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
           'failure_details':[str(x) for x in result.failures+result.errors],'ffmpeg_version':version,
           'measurements':ROWS,'commands':COMMANDS,'max_fixture_seconds':3,
           'stored_PCM_fixture_or_WAV_bytes':0,'temp_files_removed':True,
           'BlueZ_DBus_PCM_service_device_or_playback_IO':False,'native_guest_firmware_audio_admission':False,
           'Garmin_voice_DSP_or_physical_music_quality_verified':False}
    (HERE/'host-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    if not result.wasSuccessful():sys.exit(1)
