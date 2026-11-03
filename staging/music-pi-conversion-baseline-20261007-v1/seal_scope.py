#!/usr/bin/env python3
"""Seal short offline PCM evidence and copies of the changed host sources."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def require(ok,message):
    if not ok:raise ValueError(message)


def put(name,value):
    p=HERE/name
    require(not p.exists(),'Existing output '+name)
    raw=value if isinstance(value,bytes) else (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    p.write_bytes(raw)
    return raw


def main():
    require(not (HERE/'sealed-files.json').exists(),'Already sealed')
    host=json.loads((HERE/'host-proof.json').read_text())
    channel=json.loads((HERE/'channel-guard-proof.json').read_text())
    require(host['all_assigned_checks_passed'] and channel['all_assigned_checks_passed'],'Actual finite controls')
    require(host['methods']==11 and channel['methods']==3,'Exact finite scope')
    bindings=[]
    for name in ('garmin_phone_audio_bridge.py','garmin_music_player.py','garmin_audio_conversion.py'):
        file=ROOT/'scripts'/name;raw=file.read_bytes();s=file.stat()
        put('current-'+name,raw)
        bindings.append({'path':str(file.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),
                         'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
                         'scope_copy':'current-'+name,'live_service_deployed':False})
    notes='''# Fixed Pi conversion: offline baseline

The original phone bridge uses fixed volume0.5; the local player uses fixed volume1.0. Their default volume expression, 8kHz/mono output, and the phone FFmpeg arguments are unchanged. The new shared helper supports opt-in fixed --headroom-db and --mono-mode auto/left/right/average. Auto keeps the original downmix. Right/average require stereo; the local player probes channels only for opt-in selection, and rejects missing channels. Selection discards content from the other channel and is not a general music improvement.

The phone bridge now supports --plan-conversion without D-Bus imports and --offline-only --offline-input FILE --offline-output NEW.wav --input-rate 44100 --input-channels 2 --max-seconds 1. Raw input is S16_LE; offline output uses the same fixed conversion in a WAV, never opens BlueZ/PCM, never replaces an existing output, and cleans its owned temporary file. The player also supports --plan-conversion with no source argument and no Bluetooth query; its existing --prepare-only remains available. Live defaults and existing CLI flags remain compatible. The live route was not executed or deployed in this scope.

The 3-second 440/880/1500Hz low/high/low fixture retained an approximately0.5 multiplier in each segment (0.499974/0.499999/0.499974). A fixed3dB attenuation measured0.707928..0.707949 and reduced peak5690 to4028. These fixtures show no conversion-created gain pumping. They do not characterize real music, encoded source loudness metadata, the Bluetooth codec, Garmin voice DSP, mixer policy, or physical speaker sound. Near-zero cancellation can instead be produced by source stereo phase: inverse L/R gives RMS0 with auto/average; selected left/right restores the tested channel RMS4242.82 while sacrificing the other channel. A left-only input becomes half the identical-in-phase stereo level in this measured FFmpeg default downmix.

With volume0.5 and a12000-peak sine, steady RMS is about4242.82 at1kHz,4183.84 at3.4kHz,1977.34 at3.9kHz,4.17 at4.5kHz, and0 at6kHz. Output8kHz imposes a4kHz Nyquist limit and the normal resampler transition already narrows useful bandwidth. No resampler cutoff/filter-size change was made, no mSBC negotiation was requested, and no dynamic gain/noise gate/normalizer was introduced.

One FFmpeg process fed with irregular frame-aligned chunks produced exactly the same24000 samples as whole-buffer input, for auto and left+3dB. Resampling was not restarted at each chunk. An actual offline1-second conversion produced an8000-frame/mono/S16/8kHz WAV; reusing the same output was refused. Additional true ffprobe controls verified mono rejection and stereo acceptance for opt-in selection. These are normal Linux host programs, not native/guest/firmware or an attempt to replay a system-blocked admission branch.

FFmpeg primary references read for the new parameters: https://ffmpeg.org/ffmpeg-filters.html#pan (explicit channel gains and remapping), https://ffmpeg.org/ffmpeg-filters.html#volume (fixed multiplier/default once evaluation), https://ffmpeg.org/ffmpeg-resampler.html (default swr cutoff/filter description). This scope retains no downloaded giant documentation or PCM fixtures. Initial5-tone observation b69dc4 is preliminary; formal11 methods c811e6/session28395→917c21 passed, then3 new channel-guard controls7b0b05 passed. The earlier eleven methods were not replayed after adding plan_for_track; that addition and the new opt-in player call are covered by the three new controls. Existing conversion_plan/raw_ffmpeg_command/offline_raw_to_wav functions were unchanged by that addition.

Navigation work remains canceled and sealed. No D-Bus/BlueZ/device/PCM/service or playback operation occurred. No claim is made that phone-direct Garmin A2DP, a native music App, the Garmin voice DSP, or live music quality has been completed. Stop after this local source and evidence closure.
'''
    put('HANDOFF.md',notes.encode())
    put('primary-docs.json',{'schema':'music-pi-conversion-primary-docs/v1','sources':[
        {'url':'https://ffmpeg.org/ffmpeg-filters.html#pan','facts_used':'pan uses explicit channel coefficients; zero/one mapping selects channels; default -ac remains preferred absent specific needs'},
        {'url':'https://ffmpeg.org/ffmpeg-filters.html#volume','facts_used':'fixed volume multiplier; default evaluation once; no runtime commands used'},
        {'url':'https://ffmpeg.org/ffmpeg-resampler.html','facts_used':'native swr default cutoff ratio0.97 and filter size32; not changed by this scope'}],
        'actual_web_tool_references':['turn190view0','turn190view1','turn190view2','turn191view0','turn191view1','turn191view2','turn191view3'],
        'copied_verbatim_words':0})
    put('actual-tool-receipts.json',{'schema':'music-pi-conversion-actual-tools/v1','tools':[
        {'chunk_id':'d27f90','exit_code':0,'purpose':'read original phone bridge'},
        {'chunk_id':'148be6','exit_code':0,'purpose':'read original music player'},
        {'chunk_id':'d508e7','exit_code':0,'purpose':'FFmpeg version'},
        {'chunk_id':'b69dc4','exit_code':0,'purpose':'preliminary5 one-second tones'},
        {'chunk_id':'9ba18a','exit_code':0,'purpose':'preserve original source snapshots'},
        {'chunk_id':'4fe305','exit_code':0,'purpose':'phone plan-only metadata'},
        {'chunk_id':'3b34fe','exit_code':0,'purpose':'player plan-only metadata'},
        {'initial_chunk_id':'c811e6','session_id':28395,'terminal_chunk_id':'917c21','exit_code':0,
         'purpose':'11 actual short FFmpeg/conversion methods','terminal':'Ran11 tests in4.207s; OK'},
        {'chunk_id':'7b0b05','exit_code':0,'purpose':'3 additional actual ffprobe channel-guard methods','terminal':'Ran3 tests in0.673s; OK'}],
        'automatic_DBus_PCM_services_device_playback':False,
        'test_refusals_expected_not_unreported_failures':['existing offline output CLI returns2','mono right/average raises ValueError','finite gain rejects invalid values']})
    proof={'schema':'music-pi-conversion-baseline-source-proof/v1','all_assigned_checks_passed':True,
           'host_proof_sha256':SHA((HERE/'host-proof.json').read_bytes()),
           'channel_guard_proof_sha256':SHA((HERE/'channel-guard-proof.json').read_bytes()),
           'source_bindings':bindings,'actual_FFmpeg_methods':11,'actual_new_channel_guard_methods':3,
           'new_fixed_options_live_default_enabled':False,'default_live_conversion_argv_unchanged':True,
           'original_sources_preserved':True,'new_opt_in_function_added_after_main11_controls':True,
           'old11methods_replayed_after_channel_guard_addition':False,
           'max_fixture_seconds':3,'persistent_PCM_or_WAV_fixture_bytes':0,
           'actual_measured_test_pipe_PCM_output_bytes':sum(r['output_bytes'] for r in host['commands']),
           'actual_measured_test_pipe_PCM_input_bytes':sum(r['input_bytes'] for r in host['commands']),
           'preliminary_pipe_PCM_output_bytes':80000,'player_comparison_pipe_PCM_output_bytes':16000,
           'temporary_offline_generated_WAV_bytes':16078,'temporary_source_fixture_files_all_removed':True,
           'temporary_source_fixture_bytes':176400+16044+32044,
           'BlueZ_DBus_PCM_device_playback_service_IO':False,'native_guest_firmware_audio_admission':False,
           'Garmin_DSP_physical_quality_or_direct_phone_A2DP_verified':False,
           'navigation_work_resumed':False,'all_handles_closed':True,'STOP':True}
    put('proof.json',proof)
    cache={str(f.relative_to(HERE)):f.read_bytes() for f in sorted(HERE.rglob('*')) if f.is_file()}
    require(sum(map(len,cache.values()))<1048576,'Persistent output budget')
    for name in cache:(HERE/name).chmod(0o444)
    rows=[]
    for name,raw in cache.items():
        f=HERE/name;s=f.stat();rows.append({'path':str(f.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),
              'mode':'0444','stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]})
    seal={'schema':'music-pi-conversion-baseline-seal/v1','all_assigned_checks_passed':True,'files':rows,
          'source_bindings':bindings,'persistent_output_bytes_before_seal':sum(map(len,cache.values())),
          'device_or_playback_IO':False,'all_handles_closed':True,'STOP':True}
    raw=put('sealed-files.json',seal);(HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed':True,'proof_sha256':SHA((HERE/'proof.json').read_bytes()),
         'proof_bytes':(HERE/'proof.json').stat().st_size,'seal_sha256':SHA(raw),'seal_bytes':len(raw),
         'persistent_output_bytes':sum(map(len,cache.values()))+len(raw),'source_bindings':bindings,'STOP':True}))


if __name__=='__main__':main()
