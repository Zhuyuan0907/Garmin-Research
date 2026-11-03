#!/usr/bin/env python3
"""Close guard followup, retaining its real failed test and static correction."""
import hashlib
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def put(name,value):
    file=HERE/name
    if file.exists():raise ValueError('Existing '+name)
    raw=value if isinstance(value,bytes) else (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    file.write_bytes(raw);return raw


def main():
    failed=json.loads((HERE/'host-guard-proof.json').read_text());corrected=json.loads((HERE/'static-correction-proof.json').read_text())
    if not corrected['all_assigned_checks_passed'] or len(failed['checks'])!=4:raise ValueError('Missing finite checks')
    for row in corrected['source_bindings']:
        file=ROOT/row['path'];raw=file.read_bytes();s=file.stat()
        if len(raw)!=row['bytes'] or SHA(raw)!=row['sha256'] or [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]!=row['stat']:
            raise ValueError('Final source changed')
        put('current-'+file.name,raw)
    receipts={'schema':'music-pi-conversion-guard-followup-actual-tools/v2','tools':[
        {'chunk_id':'8e1f41','exit_code':1,'purpose':'four true input/CLI guards passed; fifth test used wrong fixed argv index','terminal':'Ran5 tests in0.347s; FAILED(failures=1)'},
        {'chunk_id':'500aaa','exit_code':0,'purpose':'new static correction locates actual filter value; no successful test replay'},
        {'chunk_id':'2c77b8','exit_code':0,'purpose':'prior baseline closure preserved','seal_sha256':'c212e042ae763a65a6245ad86f3f1612aad41081cbf361ff81c1bda87f53337f'}],
        'source_test_failure_is_not_platform_or_native_audio_block':True,'device_or_playback_IO':False}
    put('actual-tool-receipts.json',receipts)
    proof={'schema':'music-pi-conversion-offline-input-guard-followup-proof/v2','all_assigned_checks_passed':True,
        'scope':'guard correction only; prior actual failed suite remains failed and preserved',
        'failed_suite_sha256':SHA((HERE/'host-guard-proof.json').read_bytes()),'failed_suite_actual_exit':1,
        'four_successful_runtime_guards':failed['checks'],'static_correction_sha256':SHA((HERE/'static-correction-proof.json').read_bytes()),
        'corrected_test_only_index_error':True,'same_conversion_functions_AST':corrected['same_AST'],
        'source_bindings':corrected['source_bindings'],'baseline_seal_sha256':'c212e042ae763a65a6245ad86f3f1612aad41081cbf361ff81c1bda87f53337f',
        'production_changes':['offline pre-open lstat regular/non-symlink guard','O_NOFOLLOW|O_NONBLOCK|O_NOCTTY and exact fd identity','plan/offline/check or plan/prepare mutually exclusive modes'],
        'baseline11_and_channel3_methods_replayed':False,'new_FFmpeg_fixture_seconds':.01,
        'persistent_PCM_WAV_fixtures_bytes':0,'real_device_paths_opened':False,'BlueZ_DBus_PCM_services_playback_guest':False,
        'live_default_or_Garmin_DSP_changed':False,'physical_music_quality_verified':False,'all_handles_closed':True,'STOP':True}
    put('proof.json',proof)
    put('HANDOFF.md',b'''# Offline input guard followup

Final host sources are pinned in proof.json/current-*.py. The offline helper now lstat-rejects nonregular files and symlinks before open; opens a verified regular file with O_NOFOLLOW|O_NONBLOCK|O_NOCTTY; compares pre-open identity to fstat and checks stability after conversion. A true local FIFO and a symlink were rejected with os.open spy count0. No /dev path was opened. A10ms regular PCM file converted through real FFmpeg with the required flags and owned temporary cleanup. Phone plan/offline/check and player plan/prepare modes now have argparse mutual exclusion; four actual conflicting CLI pairs exited2 before live branches.

Actual8e1f41 exited1: the first four runtime controls passed, then a test-only hard-coded argv index expected the volume value at index19, which is the -filter:a option. Failed test source/proof stay unchanged. New500aaa static check finds the value through the option index, passes, and independently records the three preserved conversion-plan/raw-command/probe ASTs against the sealed baseline. No successful guard, old eleven conversion methods, or three channel controls was replayed. This is not a platform or native-audio rejection.

Prior baseline seal c212e042...53337f and proof c4d0c99b...dc9cea remain unchanged. Its actual fixed-gain, phase cancellation,8kHz bandwidth and chunking observations remain limited to short host fixtures. Headroom/channel selection are optional and do not establish a repair of Garmin voice-DSP pumping. Root may next run its newly assigned bounded end-to-end host prepare/offline integration against these exact sources. No Bluetooth/D-Bus/PCM/service/device/native/guest/firmware/audio admission operation occurred. Navigation remains canceled. Stop after source closure.
''')
    cache={str(f.relative_to(HERE)):f.read_bytes() for f in sorted(HERE.rglob('*')) if f.is_file()}
    if sum(map(len,cache.values()))>=1048576:raise ValueError('Output budget')
    for name in cache:(HERE/name).chmod(0o444)
    rows=[]
    for name,raw in cache.items():
        file=HERE/name;s=file.stat();rows.append({'path':str(file.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),'mode':'0444',
            'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]})
    raw=put('sealed-files.json',{'schema':'music-pi-conversion-offline-input-guard-followup-seal/v2','all_assigned_checks_passed':True,
        'files':rows,'source_bindings':corrected['source_bindings'],'old_actual_failure_preserved':True,'device_IO':False,'STOP':True})
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed':True,'proof_sha256':SHA((HERE/'proof.json').read_bytes()),
        'proof_bytes':(HERE/'proof.json').stat().st_size,'seal_sha256':SHA(raw),'seal_bytes':len(raw),
        'output_bytes':sum(map(len,cache.values()))+len(raw),'source_bindings':corrected['source_bindings'],'STOP':True}))


if __name__=='__main__':main()
