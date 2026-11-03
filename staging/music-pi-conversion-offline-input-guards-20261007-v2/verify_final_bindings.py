#!/usr/bin/env python3
"""Correct the test-only argv indexing; do not replay successful controls."""
import ast
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import garmin_audio_conversion as conversion


def require(value,message):
    if not value:raise ValueError(message)


def main():
    failed=json.loads((HERE/'host-guard-proof.json').read_text())
    require(failed['methods']==5 and failed['failures']==1 and failed['errors']==0,'Exact retained failure')
    require(len(failed['checks'])==4,'Four earlier successful controls preserved')
    def functions(file):
        return {x.name:ast.dump(x,include_attributes=False) for x in ast.parse(file.read_text()).body if isinstance(x,ast.FunctionDef)}
    old=functions(ROOT/'staging/music-pi-conversion-baseline-20261007-v1/current-garmin_audio_conversion.py')
    new=functions(ROOT/'scripts/garmin_audio_conversion.py')
    identities={name:old[name]==new[name] for name in ('conversion_plan','raw_ffmpeg_command','plan_for_track')}
    require(all(identities.values()),'Conversion math/argv changed')
    command=conversion.raw_ffmpeg_command(conversion.conversion_plan(.5,input_rate=44100,input_channels=2))
    require(command[command.index('-filter:a')+1]=='volume=0.5','Original default fixed volume')
    source=ROOT/'scripts/garmin_audio_conversion.py'
    text=source.read_text()
    require(text.index('source_path_stat = os.lstat(source)')<text.index('source_fd = os.open(source,'),'lstat before open')
    require('os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY' in text,'Open flags')
    rows=[]
    for name in ('garmin_phone_audio_bridge.py','garmin_music_player.py','garmin_audio_conversion.py'):
        file=ROOT/'scripts'/name;raw=file.read_bytes();s=file.stat()
        rows.append({'path':str(file.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                     'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]})
    proof={'schema':'music-pi-offline-guard-static-correction/v2','all_assigned_checks_passed':True,
           'previous_actual_exit1_preserved':True,'previous_failure_reason':'test argv[19] was -filter:a, not its following value',
           'corrected_guard_uses_filter_option_location':True,'same_AST':identities,'source_bindings':rows,
           'successful4_controls_or_old_PCM_suite_replayed':False,'new_FFmpeg_execution':False,
           'BlueZ_DBus_PCM_device_services_playback_guest':False}
    (HERE/'static-correction-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof))


if __name__=='__main__':main()
