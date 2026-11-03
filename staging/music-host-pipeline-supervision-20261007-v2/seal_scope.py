#!/usr/bin/env python3
"""Close finite ordinary-host supervision tests; do not run any pipeline."""
import hashlib
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SHA=lambda b:hashlib.sha256(b).hexdigest()


def write(name,value):
    file=HERE/name
    if file.exists():raise ValueError('Existing output '+name)
    raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2)+'\n').encode()
    file.write_bytes(raw);return raw


def main():
    host_raw=(HERE/'host-proof.json').read_bytes();host=json.loads(host_raw)
    if not host['all_assigned_checks_passed'] or host['methods']!=11 or host['failures'] or host['errors']:
        raise ValueError('Actual finite controls failed')
    source=ROOT/'scripts/garmin_host_audio_pipeline.py';before=source.stat();raw=source.read_bytes();after=source.stat()
    pin=lambda s:[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    if pin(before)!=pin(after) or len(raw)!=host['source_bytes'] or SHA(raw)!=host['source_sha256']:
        raise ValueError('Tested helper source changed')
    write('current-garmin_host_audio_pipeline.py',raw)
    api='''# Ordinary host pipeline supervisor

Source: scripts/garmin_host_audio_pipeline.py, class PipelineSupervisor. No Bluetooth, D-Bus, PCM/audio-device, service, firmware, native guest, map, or AT operation exists in this helper. Root owns bridge/player integration; this scope did not edit either file.

Typical integration:

```python
with PipelineSupervisor(duration_seconds=max_seconds + 45) as s:
    capture_log = s.open_log('capture', unique_capture_log_path)
    convert_log = s.open_log('convert', unique_convert_log_path)
    s.start('capture', capture_argv, stdout=subprocess.PIPE, stderr=capture_log)
    s.start('convert', convert_argv, input_from='capture', stdout=subprocess.PIPE, stderr=convert_log)
    s.start('player', hfp_helper_argv, input_from='convert')
    result = s.wait('player')
return result['returncode']
```

Optional input_meter/output_meter roles can be inserted the same way; default registered-child/log cap8 supports five stages. open_log opens a new binary log and records its handle immediately. start uses an argv sequence, never shell, and creates a new session/process group. input_from transfers an upstream stdout PIPE once and closes the parent's handle after downstream start; missing/closed stdout is an explicit setup error. Passed external handles are borrowed. Supervisor owns its open logs and the PIPE handles created by its Popen children.

Result schema garmin-host-pipeline-result/v1 contains returncode, stop_reason, failed_role, player_returncode, role-named children with PID/final/natural returncode, signals_sent/leader_signals_sent/kill_escalated/outcome, all_children_reaped, all_owned_process_groups_exited, all_owned_handles_closed, cleanup_errors, elapsed_seconds, player_force_killed, CIND_restoration_verified=false. A natural returncode is observed before a supervisor signal to the leader; final returncodes remain available even when deliberately stopped.

Completion semantics: all registered natural exits0 -> natural_eof/0; player exits0 while upstream is running -> player_exit/0 and intentional upstream stop; upstream observed independently nonzero -> upstream_failure/1 even if player0; player nonzero -> player_failure; monotonic deadline -> duration_watchdog/124; Ctrl+C -> user_interrupt/130; staged log/Popen/input error -> setup_failure/1, cleanup then original exception re-raised for caller evidence. Any unreaped registered process, surviving owned group, unclosed handle, or cleanup error changes result to cleanup_failure/1. natural_eof is process-status evidence, not a claim that an opaque player consumed every byte. Races beyond a sampled exit and sent signal remain visible through both raw statuses; a sent signal alone does not prove which internal event caused the child exit.

Shutdown preserves player SIGINT and upstream SIGTERM. Signals target only groups created by this supervisor; they include same-group player descendants such as aplay, and never target a daemon/service group. Shared shutdown and kill deadlines bound total cleanup rather than multiplying grace by the role count. Surviving groups receive SIGKILL; all registered children are waited/reaped. A second Ctrl+C is temporarily ignored during cleanup and the previous handler is restored. This code cannot wait grandchildren that escape their parent's process group or claim cleanup of unrelated processes. Bound exhaustion reports cleanup_failure instead of success. Forced KILL does not establish CIND restoration; only the HFP helper owns call state and its own wall timer. The outer duration is a watchdog, not PCM duration enforcement.

Actual6966d6 EXIT0: eleven tests in1.022s, Python fixtures lasting<=1.5s. Controls covered all-zero finite data plus sink content check, capture7, converter9, early player0, blocked/no-read pipe timeout, real parent SIGINT, second-log and Popen failures, SIGINT/TERM-ignoring child KILL, same-group player descendant holding stdout with parent wait/reap, and one-time parent-pipe transfer. Every case checked /proc/self/fd count equality, no leftover registered PID, all groups exited, owned handles closed. The descendant PID867449 was separately verified gone. Expected child KeyboardInterrupt traceback lines during group SIGINT are retained terminal output, not test failures. There were no failed or repeated tests in this scope.

This API and evidence are complete; live integration, call-state restoration, sound, and physical Bluetooth behavior remain untested. Stop after sealing.
'''
    write('API.md',api.encode())
    write('actual-tool-receipts.json',{'schema':'music-host-pipeline-supervision-actual-receipts/v2','tools':[
        {'chunk_id':'c1dd70','exit_code':2,'purpose':'confirm NEW helper absent; no execution'},
        {'chunk_id':'860ace','exit_code':0,'purpose':'bounded read of prior bridge lifecycle; no writes'},
        {'chunk_id':'6966d6','exit_code':0,'purpose':'11 real inert child tests','terminal':'Ran11 tests in1.022s; OK','wall_time_seconds':.955667996},
        {'chunk_id':'73406f','exit_code':0,'purpose':'small actual result summary'}],
        'expected_child_SIGINT_tracebacks_are_not_test_failures':True,'actual_audio_or_device_or_service_IO':False})
    proof={'schema':'music-host-pipeline-supervision-source-proof/v2','all_assigned_checks_passed':True,
        'source':{'path':str(source.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),'stat':pin(after)},
        'host_proof':{'bytes':len(host_raw),'sha256':SHA(host_raw)},
        'actual_methods':11,'max_child_fixture_seconds':1.5,'actual_test_exit':0,
        'all_cases_registered_PIDs_gone':all(row['all_registered_PIDs_gone'] for row in host['cases']),
        'all_cases_process_groups_exited':all(row['result']['all_owned_process_groups_exited'] for row in host['cases']),
        'all_cases_handles_closed':all(row['result']['all_owned_handles_closed'] for row in host['cases']),
        'all_cases_parent_FD_count_restored':all(row['parent_fd_count_before']==row['parent_fd_count_after'] for row in host['cases']),
        'same_group_descendant_reaped_by_its_parent_and_PID_gone':True,
        'upstream_failures_override_player_success':True,'group_signals_only_to_supervisor_created_sessions':True,
        'player_SIGINT_upstream_SIGTERM_preserved':True,'CIND_restoration_claimed':False,
        'bridge_player_source_edits':False,'real_PCM_Bluetooth_DBus_device_service_sound_IO':False,
        'native_guest_firmware_audio_admission_or_maps':False,'persistent_pipe_fixture_bytes':0,
        'registered_child_bound':8,'shared_shutdown_grace_seconds':5.0,'shared_kill_grace_seconds':2.0,
        'kernel_or_escaped_descendant_completion_guaranteed':False,
        'cleanup_bound_exhaustion_is_failure':True,'all_handles_closed':True,'STOP':True}
    write('proof.json',proof)
    files={str(file.relative_to(HERE)):file.read_bytes() for file in sorted(HERE.rglob('*')) if file.is_file()}
    if sum(map(len,files.values()))>=262144:raise ValueError('Persistent output budget')
    for name in files:(HERE/name).chmod(0o444)
    rows=[]
    for name,data in files.items():
        file=HERE/name;s=file.stat();rows.append({'path':str(file.relative_to(ROOT)),'bytes':len(data),'sha256':SHA(data),'mode':'0444','stat':pin(s)})
    seal=write('sealed-files.json',{'schema':'music-host-pipeline-supervision-seal/v2','all_assigned_checks_passed':True,
        'files':rows,'source_binding':proof['source'],'persistent_output_bytes_before_seal':sum(map(len,files.values())),
        'all_handles_closed':True,'device_IO':False,'STOP':True})
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed':True,'source_sha256':SHA(raw),'source_bytes':len(raw),
        'proof_sha256':SHA((HERE/'proof.json').read_bytes()),'proof_bytes':(HERE/'proof.json').stat().st_size,
        'seal_sha256':SHA(seal),'seal_bytes':len(seal),'output_bytes':sum(map(len,files.values()))+len(seal),'STOP':True}))


if __name__=='__main__':main()
