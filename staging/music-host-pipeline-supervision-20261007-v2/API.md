# Ordinary host pipeline supervisor

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
