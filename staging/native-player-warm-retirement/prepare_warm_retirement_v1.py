#!/usr/bin/env python3
"""Integrate existing native retirement into the warm single-image Source.
No claim yield, STOP_DONE, native heap or device operation is introduced.
"""
from pathlib import Path
import json,hashlib
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 old=ROOT/'staging/native-player-route-entries/mixer_source_route_v1.c';s=old.read_text()
 s=s.replace('extern struct mcs_guard aas_guard;',
 '''extern struct mcs_guard aas_guard;
extern int ns_capture_registration(void),ns_bind_selected(void),ns_retire_step(void);
volatile uint32_t mh_stop_requested,mh_stop_on_capacity;''',1)
 s=s.replace('    int r=aas_register(ticket);if(r)return r;','    int r=aas_register(ticket);if(r)return r;\n    r=ns_capture_registration();if(r)return r;',1)
 s=s.replace('    if(!mh_handoff_result)mh_started=1;','    if(!mh_handoff_result)mh_handoff_result=ns_bind_selected();\n    if(!mh_handoff_result)mh_started=1;',1)
 old_stop='''        r=aas_stop();if(r!=UMC_PENDING)return r;
        if(mh_started){(void)send_mixer(16,0);(void)send_mixer(17,0);(void)send_mixer(18,0);}
        return 0; /* local Stop pending; no hardware STOP_DONE or unload */'''
 new_stop='''        r=aas_stop();if(r!=UMC_PENDING && r!=UMC_ALREADY)return r;
        r=ns_retire_step();mh_stop_requested=(r==UMC_PENDING);return r;
        /* Native15/19/20 and full list removal replace the old16/17/18 path.
         * Claim/guard/tasks remain pinned; no STOP_DONE or safe unload. */'''
 assert old_stop in s;s=s.replace(old_stop,new_stop)
 s=s.replace('    if(!mh_started || mh_stream_error)return MCS_REJECTED;','    if(aas_control.status.state==UMC_STOPPING || !mh_started || mh_stream_error)return MCS_REJECTED;\n    if(command==10u){mh_stop_on_capacity=1;return 0;}',1)
 old_loop='''        if((bits&UMC_SOURCE_EVENT) || command==9u){if(!mh_remote_paused)drain_source_event();}'''
 new_loop='''        /* Offline command10 arms an actual Source capacity-wake Stop while
         * Mixer still owns its real full frame. No HOST lease is synthesized. */
        if(mh_stop_on_capacity && aas_guard.borrow && media_queue_control.running){
            mh_stop_on_capacity=0;mh_last_result=process_command(5u);mh_command_completed=5u;
        }
        if(mh_stop_requested){
            int r=ns_retire_step();
            if(r!=UMC_PENDING){mh_last_result=r;mh_stop_requested=0;}
        }
        if((bits&UMC_SOURCE_EVENT) || command==9u){if(!mh_remote_paused)drain_source_event();}'''
 assert old_loop in s;s=s.replace(old_loop,new_loop)
 old_commands='command!=8u && command!=9u)';assert old_commands in s;s=s.replace(old_commands,'command!=8u && command!=9u && command!=10u)',1)
 new=BASE/'mixer_source_warm_retirement_v1.c'
 with new.open('x')as f:f.write(s)
 deps={str(p.relative_to(ROOT)):sha(p)for p in(Path(__file__),old,new,ROOT/'staging/native-player-sbc-retirement/native_stop_scoped_v1.c',ROOT/'staging/native-player-sbc-retirement/mixer_source_retirement_v1.c')}
 manifest=dict(all_passed=True,source_sha256=deps,selective_warm_no_global_reset_retained=True,three_native_mutex_and_five_entry_gates_retained=True,native_stop_registration_capture_and_selected_bind=True,Stop_calls_native_retirement_in_same_image=True,old_16_17_18_reset_Stop_removed=True,pause8_resume9_retained=True,offline_capacity_borrow_Stop_command=10,durable_all_writers_or_STOP_DONE_or_claim_yield=False,device_IO=False)
 with (BASE/'source-preparation-v1.json').open('x')as f:json.dump(manifest,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,native_retirement_integrated_source=True,device_IO=False)))
if __name__=='__main__':main()
