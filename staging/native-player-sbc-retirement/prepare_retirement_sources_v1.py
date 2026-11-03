#!/usr/bin/env python3
"""NEW source derivatives only. No old runner/build execution or device action."""
from pathlib import Path
import ast,hashlib,json
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-sbc-ingress'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def create(path,text):
    with path.open('x')as f:f.write(text)
def change(text,before,after):
    assert text.count(before)==1,before[:100]
    return text.replace(before,after,1)
def main():
    inputs=[OLD/'mixer_source_ingress_v2.c',OLD/'sbc_fifo_ingress_owner_v2.c',
        OLD/'build_sbc_ingress_v3.py',OLD/'emulate_sbc_ingress_v4.py',
        ROOT/'staging/native-player-mixer-sync/emulate_mixer_sync_v3.py',
        BASE/'native_stop_scoped_v1.c',Path(__file__).resolve()]
    hashes={str(p.relative_to(ROOT)):sha(p)for p in inputs}
    audit=json.loads((ROOT/'evidence/firmware-analysis/native-ingress-physical-marker-checkpoint-audit.json').read_text())
    assert audit['all_passed'] and audit['current_findings']==239
    for p in inputs[:5]:assert audit['protected_sources'][str(p.relative_to(ROOT))]==sha(p)
    s=inputs[0].read_text()
    s=change(s,'extern struct mcs_guard aas_guard;',
      'extern struct mcs_guard aas_guard;\nextern int ns_capture_registration(void),ns_bind_selected(void),ns_retire_step(void);\nextern volatile uint32_t ns_stage;\nvolatile uint32_t mh_stop_requested,mh_stop_on_capacity;')
    s=change(s,'int r=aas_register(ticket);if(r)return r;',
      'int r=aas_register(ticket);if(r)return r;\n    r=ns_capture_registration();if(r)return r;')
    s=change(s,'if(!mh_handoff_result)mh_started=1;',
      'if(!mh_handoff_result)mh_handoff_result=ns_bind_selected();\n    if(!mh_handoff_result)mh_started=1;')
    before='''    if(command==5u){
        r=aas_stop();if(r!=UMC_PENDING)return r;
        if(mh_started){(void)send_mixer(16,0);(void)send_mixer(17,0);(void)send_mixer(18,0);}
        return 0; /* local Stop pending; no hardware STOP_DONE or unload */
    }
    if(!mh_started || mh_stream_error)return MCS_REJECTED;'''
    after='''    if(command==5u){
        r=aas_stop();if(r!=UMC_PENDING && r!=UMC_ALREADY)return r;
        r=ns_retire_step();mh_stop_requested=(r==UMC_PENDING);return r;
    }
    if(aas_control.status.state==UMC_STOPPING || !mh_started || mh_stream_error)return MCS_REJECTED;
    if(command==8u){mh_stop_on_capacity=1;return 0;}'''
    s=change(s,before,after)
    before='''        if(command){mh_iterations++;mh_last_result=process_command(command);mh_command_completed=command;}
        if(bits&UMC_SOURCE_EVENT)drain_source_event();'''
    after='''        if(command){mh_iterations++;mh_last_result=process_command(command);mh_command_completed=command;}
        /* Testable product requirement: Stop requested from an actual Source
         * wake while Mixer still borrows a full frame must defer retirement. */
        if(mh_stop_on_capacity && aas_guard.borrow && media_queue_control.running){
            mh_stop_on_capacity=0;mh_last_result=process_command(5u);mh_command_completed=5u;
        }
        if(mh_stop_requested){
            int r=ns_retire_step();
            if(r!=UMC_PENDING){mh_last_result=r;mh_stop_requested=0;}
        }
        if(bits&UMC_SOURCE_EVENT)drain_source_event();'''
    s=change(s,before,after)
    s=change(s,'command!=6u && command!=7u))','command!=6u && command!=7u && command!=8u))')
    create(BASE/'mixer_source_retirement_v1.c',s)
    owner=change(inputs[1].read_text(),'#include "owned_media_ingress_v1.c"',
        '#include "../native-player-sbc-ingress/owned_media_ingress_v1.c"')
    create(BASE/'sbc_fifo_retirement_owner_v1.c',owner)
    b=inputs[2].read_text()
    b=change(b,"OLD=ROOT/'staging/native-player-inline-fields/music-session'", "OLD=ROOT/'staging/native-player-inline-fields/music-session'\nINGRESS=ROOT/'staging/native-player-sbc-ingress'")
    b=b.replace("BASE/'owned_media_ingress_v1.c'","INGRESS/'owned_media_ingress_v1.c'")
    b=b.replace("BASE/'mixer_source_ingress_v2.c'","BASE/'mixer_source_retirement_v1.c'")
    b=b.replace("BASE/'sbc_fifo_ingress_owner_v2.c'","BASE/'sbc_fifo_retirement_owner_v1.c'")
    b=b.replace("out=BASE/'build-v3'","out=BASE/'build-v1'")
    b=b.replace("dump(BASE/'build-v3.json',manifest)","dump(BASE/'build-v1.json',manifest)")
    # New TU appears exactly once in source registry and once in compilation.
    b=b.replace("source=[Path(__file__).resolve(),","source=[Path(__file__).resolve(),BASE/'native_stop_scoped_v1.c',")
    b=b.replace('files=[HANDOFF/',"files=[BASE/'native_stop_scoped_v1.c',HANDOFF/",1)
    b=change(b,"'-I',str(BASE),'-I',str(HANDOFF)","'-I',str(BASE),'-I',str(INGRESS),'-I',str(HANDOFF)")
    b=change(b,"wanted=('aas_initialize'","wanted=('ns_capture_registration','ns_bind_selected','ns_retire_step','ns_status','ns_stage','ns_hold','ns_deferred','continuous_media_cancel_ready','mcs_mutation_begin','mcs_mutation_end','mh_stop_requested','mh_stop_on_capacity','aas_initialize'")
    b=change(b,"complete_player_image=False,", "complete_player_image=False,native_Stop_retirement_adapter_compile_only=True,native_STOP_DONE=False,safe_unload=False,")
    ast.parse(b);create(BASE/'build_retirement_v1.py',b)
    k=inputs[4].read_text()
    before='''            require(uc.reg_read(UC_ARM_REG_LR)==0x3B9C59, 'sync wrapper altered original LR')
            require(self.word(self.build['symbols']['ms_original_sync_completed']['value'])==0,
                    'PLAY opened before original sync completion')
            p=dict(entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP),
                   return_PC=0x3B9C58, call_args=self.regs(),'''
    after='''            caller=uc.reg_read(UC_ARM_REG_LR)
            is_stop=(caller!=0x3B9C59)
            if not is_stop:
                require(self.word(self.build['symbols']['ms_original_sync_completed']['value'])==0,
                        'PLAY opened before original sync completion')
            else:
                symbol=self.build['symbols']['ns_retire_step']
                require(symbol['value']<=caller-4<symbol['value']+symbol['size'],
                        'Stop barrier outside compiled retirement caller')
                require(self.word(self.build['symbols']['ns_stage']['value'])==3 and
                        self.word(self.build['symbols']['ns_hold']['value'])==1,
                        'Stop wait lost actual Source native hold')
                require(self.leases()['borrow']==self.leases()['media']==self.leases()['callback']==0,
                        'Stop wait entered before full-frame leases returned')
            p=dict(entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP),
                   return_PC=caller&~1, call_args=self.regs(), barrier_kind='Stop'if is_stop else'initialize','''
    k=change(k,before,after);ast.parse(k)
    create(BASE/'kernel_retirement_monitor_v1.py',k)
    # This derivative only selects the new observer class; no old main runs.
    i=change(inputs[3].read_text(),"PARENT=ROOT/'staging/native-player-mixer-sync/emulate_mixer_sync_v3.py'",
        "PARENT=ROOT/'staging/native-player-sbc-retirement/kernel_retirement_monitor_v1.py'")
    ast.parse(i);create(BASE/'ingress_retirement_monitor_v1.py',i)
    outputs={str(p.relative_to(ROOT)):sha(p)for p in BASE.iterdir()if p.is_file()and p.name not in ('source-preparation-v1.json',)}
    assert all(sha(ROOT/p)==h for p,h in hashes.items())
    data=dict(all_passed=True,source_sha256=hashes,output_sha256=outputs,source_derivation_only=True,guest_executed=False,
        old_sources_modified=False,device_IO=False,canonical_write=False,native_Stop_runtime_verified=False,
        native_STOP_DONE_or_quiescence_or_exclusive_verified=False)
    create(BASE/'source-preparation-v1.json',json.dumps(data,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,source_derivation_only=True,outputs=len(outputs),guest_executed=False)))
if __name__=='__main__':main()
