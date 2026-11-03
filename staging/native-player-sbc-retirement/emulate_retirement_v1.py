#!/usr/bin/env python3
"""NEW bounded Stop15/19/20 ACK and full source-list retirement guest.

Original kernel/Mixer/provider/list instructions run. Declared cold inputs,
opaque handles/backing and hardware ring fixtures remain; no phone, native
heap/exclusive/STOP_DONE/DMA drain/unload or installed App is claimed.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
def load(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
I=load(BASE/'ingress_retirement_monitor_v1.py','retirement_ingress')
B=I.B
sha,rel,dump,require=I.sha,I.rel,I.dump,I.require
HEAD=0x034e68d8+8*4

class Retirement(I.Ingress):
    def __init__(self,stock,elf,build,reference,index):
        self.native_stop_entries=[];self.native_stop_returns=[];self.pending_stops={}
        self.ns_entries=[];self.ns_returns=[];self.pending_ns=None
        self.retirement_stores=[];self.notice23=[];self.cleanup_release_calls=[]
        super().__init__(stock,elf,build,reference,index)
    def native(self):
        s=self.build['symbols'];g=s['aas_guard']['value'];o=s['memory_output_control']['value']
        index=self.word(s['ns_instance']['value'])
        provider=list(bytes(self.uc.mem_read(B.POOL+index*576,32)))if index<5 else None
        return dict(head=self.word(HEAD),node_count=struct.unpack('<H',self.uc.mem_read(B.RECORD+0x1c0,2))[0],
            prepared=self.uc.mem_read(B.RECORD+2,1)[0],methods_hex=bytes(self.uc.mem_read(B.RECORD+0xf4,68)).hex(),
            selected_index=self.word(B.RECORD+0xf0),mixer_active=self.uc.mem_read(B.MIXER+0x84,1)[0],
            provider=provider,ns_stage=self.word(s['ns_stage']['value']),ns_hold=self.word(s['ns_hold']['value']),
            native_mutation=self.word(g+48),guard_held=self.word(g+16),native_calls=self.word(o+20),
            active_ticket=self.word(o+12),installed=self.word(o+16),leases=self.leases())
    def ns_status(self):
        self.invoke_kernel('ns_status',(B.old.RESULT+512,),phase='read-only compiled retirement status')
        return list(struct.unpack('<14I',self.uc.mem_read(B.old.RESULT+512,56)))
    def boot(self):
        super().boot()
        self.invoke_kernel(0x3008a1,(B.RECORD+0x1e0,),phase='once-only original source-list mutex constructor before live first packet')
    def store(self,uc,access,address,size,value,data):
        super().store(uc,access,address,size,value,data)
        pc=self.last_instruction[0]
        if pc in (0x2fa48e,0x2fa492,0x2fa4be,0x5e75b4,0x48ee64,
                  0x437ab0,0x437ab2,0x2775cc,0x277642):
            n=self.native()
            require(n['ns_stage']==3 and n['ns_hold']==n['native_mutation']==n['native_calls']==1,
                'original retirement write outside retained Source cleanup hold')
            self.retirement_stores.append(dict(journal_ordinal=self.ordinal,PC=pc,address=address,size=size,value=value,
                state=self.snapshot(),native_before=n))
    def code(self,uc,address,size,data):
        # The inherited observer executes no instructions or host context
        # repair: only actual bodies and declared preexisting opaque services.
        super().code(uc,address,size,data)
        for entry,p in list(self.pending_stops.items()):
            if address==p['return_PC']:
                require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'],'original cleanup/removal full-return SP')
                require(self.word(B.READY_TASKS)==p['actor'],'original cleanup/removal full-return actor')
                n=self.native();require(n['ns_hold']==n['native_mutation']==n['native_calls']==1,
                    'cleanup hold dropped before full original return')
                self.native_stop_returns.append(dict(p,returned=self.snapshot(),r0=uc.reg_read(UC_ARM_REG_R0),native=n))
                del self.pending_stops[entry]
        if self.pending_ns and address==self.pending_ns['return_PC']:
            p=self.pending_ns;require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'],'compiled retirement full-return SP')
            require(self.word(B.READY_TASKS)==p['actor'],'compiled retirement returned on another actor')
            self.ns_returns.append(dict(p,returned=self.snapshot(),r0=uc.reg_read(UC_ARM_REG_R0),native=self.native()))
            self.pending_ns=None
        s=self.build['symbols']
        if address==s['ns_retire_step']['value']:
            require(self.pending_ns is None,'nested retirement source call')
            p=dict(entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),
                return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,actor=self.word(B.READY_TASKS),native=self.native())
            self.ns_entries.append(p);self.pending_ns=p
        if address in (0x2f9f1c,0x437a90,0x48ee12,0x5e75b2,0x48ee58,0x277674):
            require(address not in self.pending_stops,'nested same original retirement helper')
            n=self.native();require(n['ns_stage']==3 and n['ns_hold']==n['native_mutation']==n['native_calls']==1,
                'original retirement entry lost cleanup hold')
            expected=self.source_tcb if address==0x277674 else self.mixer_tcb
            require(self.word(B.READY_TASKS)==expected,'original retirement helper wrong Source/Mixer actor')
            if address==0x277674:
                require(self.regs()[:2]==[B.RECORD+0x1a8,0] and n['node_count']==1 and n['head'],
                    'original one-node removal input changed')
                require(len([p for p in self.sync_returns if p.get('barrier_kind')=='Stop'])==1,
                    'list removal before full original Stop sync return')
                require(n['prepared']==0 and not any(bytes.fromhex(n['methods_hex'])) and n['mixer_active']==0,
                    'list removal before native methods idle')
            p=dict(entry_PC=address,entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),
                return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,actor=expected,args=self.regs(),native=n)
            self.native_stop_entries.append(p);self.pending_stops[address]=p
        if address==0x455c86 and self.regs()[2]==23:
            n=self.native();require(n['node_count']==1 and n['head']==0 and n['ns_hold']==n['native_calls']==1,
                'notice23 misclassified as full removal/quiescence')
            require(self.regs()[1]==0,'unexpected notification metadata')
            self.notice23.append(dict(state=self.snapshot(),args=self.regs(),native=n))
        if address==0x3887a2 and 0x277674 in self.pending_stops:
            self.cleanup_release_calls.append(dict(state=self.snapshot(),args=self.regs(),native=self.native()))
    def stop(self):
        require(self.invoke_kernel('mh_request_command',(5,),phase='controller requests actual Source Stop')==0,'Stop request failed')
        before=dict(native=self.native(),ns=self.ns_status(),sync_entries=len(self.sync_entries),sync_returns=len(self.sync_returns),
            actual_controller_snapshot=self.snapshot())
        self.park()
        return dict(before_original_ACK=before,after_native_retirement=self.native(),status=self.ns_status(),source_status=self.status())
    def result(self,name,records):
        require(self.pending_ns is None and not self.pending_stops,'retirement frame still pending')
        row=super().result(name,records)
        row.update(native_stop_entries=self.native_stop_entries,full_native_stop_returns=self.native_stop_returns,
            compiled_retirement_entries=self.ns_entries,full_compiled_retirement_returns=self.ns_returns,
            actual_retirement_stores=self.retirement_stores,notice23_before_count_commit=self.notice23,
            opaque_list_release_calls=self.cleanup_release_calls,retirement_terminal=self.native(),retirement_status=self.ns_status(),
            Stop_ACK_orders_same_Mixer_only=True,original_heap_query_and_release_still_opaque_fixtures=True,
            native_control_remains_STOPPING=True,module_guard_and_original_TCBs_remain_resident=True,
            native_STOP_DONE_or_exclusive_hardware_drain_safe_unload_verified=False)
        return row

def positive_complete(m,records,expect_fifo):
    n=m.native();s=m.ns_status();state=m.status()
    require(s[0]==4 and s[7]==s[8]==s[9]==1 and s[10]==expect_fifo and not s[12],
        'whole Stop/removal/anchor/FIFO transaction did not complete')
    require(n['head']==n['node_count']==n['prepared']==n['mixer_active']==n['active_ticket']==n['installed']==0,
        'native source remained live after bounded retirement')
    require(n['native_calls']==n['native_mutation']==0 and n['guard_held']==1 and
        state[8]==state[6]==state[7]==0,'hold leaked or STOP_DONE/unload fabricated')
    require(m.producer()['owned'][4]==m.producer()['queue'][2]==0,'owned FIFO or copied input remains')
    require(len(m.notice23)==len(m.cleanup_release_calls)==1,'original full list delete chain missing')
    ordered=[struct.unpack('<3I',bytes.fromhex(x['bytes_hex']))[0]&255 for x in m.message_receives]
    require(ordered[-3:]==[15,19,20],'native Stop FIFO ordering failed')
    decoders=len(m.codec_entries);records.append(m.receive(m.packet(1),False))
    require(len(m.codec_entries)==decoders,'retired source decoded foreign input')
    records.append(dict(native=n,status=s,original_FIFO_command_order=ordered))

def run_case(m,name):
    m.boot();records=[]
    if name=='Stop_before_first_packet_keeps_no_anchor':
        records.append(m.stop());records.append(m.receive(m.packet(0),False))
        require(m.ns_status()[0]==6 and not m.native_stop_entries and not m.sync_entries and not m.codec_entries,
            'pre-input Stop invented cleanup/completion')
        return records
    records.append(m.receive(m.packet(0)));m.complete_first_sync_and_attach_output()
    require(m.ns_status()[0]==2,'Source did not capture exact registration/selected provider')
    if name=='foreign_controller_cannot_retire_source':
        before=m.native();r=m.invoke_kernel('ns_retire_step',phase='negative ordinary controller retirement caller')
        require(r==0xfffffffb,'foreign controller accepted Source cleanup')
        after=m.native();require(before==after and not m.native_stop_entries,'foreign caller changed native source')
        records.append(dict(foreign_result=r,before=before,after=after))
    if name in ('Stop_with_full_PCM_and_pending_compressed','Stop_during_actual_Mixer_borrow_defers'):
        if name=='Stop_during_actual_Mixer_borrow_defers':m.command(8)
        for i in range(1,6):records.append(m.receive(m.packet(i)))
        require(m.producer()['owned'][4]==4 and m.producer()['queue'][2]==2,'pending input backpressure fixture missing')
        if name=='Stop_during_actual_Mixer_borrow_defers':
            m.park();require(m.ns_status()[6]>=1,'actual borrowed Mixer frame never deferred Stop')
            require(any(p['native']['leases']['borrow'] for p in m.ns_entries),'Stop was not requested in full Mixer borrow')
            positive_complete(m,records,3);return records
        records.append(m.stop());positive_complete(m,records,4);return records
    if name=='replaced_native_head_is_pinned':
        m.fixture(HEAD,struct.pack('<I',0xd0ffffff),'negative independent native writer changes head identity')
        records.append(m.stop())
        n=m.native();require(n['head']==0xd0ffffff and n['node_count']==1 and n['active_ticket'] and
            n['installed'] and not m.native_stop_entries and not m.notice23,'changed head was deleted or anchor released')
        records.append(m.receive(m.packet(1),False));return records
    raw=m.cycle(True);m.compare(raw,m.expected(0))
    records.append(dict(PCM_hex=raw.hex(),HOST_expected_PCM_hex=m.expected(0).hex()))
    records.append(m.stop());positive_complete(m,records,0)
    return records

def main():
    require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
    runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
    build=json.loads((BASE/'build-v2.json').read_text());reference=json.loads(I.REFERENCE.read_text())
    sources={**build['source_sha256'],**build['generated_sha256'],**reference['source_sha256']}
    for p in (Path(__file__).resolve(),BASE/'ingress_retirement_monitor_v1.py',BASE/'kernel_retirement_monitor_v1.py',
        B.PARENT,I.REFERENCE,BASE/'build-v2.json',ROOT/build['ELF'],ROOT/'scripts/analyze_native_sections.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py'):
        sources[rel(p)]=sha(p)
    for p,h in sources.items():require(sha(ROOT/p)==h,'changed source '+p)
    require(sources[build['ELF']]==build['ELF_sha256'],'wrong ELF')
    dump(runtime/'inputs-at-run.json',sources);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    e=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','retirement_elf').ELF32(ROOT/build['ELF'])
    stock=B.NativeImage();cases=[];m=None
    try:
        for name,index in (('Stop_after_real_PCM_playback',1),('Stop_with_full_PCM_and_pending_compressed',0),
            ('Stop_during_actual_Mixer_borrow_defers',0),('Stop_before_first_packet_keeps_no_anchor',2),
            ('foreign_controller_cannot_retire_source',1),('replaced_native_head_is_pinned',1)):
            m=Retirement(stock,e,build,reference,index);records=run_case(m,name);row=m.result(name,records)
            p=runtime/(name+'.json');dump(p,row);cases.append(dict(name=name,path=rel(p),sha256=sha(p),passed=True))
            print(json.dumps(dict(case=name,Stop_helpers=len(m.native_stop_returns),barrier_returns=m.ns_status()[7],deferred=m.ns_status()[6])),flush=True);m=None
        proof=dict(all_passed=True,source_sha256=sources,cases=cases,case_count=len(cases),updated_utc=datetime.now(timezone.utc).isoformat(),
            actual_original_Stop15_cleanup19_ACK20_and_full_list_removal=True,actual_provider_stop_and_release_methods=True,
            module_and_tasks_remain_pinned=True,original_heap_and_hardware_outputs_still_fixtures=True,
            independent_FILE_review_complete=False,native_STOP_DONE_heap_exclusive_phone_App_speaker_or_safe_unload_verified=False,device_IO=False)
        dump(BASE/'native-retirement-v1-proof.json',proof);print(json.dumps(dict(all_passed=True,proof=rel(BASE/'native-retirement-v1-proof.json'))),flush=True)
    except BaseException as error:
        row=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),source_sha256=sources,cases_completed=cases,device_IO=False)
        if m:row.update(phase=m.phase,trace=m.trace,registers=m.snapshot(),native=m.native(),producer=m.producer(),
            native_stop_entries=m.native_stop_entries,native_stop_returns=m.native_stop_returns,ns_entries=m.ns_entries,ns_returns=m.ns_returns,
            actual_retirement_stores=m.retirement_stores,notice23=m.notice23,CPU_store_journal=m.journal,
            declared_fixture_mutations=m.fixtures,initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
            final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC})
        dump(runtime/'terminal-failure.json',row);raise
if __name__=='__main__':main()
