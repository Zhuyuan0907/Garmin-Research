#!/usr/bin/env python3
"""Loaded native guarded callback -> real original kernel tasks -> virtual output.

The existing output/kernel fixtures are prepared first and their idle decoder
is exited. Stock loader then reads the new module in that SAME VM, preserving
live kernel RAM. The outer filesystem proof remains the preceding frozen stage;
this stage uses the original DLL loader with explicit host read boundary.
Radio, storage, MMU/cache and peripheral input/output remain fixtures.
"""
from emulate_native_loaded_playback import *
from emulate_native_music_loaded import (INPUT,HEAP,OUTPUT,STATE,CONTEXT,CHANNELS,DESCRIPTORS,
    CONTROL,RECORD,AVDTP_MUTEX,DB_MUTEX,ENTITY,TX,HEAD,TAIL,FREE,SCHEDULED,L2_MUTEX,LCID,MEDIA_LCID,PEER)
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_LR
from unicorn import UC_PROT_WRITE,UC_HOOK_MEM_READ
from collections import Counter
import hashlib
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

class ReadyMusicVM(LoadedPlayback):
    def __init__(self,stock,legacy,app,source_priority=40,defer_yield=False,boot_runtime=True):
        self.loading_component=False;self.loaded_playback_ready=False
        self.app=app;self.app_proof={};self.legacy_execution_after_load=[]
        self.status_irq_depth=0;self.status_reads=0;self.status_captures=0
        self.init_pause_pending=False;self.init_pause_events=[];self.original_START_entries=0
        self.radio_ready=False;self.sym={k:v['address'] for k,v in app['symbols'].items()}
        EventDriver.__init__(self,stock,*legacy)
        # Scaffolding has no incoming packets or source task. Stop its one
        # idle decoder before replacing the private implementation.
        old_worker=self.worker_tcb
        require(not self.pipeline()[4] and not self.queue_state()[2] and
                self.source_state()['tcb']==0,'Preparatory fixture already owns media')
        require(self.pipe('media_worker_shutdown')==0,'Preparatory decoder shutdown failed')
        self.yield_all()
        require(self.byte(old_worker+22)==0x80 and self.worker_state()[6]==1,
                'Preparatory decoder did not finish stock exit')
        self.preparatory_worker=old_worker
        self.legacy_ranges=[(m['load_base'],m['load_base']+m['flat_binary_bytes']) for m in legacy]
        self.source_ready=False;self.hook_ready=False
        old_owned=(ROOT/self.output['flat_binary']).read_bytes()
        off=self.publication_entry-self.output['load_base']
        for address,raw in ((self.publication_entry,old_owned[off:off+8]),
                           (self.source['completion_entry'],stock.read(self.source['completion_entry'],10)),
                           (DRIVER_CALLBACK,stock.read(DRIVER_CALLBACK,10))):
            self.uc.mem_write(address,raw);self.uc.ctl_remove_cache(address,address+len(raw))
        self.prepare_radio_fixture()
        kernel_snapshot=(self.current(),self.word(CENTRAL_GLOBAL),self.output_tcb,self.timer_tcb)
        self.loaded_report=load_in_existing_vm(self,app)
        require(kernel_snapshot==(self.current(),self.word(CENTRAL_GLOBAL),self.output_tcb,self.timer_tcb),
                'Loader reset a running kernel or audio-task pointer')
        symbols=app['symbols'];base=app['extension_base'];flat=(ROOT/app['extension_flat']).read_bytes()
        require(bytes(self.uc.mem_read(base,len(flat)))==flat,'Original reader did not load exact combined code')
        require(struct.unpack('<Iii',self.uc.mem_read(symbols['app_component_state']['address'],12))==
                (1,11,0),'Combined entry did not initialize original voice/decoder')
        self.voice_runtime_before=bytes(self.uc.mem_read(IMAGE+12,app['original_ram_bytes']-12))
        self.tts_pointers_before=[(int(r['storage'],16),int(r['trampoline'],16),int(r['target_word'],16))
                                 for r in self.loaded_report['trampolines_verified']]
        table=symbols['app_component_api']['address'];names=app['private_api']
        require(list(struct.unpack('<12I',self.uc.mem_read(table,48)))==
                [symbols[n]['address'] for n in names],'Private API table points at legacy code')
        self.output=dict(self.output,load_base=base,flat_binary=app['extension_flat'],
            flat_binary_bytes=len(flat),elf_sha256=app['extension_elf_sha256'],symbols=symbols,
            pcm_pages=app['pcm_pages'],gather_page=symbols['gather']['address'])
        self.symbols.update(symbols)
        self.native_aliases.update({name:v['address'] for name,v in symbols.items()
                                   if name in self.native_aliases})
        self.control=symbols['memory_output_control']['address']
        self.slot_base=symbols['memory_output_slots']['address']
        self.state_start=symbols['__app_bss_start']['address'];self.state_end=symbols['__app_bss_end']['address']
        self.mapping_end=(self.state_end+4095)&~4095
        self.buffers=app['pcm_pages'];self.buffer_expected={}
        self.stack_start=symbols['__worker_stack_start']['address']
        self.stack_end=symbols['__worker_stack_end']['address']
        self.source_stack=symbols['__source_stack_start']['address']
        self.source_stack_end=symbols['__source_stack_end']['address']
        self.playback_bss=symbols['playback_state']['address'];self.playback_end=self.playback_bss+32
        self.coord_bss=symbols['coordinator_state']['address'];self.coord_end=self.coord_bss+60
        self.source_bss=symbols['source_worker_state']['address'];self.source_end=self.source_bss+52
        ranges=function_ranges(app)
        coord_names=[n for n in ranges if n.startswith('media_coordinator_')]
        lo=min(ranges[n][0] for n in coord_names);hi=max(sum(ranges[n]) for n in coord_names)
        self.coordinator=dict(self.coordinator,load_base=lo,flat_binary_bytes=hi-lo,
            symbols=symbols,owned_elf_sha256_required=app['extension_elf_sha256'])
        self.playback=dict(self.playback,symbols=symbols)
        self.source=dict(self.source,symbols=symbols,load_base=base,flat_binary_bytes=len(flat),
            owned_elf_sha256_required=app['extension_elf_sha256'],
            coordinator_elf_sha256_required=app['extension_elf_sha256'],
            publication_entry=symbols['owned_media_consume']['address'],
            publication_resume=symbols['owned_media_consume']['address']+8)
        self.publication_entry=self.source['publication_entry']
        require(bytes(self.uc.mem_read(self.publication_entry,8)).hex()=='f3472de90050a0e1',
                'Relocated publication prologue changed')
        self.source_observe_points={self.address(n) for n in (
            'media_coordinator_init','media_coordinator_pump','media_coordinator_cancel',
            'source_publication_hook','source_publication_after_original','source_worker_published',
            'source_completion_after_original','source_worker_completed')}
        self.source_observe_points.update((0x277596,0x2775e6,0x277694,0x36b720,0x3ec498))
        self.publication_patch=struct.pack('<II',0xe51ff004,self.address('source_publication_hook'))
        self.completion_patch=bytes.fromhex('004b1847')+struct.pack('<I',self.address('source_completion_hook'))+bytes.fromhex('c046')
        self.hook_bytes=bytes.fromhex('014b1847c046')+struct.pack('<I',self.address('playback_callback_hook'))
        self.app_guards=[(base+0x15000,4096),(base+0x1f000,4096),
                         (self.stack_start,64),(self.source_stack,64)]
        for address,size in self.app_guards:
            require(not any(self.uc.mem_read(address,size)),'Wrapper did not clear new guard region')
            self.uc.mem_write(address,b'\xa5'*size)
        self.uc.mem_protect(base,(len(flat)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
        self.source_ready=True;self.hook_ready=True;self.loaded_playback_ready=True
        self.worker_steps=[];self.switch_visits=set();self.kernel_events=[]
        self.native_aliases.update({n:v['address'] for n,v in symbols.items()})
        self.dispatch.callback=self.address('native_music_callback')
        self.radio_ready=True
        for address in (0x4ccfb4,0x4ccc3c,0x5d7588):self.radio_call(address)
        require(self.word(RECORD)==0x90007,'Original SDP did not boot')
        for page in {p['address']&~4095 for p in app['patch_plan']}:
            self.uc.mem_protect(page,4096,7)
        require(self.kernel_call('native_music_start')==0,'Loaded native bootstrap failed')
        for page in {p['address']&~4095 for p in app['patch_plan']}:
            self.uc.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
        self.signaling_fixture()
        if boot_runtime:
            require(self.kernel_call('music_runtime_boot',(self.channel,36,source_priority))==0,'Runtime task construction failed')
        self.worker_tcb=self.worker_state()[0];self.source_tcb=self.source_state()['tcb']
        if boot_runtime and not defer_yield:
            self.yield_all()
            require(self.worker_tcb==((self.stack_end-108)&~7) and self.worker_state()[1]==1 and
                    self.byte(self.worker_tcb+22)==2 and self.source_state()['init_result']==0 and
                    self.source_state()['entered']==1 and self.byte(self.source_tcb+22)==2,
                    'Relocated source/decoder tasks did not boot/block')
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.protect_original_voice,
                         begin=IMAGE,end=IMAGE+app['original_ram_bytes']-1)
        self.queries_before=self.query_original_api()
        self.status_range=function_ranges(app)['music_runtime_status']
        self.status_fields=[(self.address(n),size) for n,size in [('music_runtime_state',40),
            ('source_worker_state',52),('coordinator_state',60),('media_worker_state',32),
            ('memory_output_control',48),('media_queue_control',36),('owned_media_control',52)]]
        self.uc.hook_add(UC_HOOK_MEM_READ,self.watch_snapshot_reads)



    def prepare_radio_fixture(self):
        self.radio_locks={DB_MUTEX:False,L2_MUTEX:False};self.radio_sends=[];self.guest_writes=[]
        self.radio_calls=[];self.radio_visits=Counter();self.radio_cache=[]
        for page in range(0x50000,0xcb2000,4096):
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096)
                size=min(4096,0xcb179c-page)
                if size>0:self.uc.mem_write(page,self.stock.read(page,size))
        for start,n in [(0x3a7c000,4096),(0x3a96000,8192),(INPUT,4096),(HEAP,4096),(OUTPUT,4096)]:
            if not any(lo<=start and start+n-1<=hi for lo,hi,_ in self.uc.mem_regions()):self.uc.mem_map(start,n)
            self.uc.mem_write(start,b'\xa5'*n)
        self.uc.mem_write(CONTEXT,bytes(DESCRIPTORS+36-CONTEXT))
        self.uc.mem_write(CONTROL,bytes(168));self.uc.mem_write(ENTITY,bytes(880));self.uc.mem_write(TX,bytes(2600))
        self.uc.mem_write(ENTITY+6,struct.pack('<H',LCID));self.uc.mem_write(ENTITY+0x14,struct.pack('<H',672))
        self.uc.mem_write(ENTITY+0x1e,b'\x05');self.uc.mem_write(ENTITY+0x25,b'\xff')
        for i in range(50):self.uc.mem_write(TX+i*52+0x2f,b'\xff')
        for a,data in [(0xf6957c,b'\0'),(SCHEDULED,b'\0'),(HEAD,b'\xff'),(TAIL,b'\xff'),(FREE,struct.pack('<H',50)),
            (0xf69584,struct.pack('<H',4)),(0xf69586,struct.pack('<H',8)),(0xf69598,bytes(4)),
            (0xf695b0,struct.pack('<H',1)),(0xf42e3c,b'\0')]:self.uc.mem_write(a,data)
        for a in self.dispatch.hooks:
            self.uc.mem_write(a,self.stock.read(a,4));self.uc.ctl_remove_cache(a,a+4)
        self.dispatch.hooks.clear()
        self.radio_sites={0x221d2c,0x55238e,0x5523de,0x5523fc,0x50c138,0x50c150,
            0x5525bc,0x5524da,0x5524ee,0x5524f6,0x5a7794,0x60faec,0x525f1c,0x544bc4,0x525560,0x5450a4}
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.watch_guest_MAIN)

    def watch_guest_MAIN(self,uc,access,address,size,value,data):
        if not self.radio_ready or not 0x50000<=address<0xcb179c:return
        pc=uc.reg_read(UC_ARM_REG_PC)
        require(self.app['extension_base']<=pc<self.address('__app_code_end'), 'MAIN write did not come from loaded guest')
        require(any(p['address']<=address and address+size<=p['address']+p['length'] for p in self.app['patch_plan']),
                'Undeclared guest MAIN change')
        self.guest_writes.append({'PC':hex(pc),'address':hex(address),'bytes':size})

    def ret_radio(self,value=0):
        self.uc.reg_write(UC_ARM_REG_R0,value&0xffffffff);self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))

    def observe(self,uc,address,size,data):
        if getattr(self,'radio_ready',False):
            if address==0x21b6cc:self.status_irq_depth+=1
            elif address==0x21b6dc:
                require(self.status_irq_depth>0,'Unbalanced fixture IRQ restore')
                self.status_irq_depth-=1
            if address==0x5752cc:self.original_START_entries+=1
            if address==self.address('music_runtime_status'):self.status_captures+=1
            if self.init_pause_pending and address==self.address('__wrap_media_coordinator_init'):
                self.init_pause_pending=False
                require(self.current()==self.source_tcb and self.source_state()['entered']==1,
                        'Initializer pause did not occur on actual source actor')
                self.init_pause_events.append({'original_PC':hex(address),'current_tcb':hex(self.current()),
                    'SP':hex(uc.reg_read(UC_ARM_REG_SP)),'source_init_result_before_return':self.source_state()['init_result'],
                    'guest_trampoline_posts_controller_via_original_kernel':True})
                uc.reg_write(UC_ARM_REG_PC,0x09400200);return
        if getattr(self,'radio_ready',False) and address in self.radio_sites:
            self.radio_visits[address]+=1;r=[uc.reg_read(v) for v in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
            if address==0x221d2c:
                uc.ctl_remove_cache(IMAGE,DESCRIPTOR);uc.ctl_remove_cache(0x50000,0xcb179c)
                self.radio_cache.append('module_and_MAIN_VM_invalidation_fixture');self.ret_radio();return
            if address==0x55238e:self.radio_locks[AVDTP_MUTEX]=False;self.ret_radio();return
            if address in (0x5523de,0x5523fc):
                acquire=address==0x5523de;obj=r[0]
                require(obj in self.radio_locks and self.radio_locks[obj]!=acquire,'Unbalanced fixture radio lock')
                self.radio_locks[obj]=acquire;self.ret_radio();return
            if address==0x50c138:
                require(r[0]==25,'PSM changed');uc.mem_write(r[1],struct.pack('<I',25)+bytes(48));self.ret_radio();return
            if address==0x50c150:
                require(struct.unpack('<5I',uc.mem_read(r[0],20))==(25,0x50b989,0x50b5c5,0x50b3dd,0x50b1f9),'PSM ABI changed')
                self.ret_radio();return
            if address in (0x5525bc,0x5524ee,0x60faec,0x525f1c,0x544bc4,0x525560,0x5450a4):self.ret_radio();return
            if address==0x5524da:
                require(0<r[0]<=32,'Radio allocation changed');self.ret_radio(HEAP+4096-32);return
            if address==0x5524f6:
                require(r[2]<=64,'Radio memcpy changed');uc.mem_write(r[0],bytes(uc.mem_read(r[1],r[2])));self.ret_radio(r[0]);return
            if address==0x5a7794:
                self.radio_sends.append({'lcid':r[0],'wire_hex':bytes(uc.mem_read(r[2]+4,r[1]-4)).hex()});return
        if getattr(self,'radio_ready',False) and address==self.address('source_worker_published'):
            require(self.current()==self.worker_tcb and not self.pipeline()[1] and not any(self.radio_locks.values()),
                    'Source notified before decode busy/AV mutex released or by wrong actor')
        super().observe(uc,address,size,data)

    def radio_call(self,address,args=(),payload=None,pointer_arg=None):
        args=list(args)
        if payload is not None:
            require(0<len(payload)<=4096,'Radio fixture payload bounds')
            self.uc.mem_protect(INPUT,4096,UC_PROT_READ|UC_PROT_WRITE)
            p=INPUT+4096-len(payload);self.uc.mem_write(p,payload);self.uc.mem_protect(INPUT,4096,UC_PROT_READ)
            args[pointer_arg]=p
        self.native_aliases['_radio_call']=address|1
        result=self.kernel_call('_radio_call',args)
        require(not any(self.radio_locks.values()),'Radio call retained mutex')
        if payload is not None:require(bytes(self.uc.mem_read(p,len(payload)))==payload,'Radio input was modified')
        self.radio_calls.append({'entry':hex(address),'result':result});return result

    def signaling_fixture(self):
        self.uc.mem_write(CONTEXT+0x13,b'\x00\xff\xff'+PEER)
        self.uc.mem_write(CHANNELS,struct.pack('<H',LCID)+bytes([0,0,0,0x10,0,0]))

    def wire(self,raw):
        before=len(self.radio_sends);result=self.radio_call(0x50bbb8,[LCID,0,len(raw)],raw,1)
        return {'result':result,'new_sends':self.radio_sends[before:],'state':self.byte(STATE+0x12)}

    def stream_state(self):
        values=struct.unpack('<20Ii',self.uc.mem_read(self.address('music_stream_state'),84))
        return dict(zip(['active','session','local_seid','remote_seid','codec_word','prepared','configured','next_session',
            'queue_epoch','callbacks','enqueued','rejected','consumed','consumer_rejected','cancellations','private_retired',
            'slot0_session','slot1_session','slot2_session','slot3_session','last_error'],values))

    def configure(self,config):
        b0={2:0x20,3:0x10}[config['frequency']]|{0:8,1:4,2:2,3:1}[config['mode']]
        b1={0:0x80,1:0x40,2:0x20,3:0x10}[config['blocks']]|{0:8,1:4}[config['subbands']]|{0:1,1:2}[config['allocation']]
        body=bytes([4,8,1,0,7,6,0,0,b0,b1,2,53]);accepted=self.wire(b'\x10\x03'+body)
        require(accepted['new_sends'][0]['wire_hex']=='1203' and self.stream_state()['active'],'Configuration rejected')
        self.wire(bytes.fromhex('100604'));self.radio_call(0x50b988,[0,MEDIA_LCID,0],PEER,0)
        data=bytearray(12);struct.pack_into('<H',data,8,1008)
        self.radio_call(0x50b3dc,[MEDIA_LCID,0],bytes(data),1);self.radio_call(0x50b1f8,[MEDIA_LCID,0])
        started=self.wire(bytes.fromhex('100704'));require(started['state']==8 and self.queue_state()[4],'Start rejected')

    def deliver(self,data):
        before=self.stream_state()['enqueued'];result=self.radio_call(0x50bbb8,[MEDIA_LCID,0,len(data)],data,1)
        self.uc.mem_write(INPUT,b'\xcc'*4096)
        return result,self.stream_state()['enqueued']-before

    def verify_runtime(self):
        require(bytes(self.uc.mem_read(self.app['extension_base'],self.app['extension_bytes']))==
                (ROOT/self.app['extension_flat']).read_bytes(),'Guest altered its module code')
        require(len(self.app['patch_plan'])==11 and sum(x['bytes'] for x in self.guest_writes)==64,'Guest patch count differs')
        for p in self.app['patch_plan']:
            require(bytes(self.uc.mem_read(p['address'],p['length'])).hex()==p['after'],'Guest hook differs')
        self.verify()


    def runtime_state(self):
        fields=['initialized','channel','decoder_tcb','source_tcb','last_error','source_init_done',
                'source_init_result','source_init_owner','last_status','snapshots']
        return dict(zip(fields,struct.unpack('<4IiIi3I',self.uc.mem_read(self.address('music_runtime_state'),40))))

    def watch_snapshot_reads(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC);lo,n=self.status_range
        if lo<=pc<lo+n and any(a<=address and address+size<=a+length for a,length in self.status_fields):
            require(self.status_irq_depth>0,'Status field read outside IRQ boundary')
            self.status_reads+=1

    def arm_initializer_pause(self):
        # Explicit EVENT INPUT fixture only. No runtime/module/MAIN patch or
        # Python context save/restore. The guest thunk uses original POST;
        # original kernel switches/restores the real source/controller tasks.
        directory=ROOT/'staging/native-music-ready'
        asm=directory/'initializer-event-fixture.S';obj=directory/'initializer-event-fixture.o'
        elf=directory/'initializer-event-fixture.elf';flat=directory/'initializer-event-fixture.bin'
        asm.write_text('.syntax unified\n.cpu arm1176jzf-s\n.arm\n.text\n.global _start\n_start:\n'
            'push {r0,r1,r2,r3,r12,lr}\nldr r0, controller\nmov r1,#1\nldr r12, post\nblx r12\n'
            'pop {r0,r1,r2,r3,r12,lr}\nldr pc, resume\n.align 2\ncontroller: .word '+hex(self.controller)+
            '\npost: .word 0x2fcf44\nresume: .word '+hex(self.address('__wrap_media_coordinator_init'))+'\n')
        subprocess.check_output(['arm-linux-gnueabi-as','-mcpu=arm1176jzf-s','-o',str(obj),str(asm)])
        subprocess.check_output(['arm-linux-gnueabi-ld','-Ttext=0x09400200','-o',str(elf),str(obj)])
        subprocess.check_output(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
        code=flat.read_bytes();require(len(code)<128,'Event fixture exceeded reserved test code space')
        self.uc.mem_write(0x09400200,code);self.uc.ctl_remove_cache(0x09400200,0x09400200+len(code))
        self.init_pause_pending=True

    def stop_tasks(self):
        expected=-22 if self.source_state()['finished_on_stack'] and self.source_state()['init_result'] else 0
        require(self.kernel_call('music_runtime_shutdown')==expected,'Runtime shutdown failed')
        self.yield_all()
        require(self.source_state()['finished_on_stack']==self.worker_state()[6]==1 and
                self.byte(self.source_tcb+22)==self.byte(self.worker_tcb+22)==0x80 and
                not self.source_state()['pending'] and not self.coord()['cancel_pending'] and
                not self.coord()['ticket'] and not self.pipeline()[4] and not self.queue_state()[2],
                'Tasks did not exit and release source work')
        require(self.kernel_call('music_runtime_boot',(self.channel,36,40))==-25 and
                self.kernel_call('source_worker_boot',(40,))==0,'Exited stacks/TCBs reused')
        require(all(self.byte(tcb+22)==2 and not self.word(tcb+4) and t['sends']==t['receives']
                for tcb,t in self.aux_tasks.items()),'Original auxiliary FIFO tasks still active')
        self.verify_runtime();require(self.query_original_api()==self.queries_before,'Original TTS query changed')

    def drain_until(self,predicate,limit=30):
        for _ in range(limit):
            if predicate():return
            if self.half(self.driver_record):self.frame()
            else:self.yield_all()
        require(predicate(),'Native source/cancellation did not finish within frame bound')

    def snapshot(self):
        return {'stream':self.stream_state(),'queue':list(self.queue_state()),'owned':list(self.pipeline()),
                'source_worker':self.source_state(),'coordinator':self.coord(),
                'decoder_worker':list(self.worker_state()),'loaded':self.loaded_report,
                'guest_MAIN_write_bytes':sum(x['bytes'] for x in self.guest_writes),
                'original_TTS40_runtime_preserved':True,'source_events':self.event_trace,
                'original_synchronous_start_returns':self.start_returns,
                'compiled_lifecycle_events':self.coord_events,'original_node_removals':self.original_node_removals,
                'same_call_budget_continuations':self.budget_continuations,
                'virtual_frame_count':len(self.peripheral_chunks),'native_read_count':len(self.native_chunks),
                'runtime_state':self.runtime_state(),'status_irq_reads':self.status_reads,
                'status_captures':self.status_captures,'original_START_entries':self.original_START_entries,
                'initializer_pause_fixture':self.init_pause_events,
                'decoder_native_tcb_state':self.byte(self.worker_tcb+22),
                'source_native_tcb_state':self.byte(self.source_tcb+22)}


def main():
    import unicorn
    from emulate_native_sbc import verify_guard_faults
    from datetime import datetime,timezone
    build_path='staging/native-music-ready/manifest.json';app=json.loads((ROOT/build_path).read_text())
    def hash_path(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
    for path,h in app['source_sha256'].items():require(hash_path(path)==h,'Build source changed '+path)
    guard_fault_controls=verify_guard_faults()
    original=(ROOT/app['original_binary']).read_bytes();app['original_ram_bytes']=struct.unpack_from('<I',original,4)[0]
    app['manifest_path']=build_path
    legacy_paths=['staging/native-media-consumer/manifest.json','staging/native-owned-media/manifest.json',
        'staging/native-playback-control/manifest.json','staging/native-media-coordinator/manifest.json',
        'staging/native-source-worker/manifest.json']
    legacy=list(map(check_manifest,(ROOT/p for p in legacy_paths)))
    stock=NativeImage();reference=Reference()
    tables=json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    cases=[];frames_checked=0;pcm_checked=0
    def config(frequency=2,mode=3):return dict(frequency=frequency,mode=mode,subbands=1,blocks=3,allocation=0,bitpool=32)
    def record(name,m,checks,extra):
        require(all(checks.values()),name+': '+str(checks));m.stop_tasks()
        cases.append({'name':name,'passed':True,'checks':checks,'snapshot':m.snapshot(),'extra':extra})
        print(json.dumps({'case':name,'passed':True}),flush=True)
    def fill(m,frames):
        for i in range(4):require(m.deliver(packet(frames[2*i:2*i+2],i))[1]==1,'Packet not copied')
        m.yield_all();require(m.deliver(packet(frames[8:],4))[1]==1,'Last packet not copied');m.yield_all()
        require(m.pipeline()[4]==4 and m.queue_state()[2]==1 and m.coord()['starts']==1,
                'Four held PCM plus one compressed capacity deferral not established')
    body=bytes.fromhex('1003040801000706000021150235')
    def play_pair(m,sequence):
        cfg=config();m.configure(cfg);frames=reference.encode(cfg,frames=2)
        m.deliver(packet(frames,sequence));m.yield_all()
        m.drain_until(lambda:m.coord()['completed']==1 and not m.coord()['ticket'])
        wanted,_=reference_pcm(reference,frames,44100,2,tables)
        require(b''.join(m.native_chunks)==wanted,'Startup/resume PCM reference differs')
        return wanted
    # Reject invalid initial boot parameters before any owned state/TCB exists.
    m=ReadyMusicVM(stock,legacy,app,boot_runtime=False)
    before=(m.pipeline(),m.worker_state(),m.source_state())
    for args in [(18,36,40),(m.channel,256,40),(m.channel,36,256)]:
        require(m.kernel_call('music_runtime_boot',args)==-25,'Invalid boot accepted')
    require((m.pipeline(),m.worker_state(),m.source_state())==before and not m.kernel_call('music_runtime_status'),
            'Invalid parameters initialized/allocated work')
    require(m.kernel_call('music_runtime_boot',(m.channel,36,40))==0,'Valid boot after rejection failed')
    m.worker_tcb=m.worker_state()[0];m.source_tcb=m.source_state()['tcb'];m.yield_all()
    wanted=play_pair(m,20)
    record('invalid_cold_boot_parameters_leave_state_untouched_then_native_play',m,{
        'no_preboot_state_or_TCB_change':True,'later_native_initialization_and_reference_PCM':True,
        'initializer_return_captured_for_actual_source_owner':m.runtime_state()['source_init_done']==1 and
            m.runtime_state()['source_init_result']==0 and m.runtime_state()['source_init_owner']==m.source_tcb},
        {'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    # TCB construction is not initialization. No synthetic entered/ready seed.
    m=ReadyMusicVM(stock,legacy,app,defer_yield=True);status=m.kernel_call('music_runtime_status');early=m.wire(body)
    require(status==4 and m.source_state()['entered']==0 and not m.runtime_state()['source_init_done'] and
            early['new_sends'][0]['wire_hex']=='13030031' and early['state']==1,
            'Constructed but unentered source accepted configuration')
    m.yield_all();wanted=play_pair(m,21)
    record('constructed_unentered_tasks_reject_config_then_original_init_allows_play',m,{
        'preinit_rejected_before_original_accept':early['state']==1,
        'native_init_then_reference_PCM':m.runtime_state()['source_init_done']==1 and m.runtime_state()['source_init_owner']==m.source_tcb},
        {'status_before_entry':status,'early_reply':early,'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    # Explicit event input at initializer boundary; ORIGINAL POST/context switch
    # suspends source and resumes its waiting controller. No Python CPU restore.
    m=ReadyMusicVM(stock,legacy,app,defer_yield=True);m.arm_initializer_pause();m.kernel_call('_wait')
    require(m.current()==m.controller and len(m.init_pause_events)==1 and m.source_state()['entered']==1 and
            m.source_state()['init_result']==0 and not m.runtime_state()['source_init_done'] and not m.coord()['initialized'],
            'Real initializer boundary not suspended')
    status=m.kernel_call('music_runtime_status');early=m.wire(body)
    require(status==4 and early['new_sends'][0]['wire_hex']=='13030031' and early['state']==1,
            'entry++ and zero init_result falsely treated as ready')
    m.yield_all();require(m.kernel_call('music_runtime_status')==5,'Initializer did not resume/return on source actor')
    wanted=play_pair(m,22)
    record('entered_zero_result_but_initializer_paused_rejects_until_real_return',m,{
        'original_kernel_event_switch_preserves_initializer':len(m.init_pause_events)==1,
        'not_ready_before_full_initializer_return':status==4 and early['state']==1,
        'resumed_actual_owner_result_then_reference_PCM':m.runtime_state()['source_init_done']==1 and
            m.runtime_state()['source_init_owner']==m.source_tcb and m.runtime_state()['source_init_result']==0},
        {'status_during_pause':status,'early_reply':early,'event_fixture_disclosed':True,
         'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    # Foreign prepared source is an explicit INPUT fixture. Execute unchanged
    # original initializer failure and stock task exit; never force init_result.
    m=ReadyMusicVM(stock,legacy,app,defer_yield=True);m.uc.mem_write(m.record+2,b'\x01');m.yield_all()
    failed=m.runtime_state();status=m.kernel_call('music_runtime_status');early=m.wire(body)
    require(failed['source_init_done']==1 and failed['source_init_result']==-25 and
            failed['source_init_owner']==m.source_tcb and m.source_state()['init_result']==-25 and
            m.source_state()['finished_on_stack']==1 and m.byte(m.source_tcb+22)==0x80 and
            status==4 and early['new_sends'][0]['wire_hex']=='13030031',
            'Native initializer failure did not fail closed/preserve result')
    m.uc.mem_write(m.record+2,b'\x00') # Restore ONLY explicit foreign-source fixture.
    record('original_initializer_busy_failure_recorded_actor_exits_configuration_closed',m,{
        'original_failure_not_host_return_stub':failed['source_init_result']==-25,
        'failed_source_exited_original_kernel':m.source_state()['finished_on_stack']==1,
        'no_PCM_source_or_native_start':not m.pipeline()[4] and not m.coord()['starts'] and not m.native_chunks,
        'failed_TCB_module_remain_pinned':m.source_state()['tcb']==m.source_tcb},
        {'native_failure':failed,'status_after_failure':status,'early_reply':early,
         'foreign_prepared_source_is_restored_fixture':True,'frames_reference_checked':0,'PCM_reference_bytes':0})
    # Longer list reaches owned busy rejection; oversized list never enters
    # stock8-bit loop. At255 preserve stock behavior and then verify playback.
    m=ReadyMusicVM(stock,legacy,app);cfg=config();m.configure(cfg)
    m.wire(bytes.fromhex('100904'));entries=m.original_START_entries
    busy=m.wire(b'\x10\x07'+bytes([4])*4)
    require(busy['new_sends'][0]['wire_hex']=='13070431' and busy['state']==4 and m.original_START_entries==entries,
            'Long owned list bypassed busy check')
    m.yield_all();require(m.kernel_call('music_runtime_status')==5,'Empty cancellation not complete')
    before=m.original_START_entries;oversized=m.wire(b'\x10\x07'+bytes([4])*256)
    require(oversized['new_sends'][0]['wire_hex']=='13070411' and oversized['state']==4 and
            m.original_START_entries==before,'Oversized START entered original wrapping loop')
    maxlist=m.wire(b'\x10\x07'+bytes([4])*255)
    require(maxlist['new_sends'][0]['wire_hex']=='1207' and maxlist['state']==8 and
            m.original_START_entries==before+1,'Bounded stock START255 behavior changed')
    frames=reference.encode(cfg,frames=2);m.deliver(packet(frames,23));m.yield_all()
    m.drain_until(lambda:m.coord()['completed']==1 and not m.coord()['ticket'])
    wanted,_=reference_pcm(reference,frames,44100,2,tables)
    record('START_list4_busy_list256_rejected_list255_stock_then_native_play',m,{
        'owned_busy_checked_beyond3':busy['state']==4,
        'oversize_8bit_wrap_avoided_before_stock':oversized['state']==4,
        'maximum_bounded_stock_behavior_and_reference_PCM':maxlist['state']==8 and b''.join(m.native_chunks)==wanted},
        {'busy':busy,'oversized':oversized,'stock_max_list_length':255,
         'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    for priority in (40,28):
        for frequency,mode in [(2,0),(2,3),(3,2)]:
            m=ReadyMusicVM(stock,legacy,app,priority);cfg=config(frequency,mode);m.configure(cfg)
            frames=reference.encode(cfg,frames=10);rate=44100 if frequency==2 else 48000;channels=1 if mode==0 else 2
            wanted,_=reference_pcm(reference,frames,rate,channels,tables);fill(m,frames)
            require(m.kernel_call('music_stream_retire_private',(m.coord()['ticket'],))==-16,
                    'Private retirement bypassed retained source actor')
            m.drain_until(lambda:m.coord()['completed']==5 and not m.coord()['ticket'])
            stereo=b''.join(wanted[i:i+2]*2 for i in range(0,len(wanted),2))
            during=sum(e['kind']=='publication' and e['coordinator_busy']==1 and
                       e['native_condition_waiter']!=0 for e in m.event_trace)
            record('native_tasks_'+str(rate)+'_mode'+str(mode)+'_source_priority'+str(priority),m,{
                'native_PCM_reference':b''.join(m.native_chunks)==wanted,
                'virtual_stereo_reference':b''.join(m.peripheral_chunks)==stereo,
                'source_lifecycle_auto_starts_completes_all5':m.coord()['starts']==m.coord()['completed']==5 and
                    m.source_state()['publications']==m.source_state()['completions']==5,
                'capacity_wakeup_finishes_fifth_packet':not m.pipeline()[4] and not m.queue_state()[2] and m.worker_state()[4]>0,
                'all_native_start_returns_after_original_ACK':len(m.start_returns)==5 and not m.start_return_points,
                'higher_source_priority_publication_during_sync_start':priority!=28 or during>0,
                'no_source_lifecycle_errors':m.coord()['failures']==0,
                'private_retire_rejects_live_actor':True},
                {'rate':rate,'mode':mode,'channels':channels,'source_priority':priority,'frames_reference_checked':10,
                 'packets':5,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted),
                 'virtual_stereo_sha256':sha(stereo),'publication_during_synchronous_start':during})
            frames_checked+=10;pcm_checked+=len(wanted)
    # Suspend initiates real source cancellation. Busy START must reject before
    # original state changes. No host deletes/recycles/advances the coordinator.
    m=ReadyMusicVM(stock,legacy,app);cfg=config();m.configure(cfg);frames=reference.encode(cfg,frames=10)
    fill(m,frames);reads=len(m.guarded_reads);session=m.stream_state()['session']
    paused=m.wire(bytes.fromhex('100904'));busy=m.wire(bytes.fromhex('100704'))
    require(paused['state']==busy['state']==4 and busy['new_sends'][0]['wire_hex']=='13070431',
            'Busy START accepted while old source pending: '+repr((paused,busy)))
    m.yield_all();m.drain_until(lambda:not m.coord()['cancel_pending'] and not m.pipeline()[4])
    require(m.coord()['discarded']==4 and not m.queue_state()[2] and len(m.guarded_reads)==reads,
            'Suspend did not cancel held/pending data without new reads')
    resumed=m.wire(bytes.fromhex('100704'));m.deliver(packet(frames[:2],10));m.yield_all()
    m.drain_until(lambda:m.coord()['completed']==1 and not m.coord()['ticket'])
    wanted,_=reference_pcm(reference,frames[:2],44100,2,tables)
    record('native_Suspend_busy_START_rejection_then_clean_resume',m,{
        'old_source_cleanup_completed':m.coord()['cancelled']==1 and m.coord()['discarded']==4,
        'START_rejected_before_native_state_change':busy['state']==4,
        'native_resume_retains_session_clean_decoder':resumed['state']==8 and m.stream_state()['session']==session and
            b''.join(m.native_chunks)[-len(wanted):]==wanted,
        'pending_compressed_packet_not_decoded':m.stream_state()['consumed']==5},
        {'busy_reply':busy,'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    # Disconnect invalidates captured session immediately, while source actor
    # keeps PCM pinned until original stop and node removal complete.
    m=ReadyMusicVM(stock,legacy,app);m.configure(cfg);frames=reference.encode(cfg,frames=10);fill(m,frames)
    old_session=m.stream_state()['session'];m.radio_call(0x50be1c,[MEDIA_LCID])
    body=bytes.fromhex('1003040801000706000021150235');busy=m.wire(body)
    require(busy['new_sends'][0]['wire_hex']=='13030031' and busy['state']==1 and not m.stream_state()['active'],
            'New configuration accepted before asynchronous old PCM retirement')
    m.yield_all();m.drain_until(lambda:not m.coord()['cancel_pending'] and not m.pipeline()[4])
    m.configure(cfg);m.deliver(packet(frames[:2],11));m.yield_all()
    m.drain_until(lambda:m.coord()['completed']==1 and not m.coord()['ticket'])
    wanted,_=reference_pcm(reference,frames[:2],44100,2,tables)
    record('native_disconnect_busy_config_retirement_reused_LCID_new_session',m,{
        'new_session_not_inferred_from_reused_LCID':m.stream_state()['session']>old_session,
        'old_four_sources_removed_by_source_actor':m.coord()['discarded']==m.coord()['remove_calls']==4,
        'new_reference_PCM':b''.join(m.native_chunks)[-len(wanted):]==wanted,
        'capacity_and_decoder_empty':not m.pipeline()[4] and not m.queue_state()[2]},
        {'busy_reply':busy,'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    # A later CRC error must produce no source publication, then recover to a
    # fresh decoder/FIR reference without restarting the retained OS workers.
    m=ReadyMusicVM(stock,legacy,app);m.configure(cfg);frames=reference.encode(cfg,frames=2)
    bad=bytearray(frames[1]);bad[3]^=1;m.deliver(packet([frames[0],bytes(bad)],0));m.yield_all()
    require(m.pipeline()[9]==1 and not m.pipeline()[4] and not m.coord()['starts'] and
            not m.source_state()['publications'] and not m.native_chunks,'Failed packet published partial PCM')
    m.deliver(packet(frames,1));m.yield_all();m.drain_until(lambda:m.coord()['completed']==1 and not m.coord()['ticket'])
    wanted,_=reference_pcm(reference,frames,44100,2,tables)
    record('native_worker_later_CRC_no_source_prefix_then_reset_recovery',m,{
        'failed_packet_no_partial_source':m.pipeline()[9]==1 and m.source_state()['publications']==1,
        'fresh_reference_after_failure':b''.join(m.native_chunks)==wanted,
        'worker_entered_once_without_restart':m.worker_state()[1]==1 and m.source_state()['entered']==1},
        {'frames_reference_checked':2,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted)})
    frames_checked+=2;pcm_checked+=len(wanted)
    deps=set(app['source_sha256'])|set(legacy_paths)|{'scripts/emulate_native_music_runtime.py','staging/native-music-ready/initializer-event-fixture.S',
        'staging/native-music-ready/initializer-event-fixture.bin',
        'scripts/emulate_native_loaded_playback.py','scripts/emulate_native_source_worker.py',
        'scripts/emulate_native_music_loaded.py','scripts/emulate_native_voice_convert.py',
        'scripts/emulate_native_voice_media.py','scripts/emulate_native_sbc.py'}
    # Transitive frozen event/driver/kernel fixture dependencies are explicit.
    prior=json.loads((ROOT/'evidence/firmware-analysis/native-loaded-playback-emulation.json').read_text())
    deps.update(prior['source_sha256']);deps.add('evidence/firmware-analysis/native-loaded-playback-emulation.json')
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':build_path,'build_manifest_sha256':hash_path(build_path),
        'source_sha256':{p:hash_path(p) for p in sorted(deps)},'emulator_binding_version':unicorn.__version__,
        'emulator_native_version':list(unicorn.uc_version()),'guard_fault_controls':guard_fault_controls,
        'cases':cases,'case_count':len(cases),'all_passed':True,
        'initializer_full_return_owner_result_ready_verified':True,
        'status_sensitive_reads_inside_modeled_IRQ_boundaries':True,
        'initializer_pause_uses_explicit_guest_event_fixture_not_real_IRQ':True,
        'oversize_START_rejected_before_original8bit_counter_loop':True,
        'frames_reference_checked':frames_checked,'PCM_reference_checked_bytes':pcm_checked,
        'original_loader_registered_wire_guard_native_tasks_source_virtual_output_same_VM':True,
        'original_outer_filesystem_exercised_this_stage':False,
        'preceding_frozen_full_outer_guarded_PCM_proof':'evidence/firmware-analysis/native-music-stream-emulation.json',
        'guest_installs11_MAIN_sites64bytes_no_host_postload_dispatch_or_audio_hook_patches':True,
        'host_decoder_step_or_coordinator_pump_notify_register_start_remove_release':False,
        'original_voice40_and_full_runtime_preserved':True,'modules_TCB_stacks_remain_pinned_after_exit':True,
        'actual_package_acceptance_verified':False,'real_phone_speaker_navigation_verified':False,
        'device_io':False,'device_install_candidate':False,
        'previous_checkpoint':json.loads((ROOT/'staging/native-music-ready/previous-checkpoint.json').read_text()),
        'limits':'Linker-wrapped full coordinator initializer return/result/owner, coherent IRQ status, cold invalid-parameter/unentered/actual event-paused initializer/native busy-failure controls and START4/255/256 bounds; original DLL loader/bootstrap/registered endpoint/wire with native kernel decoder/source/central/mixer/timer tasks, synchronous source start/ACK, guarded readers, native completion/removal/release and bounded cancellation. Host prepares inherited kernel/storage/radio/heap/MMU/cache/power/inventory fixtures and virtual peripheral frames. Prior full outer filesystem chain remains frozen; this stage uses original DLL loader read boundary, not full outer/FAT/storage initialization. Original voice40/runtime preserved, no continuous live producer/IRQ/DAC/navigation/phone/hardware/App/menu/install acceptance or safe unload. Mono16k intermediate not final music quality. Concurrent not-yet-entered callbacks, real channel reservation, worker failure rollback/in-flight cancellation and large signaling/fragmentation/jitter remain open.'}
    path=ROOT/'evidence/firmware-analysis/native-music-ready-emulation.json';path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'cases':len(cases),'all_passed':True}),flush=True)

if __name__=='__main__':main()
