#!/usr/bin/env python3
"""Run the preserving DLL's complete workers/events in the same native VM.

The old harness first prepares stock kernel/output fixtures; its unused
decoder task is explicitly shut down. The original DLL loader then loads the
combined voice into that SAME VM, without resetting live kernel RAM. All
subsequent custom code must execute in the original 3MiB voice reservation.
Incoming AVDTP packets, hardware inventory/heap/power and output frames remain
fixtures. No real VPM mount, UI, registered SEP or physical speaker is tested.
"""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import struct
import subprocess

from unicorn import UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import UC_CPU_ARM_1176
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR, STUBS, INIT
import emulate_native_loader as loader_module
from emulate_native_loader import simulate
import emulate_native_source_worker as source_tests
from emulate_native_source_worker import EventDriver
from emulate_native_source_controller import DRIVER_CALLBACK, CENTRAL_GLOBAL
from emulate_native_memory_completion import CompletionAudio
from emulate_native_memory_notice import check_manifest
from emulate_native_audio_registration import require, sha
from emulate_native_sbc import Reference, OUTPUT_PAGE

BUILD=ROOT/'staging/native-app-component-emulation'


def load_in_existing_vm(machine,app):
    """Adapt only setup/mapping and budgets of the frozen stock loader harness.

    Keep initialized data already supplied by stock startup; copying it again
    would destroy the running kernel. Reuse mapped pages and map only missing
    pages. Actual stock loader/read/bootstrap/export instructions still run.
    """
    uc=machine.uc;stock=machine.stock
    require(bytes(uc.mem_read(0xf09364,99*4))==
            stock.read(stock.runtime_to_load(0xf09364,99*4),99*4),
            'Original99 loader host imports were changed by preparatory fixture')
    original_factory=loader_module.Uc
    saved={name:getattr(uc,name) for name in ('mem_map','mem_write','emu_start','ctl_set_cpu_model')}
    mappings=[];skipped_initial_data=[]
    def mem_map(address,size,perms=7):
        require(address%4096==0 and size%4096==0,'Unaligned loader mapping')
        for page in range(address,address+size,4096):
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in uc.mem_regions()):
                saved['mem_map'](page,4096,perms);mappings.append(page)
    initial=stock.read(0xcb1980,0x7224c)
    def mem_write(address,data):
        if address==0xf00000 and len(data)==len(initial) and data==initial:
            skipped_initial_data.append(len(data));return
        saved['mem_write'](address,data)
    def emu_start(begin,until,timeout=0,count=0):
        if begin==(INIT|1) and count==300000:timeout,count=30000000,1000000
        return saved['emu_start'](begin,until,timeout=timeout,count=count)
    def cpu_model(model):
        require(model==UC_CPU_ARM_1176,'Loader attempted to change CPU model')
    def factory(*args,**kwargs):
        uc.mem_map=mem_map;uc.mem_write=mem_write;uc.emu_start=emu_start
        uc.ctl_set_cpu_model=cpu_model
        return uc
    machine.loading_component=True;loader_module.Uc=factory
    try:
        result,report=simulate(stock,'extended_voice',
            module_bytes=(ROOT/app['combined_binary']).read_bytes(),
            module_ram_bytes=app['combined_ram_bytes'],poison_module_ram=True,return_session=True)
        require(result is uc,'Component was loaded in a different emulator')
    finally:
        loader_module.Uc=original_factory
        for name,value in saved.items():setattr(uc,name,value)
        machine.loading_component=False
    require(skipped_initial_data==[0x7224c],'Original kernel initialized RAM preservation not verified')
    report.update(same_vm_as_native_kernel=True,original_initialized_data_not_recopied=True,
                  newly_mapped_pages=len(mappings),loader_instruction_budget=1000000,
                  loader_timeout_us=30000000)
    return report


def function_ranges(app):
    text=subprocess.check_output(['arm-linux-gnueabi-nm','-S','--defined-only',
        str(ROOT/app['extension_elf'])],text=True)
    result={}
    for line in text.splitlines():
        p=line.split()
        if len(p)==4 and p[2] in ('T','t'):
            result[p[3]]=(int(p[0],16),int(p[1],16))
    return result


class LoadedPlayback(EventDriver):
    def __init__(self,stock,legacy,app):
        self.loading_component=False;self.loaded_playback_ready=False
        self.app=app;self.app_proof={};self.legacy_execution_after_load=[]
        super().__init__(stock,*legacy)
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
        for address,raw in ((self.publication_entry,self.publication_patch),
                           (self.source['completion_entry'],self.completion_patch),
                           (DRIVER_CALLBACK,self.hook_bytes)):
            self.uc.mem_write(address,raw);self.uc.ctl_remove_cache(address,address+len(raw))
        self.source_ready=True;self.hook_ready=True;self.loaded_playback_ready=True
        self.worker_steps=[];self.switch_visits=set();self.kernel_events=[]
        self.dispatch.callback=self.address('media_worker_callback')
        self.dispatch.configure(slot=2,channel_index=11,context_index=1)
        require(self.kernel_call('owned_media_init',(self.channel,))==0,'Relocated owned init failed')
        require(self.kernel_call('media_queue_begin')==0,'Relocated queue begin failed')
        require(self.kernel_call('media_worker_init')==0,'Relocated worker init failed')
        self.worker_tcb=self.kernel_call('media_worker_boot',(36,));self.yield_all()
        require(self.worker_tcb==((self.stack_end-108)&~7) and self.worker_state()[1]==1 and
                self.byte(self.worker_tcb+22)==2,'Relocated decoder did not boot/block on reserved stack')
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.protect_original_voice,
                         begin=IMAGE,end=IMAGE+app['original_ram_bytes']-1)
        self.queries_before=self.query_original_api()

    def observe(self,uc,address,size,data):
        if self.loading_component:return
        if self.loaded_playback_ready:
            require(not any(lo<=address<hi for lo,hi in self.legacy_ranges),
                    'Playback entered an old virtual custom-code image: '+hex(address))
        super().observe(uc,address,size,data)

    def protect_original_voice(self,uc,access,address,size,value,data):
        raise ValueError('Relocated playback wrote into original voice runtime: '+hex(address))

    def query_original_api(self):
        self.native_aliases['_loaded_tts_query']=STUBS+39*12
        rows=[]
        for selector,wanted,value in ((0,1,0),(1,0,0xa5a5a5a5)):
            self.put(OUTPUT_PAGE,0xa5a5a5a5)
            result=self.kernel_call('_loaded_tts_query',(selector,OUTPUT_PAGE,1))
            require((result,self.word(OUTPUT_PAGE))==(wanted,value),'Loaded original TTS query behavior changed')
            rows.append({'selector':selector,'returned':result,'output_word':hex(value)})
        return rows

    def verify(self):
        # Keep original heap/provider/ring/channel guards. The predecessor's
        # separate BSS canaries would overlap legitimate new shared BSS, so
        # use reserved-layout padding guards and full original voice snapshot.
        CompletionAudio.verify(self)
        require(not self.state()['native_calls'] and not self.state()['reader_in_flight'],
                'Relocated private native/reader hold remains')
        for address,size in self.app_guards:
            require(bytes(self.uc.mem_read(address,size))==b'\xa5'*size,'Reserved layout/stack guard changed')
        require(bytes(self.uc.mem_read(IMAGE+12,self.app['original_ram_bytes']-12))==self.voice_runtime_before,
                'Full original voice runtime changed during custom playback')
        for slot,(storage,pointer,target) in enumerate(self.tts_pointers_before):
            require(self.word(storage)==pointer and self.word(STUBS+slot*12+8)==target,
                    'Original40 TTS import/trampoline replaced')

    def verify_event_worker(self):
        require(self.source_state()['entered']==self.source_state()['finished_on_stack']==1 and
                self.byte(self.source_tcb+22)==self.byte(self.worker_tcb+22)==0x80 and
                not self.source_state()['pending'] and not self.coord()['busy'] and
                not self.coord()['ticket'] and not self.coord()['cancel_pending'] and not self.pipeline()[4],
                'Relocated tasks did not finish full source cleanup')
        require(self.kernel_call('source_worker_shutdown')==-22 and
                self.kernel_call('source_worker_cancel')==-22 and
                self.kernel_call('source_worker_boot',(40,))==0,'Exited reserved stack was reused')
        require(len(self.publication_inputs)==len(self.publication_returns)>0 and
                len(self.completion_returns)==self.source_state()['completions']>0,
                'Relocated after-return wrapper bodies skipped')
        require(all(self.byte(tcb+22)==2 and not self.word(tcb+4) and t['sends']==t['receives']
                    for tcb,t in self.aux_tasks.items()),'Original FIFOs/tasks are still active')
        flat=(ROOT/self.app['extension_flat']).read_bytes();off=self.publication_entry-self.app['extension_base']
        patched=flat[:off]+self.publication_patch+flat[off+8:]
        require(bytes(self.uc.mem_read(self.app['extension_base'],len(flat)))==patched and
                bytes(self.uc.mem_read(self.source['completion_entry'],10))==self.completion_patch and
                bytes(self.uc.mem_read(DRIVER_CALLBACK,10))==self.hook_bytes,
                'Relocated code or explicitly installed entry hooks differ')
        for address,size in ((self.source['completion_entry']+10,80),(DRIVER_CALLBACK+10,48)):
            require(bytes(self.uc.mem_read(address,size))==self.stock.read(address,size),
                    'Original displaced-hook continuation body changed')
        self.queries_after=self.query_original_api();require(self.queries_after==self.queries_before,
                    'Original query changed after custom task lifecycle')
        self.source_ready=False;self.hook_ready=False
        for address,raw in ((self.publication_entry,flat[off:off+8]),
                           (self.source['completion_entry'],self.stock.read(self.source['completion_entry'],10)),
                           (DRIVER_CALLBACK,self.stock.read(DRIVER_CALLBACK,10))):
            self.uc.mem_write(address,raw);self.uc.ctl_remove_cache(address,address+len(raw))
        require(bytes(self.uc.mem_read(self.app['extension_base'],len(flat)))==flat,'Restored combined code differs')
        self.verify_central()
        require(self.byte(self.preparatory_worker+22)==0x80,'Preparatory task unexpectedly resumed')
        self.app_proof={'manifest':self.app['manifest_path'],'loaded_report':self.loaded_report,
            'combined_ram_bytes':self.app['combined_ram_bytes'],
            'component_loaded_and_played_in_same_vm':True,'legacy_custom_code_used_after_load':False,
            'old_fixture_decoder_exited_before_component_load':True,
            'decoder_tcb':hex(self.worker_tcb),'source_tcb':hex(self.source_tcb),
            'new_reserved_pcm_pages':[hex(p) for p in self.buffers],
            'new_reserved_stack_ranges':[[hex(self.stack_start),hex(self.stack_end)],
                                         [hex(self.source_stack),hex(self.source_stack_end)]],
            'original_voice_runtime_and40_api_pointers_preserved':True,
            'original_api_queries_before_and_after':self.queries_before,
            'reserved_padding_and_stack_guards_preserved':True,
            'full_original_speech_or_navigation_tested':False,'safe_unload_verified':False,
            'emulator_hooks_restored_after_native_tasks_exited':True,'device_io':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--diagnostic',action='store_true');args=parser.parse_args()
    legacy=list(map(check_manifest,(ROOT/'staging/native-media-consumer/manifest.json',
        ROOT/'staging/native-owned-media/manifest.json',ROOT/'staging/native-playback-control/manifest.json',
        ROOT/'staging/native-media-coordinator/manifest.json',ROOT/'staging/native-source-worker/manifest.json')))
    manifests=sorted(BUILD.glob('*/manifest.json'));require(len(manifests)==3,'Missing combined voice placement')
    stock,reference=NativeImage(),Reference()
    cv=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    cases=((0,0,40),(2,3,28),(2,3,40),(3,2,28),(3,2,40),(0,0,28))
    routes=[];cancelled=[];instances=[];original_driver=source_tests.EventDriver
    try:
        for i,path in enumerate(manifests):
            app=json.loads(path.read_text());app['manifest_path']=str(path.relative_to(ROOT))
            for p,expected in app['source_sha256'].items():require(sha((ROOT/p).read_bytes())==expected,'Dependency changed: '+p)
            require(sha((ROOT/app['combined_binary']).read_bytes())==app['combined_sha256'],'Combined binary changed')
            def factory(*unused):
                m=LoadedPlayback(stock,legacy,app);instances.append(m);return m
            source_tests.EventDriver=factory
            for frequency,mode,priority in cases[2*i:2*i+2]:
                result=source_tests.stream(stock,legacy,reference,tables,frequency,mode,priority)
                result['component']=instances.pop().app_proof;routes.append(result)
                print(json.dumps({'voice':path.parent.name,'rate':result['rate'],
                                  'priority':priority,'same_vm_loaded_playback_passed':True}),flush=True)
                if args.diagnostic:return
            result=source_tests.cancel(stock,legacy,reference)
            result['component']=instances.pop().app_proof;cancelled.append(result)
            print(json.dumps({'voice':path.parent.name,'cancel_passed':True}),flush=True)
    finally:source_tests.EventDriver=original_driver
    prior_path=ROOT/'evidence/firmware-analysis/native-source-worker-emulation.json'
    prior=json.loads(prior_path.read_text())
    deps=dict(prior['dependency_sha256'])
    for p in [Path(__file__),ROOT/'scripts/emulate_native_source_worker.py',
              ROOT/'scripts/emulate_native_loader.py',prior_path,
              ROOT/'scripts/emulate_native_app_component.py',*manifests]:
        deps[str(p.relative_to(ROOT))]=sha(p.read_bytes())
    for path in manifests:deps.update(json.loads(path.read_text())['source_sha256'])
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'routes':routes,'cancellation':cancelled,'all_passed':True,'voices':3,
        'test_matrix_is_rotating_formats_not_full18_cross_product':True,
        'decoded_stream_frames':sum(r['decoded_frames'] for r in routes),
        'source_pcm_bytes':sum(r['pcm_bytes'] for r in routes),
        'virtual_stereo_bytes':sum(r['virtual_stereo_bytes'] for r in routes),
        'source_sha256':deps,'old_compiled_artifacts_changed':False,
        'device_io':False,'device_install_candidate':False,
        'limits':'Three preserving DLL placements loaded by original stock instructions in same VM as original kernel/output tasks; rotating6 format/priority routes plus3 cancels. Old fixture decoder shut down before load; no old virtual custom code executes afterward. Synthetic file callbacks bypass VPM mount/signatures. Original40 APIs and complete original voice RAM preserved; one benign query exercised, not full speech/navigation. All phone packets/SEP slots/peripheral frames/heap/physical inventory/gain/power/arbitration are still fixtures, no actual registered SDP/SEP/phone/hardware UI/App or realtime/seamless playback. Tasks/stacks/TCBs/modules pinned, no reload/unload guarantee; in-flight producer cancellation/wrong-actor/recovery remain open.'}
    path=ROOT/'evidence/firmware-analysis/native-loaded-playback-emulation.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'all_passed':True,'routes':6,'cancels':3}),flush=True)


if __name__=='__main__':main()
