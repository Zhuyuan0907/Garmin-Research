#!/usr/bin/env python3
"""Load the combined prototype using stock instructions, offline only.

Synthetic file callbacks supply DLL bytes. The VPM filesystem, signatures,
new workers/hooks, UI, phone and physical speaker are not exercised here.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR, STUBS, INIT
import emulate_native_loader as loader_module
from emulate_native_loader import simulate
from emulate_native_sbc import Machine, Reference, RESULT_PAGE, PAGE_BYTES
from emulate_native_sbc_component import LoadedMachine

BUILD = ROOT/'staging/native-app-component-emulation'
LOADER_INSTRUCTION_BUDGET = 1000000
LOADER_TIMEOUT_US = 30000000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def simulate_with_app_budget(*args, **kwargs):
    """Extend only this new experiment's loader budget, keeping old code frozen.

    Original and combined controls get identical bounds. No CPU state,
    instruction bytes or loader callbacks are changed by this adapter.
    """
    original_factory = loader_module.Uc
    def factory(*constructor_args, **constructor_kwargs):
        uc = original_factory(*constructor_args, **constructor_kwargs)
        original_start = uc.emu_start
        def start(begin, until, timeout=0, count=0):
            if begin==INIT|1 and count==300000:
                timeout, count = LOADER_TIMEOUT_US, LOADER_INSTRUCTION_BUDGET
            return original_start(begin, until, timeout=timeout, count=count)
        uc.emu_start = start
        return uc
    loader_module.Uc = factory
    try:
        return simulate(*args, **kwargs)
    finally:
        loader_module.Uc = original_factory


class AppMachine(LoadedMachine):
    def __init__(self, emulator, manifest):
        super().__init__(emulator, manifest)
        names = manifest['private_api']
        table = manifest['symbols']['app_component_api']['address']
        values = struct.unpack('<'+str(len(names))+'I', self.uc.mem_read(table, 4*len(names)))
        self.symbols = {}
        for name, address in zip(names, values):
            if address != manifest['symbols'][name]['address']:
                raise ValueError('Private API pointer differs from linked symbol: '+name)
            if not manifest['extension_base'] <= address < manifest['extension_base']+manifest['extension_bytes']:
                raise ValueError('Private API points outside appended code')
            self.symbols[name] = {'address': address}
        self.table_calls = []

    def code(self, uc, address, size, data):
        self.counter += 1

    def call(self, name, args=(), fifth=None):
        if name not in self.manifest['private_api']:
            raise ValueError('Function is not in private API')
        self.table_calls.append(name)
        return Machine.call(self, name, args, fifth)


def check_one(stock, reference, path):
    m = json.loads(path.read_text())
    for field, expected in (('original_binary', 'original_binary_sha256'),
                            ('combined_binary', 'combined_sha256'),
                            ('extension_elf', 'extension_elf_sha256'),
                            ('extension_flat', 'extension_flat_sha256')):
        if sha((ROOT/m[field]).read_bytes()) != m[expected]:
            raise ValueError('Build artifact changed: '+m[field])
    for p, expected in m['source_sha256'].items():
        if sha((ROOT/p).read_bytes()) != expected:
            raise ValueError('Build dependency changed: '+p)
    original = (ROOT/m['original_binary']).read_bytes()
    combined = (ROOT/m['combined_binary']).read_bytes()
    original_uc, baseline = simulate_with_app_budget(stock, 'original_voice', module_bytes=original,
        module_ram_bytes=m['original_ram_bytes'], poison_module_ram=True, return_session=True)
    uc, loader = simulate_with_app_budget(stock, 'extended_voice', module_bytes=combined,
        module_ram_bytes=m['combined_ram_bytes'], poison_module_ram=True, return_session=True)
    a, b = baseline['module_export_registration'][-1], loader['module_export_registration'][-1]
    fields = ('version','export_table','count','targets')
    assert a['count']==40 and all(a[k]==b[k] for k in fields)
    assert baseline['trampolines_verified']==loader['trampolines_verified']
    length = m['original_file_bytes']
    original_runtime = bytes(original_uc.mem_read(IMAGE+12, length-12))
    assert bytes(uc.mem_read(IMAGE+12, length-12))==original_runtime
    tail_length = m['original_ram_bytes']-length
    tail_a = bytes(original_uc.mem_read(IMAGE+length, tail_length))
    tail_b = bytes(uc.mem_read(IMAGE+length, tail_length))
    tail_diff = [{'offset':length+n,'original':x,'extended':y}
                 for n,(x,y) in enumerate(zip(tail_a,tail_b)) if x!=y]
    # Check startup independently of decoder calls. The loader poisons the
    # new memory before startup; the wrapper must clear it without using the
    # descriptor or any original voice state as extension storage.
    symbols = m['symbols']
    app_state = struct.unpack('<Iii', uc.mem_read(symbols['app_component_state']['address'],12))
    assert app_state[0]==1 and app_state[1] in (6,11) and app_state[2]==0
    cleared = []
    for name, size in (('memory_output_control',48),('owned_media_control',52),
                       ('media_queue_control',36),('media_queue_stats',36),
                       ('media_worker_state',32),('playback_state',32),
                       ('coordinator_state',60),('source_worker_state',72)):
        assert not any(uc.mem_read(symbols[name]['address'],size)), name
        cleared.append({'symbol':name,'bytes':size})
    ranges = [(page,4096) for page in m['pcm_pages']]
    ranges += [(symbols['gather']['address'],4096)]
    for prefix in ('queue_payload','worker_stack','source_stack'):
        start,end = (symbols['__'+prefix+'_'+suffix]['address'] for suffix in ('start','end'))
        ranges.append((start,end-start))
    for address,size in ranges:
        assert not any(uc.mem_read(address,size)), (hex(address),size)
        assert IMAGE <= address < address+size <= DESCRIPTOR
    machine = AppMachine(uc,m)
    configs = [dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31),
               dict(frequency=2,mode=3,subbands=1,blocks=3,allocation=0,bitpool=53),
               dict(frequency=3,mode=2,subbands=1,blocks=3,allocation=0,bitpool=53)]
    cases = []
    for n, config in enumerate(configs):
        # The first decode relies on reset performed by the real entry.
        if n: machine.reset()
        frames = reference.encode(config,frames=2)
        expected = reference.decode_stream(frames)
        output = []
        for frame,wanted in zip(frames,expected):
            status,result,pcm,_ = machine.decode(frame)
            assert status==0 and result[0]==len(frame) and pcm==wanted
            output.append(pcm)
        cases.append({'config':config,'frames':len(frames),
            'reference_byte_identical':True,'pcm_sha256':sha(b''.join(output))})
    # Invoke one understood stock API through its original RAM trampoline in
    # both sessions. This is a small query, not full navigation speech.
    original_machine = LoadedMachine(original_uc,m)
    query = int(loader['trampolines_verified'][39]['trampoline'],16)
    queries = []
    for selector,wanted,value in ((0,1,0),(1,0,0xa5a5a5a5)):
        results = []
        for runtime in (machine,original_machine):
            destination = RESULT_PAGE+PAGE_BYTES-4
            runtime.uc.mem_write(destination,struct.pack('<I',0xa5a5a5a5))
            runtime.symbols['_original_query']={'address':query}
            result = Machine.call(runtime,'_original_query',(selector,destination,1))
            results.append((result,struct.unpack('<I',runtime.uc.mem_read(destination,4))[0]))
        assert results[0]==results[1]==(wanted,value)
        queries.append({'slot':39,'selector':selector,'returned':wanted,
                        'output_word':hex(value),'baseline_identical':True})
    assert bytes(uc.mem_read(IMAGE+12,length-12))==original_runtime
    for r in loader['trampolines_verified']:
        assert struct.unpack('<I',uc.mem_read(int(r['storage'],16),4))[0]==int(r['trampoline'],16)
        assert struct.unpack('<I',uc.mem_read(STUBS+r['slot']*12+8,4))[0]==int(r['target_word'],16)
    return {'voice':m['voice_package'],'manifest':str(path.relative_to(ROOT)),
        'combined_sha256':m['combined_sha256'],'appended_code_bytes':m['extension_bytes'],
        'combined_ram_bytes':m['combined_ram_bytes'],
        'remaining_original_reservation_bytes':m['remaining_reservation_bytes'],
        'original_loader':baseline,'combined_loader':loader,
        'loader_instruction_budget':LOADER_INSTRUCTION_BUDGET,'loader_timeout_us':LOADER_TIMEOUT_US,
        'app_state_at_entry_return':list(app_state),'zero_control_regions':cleared,
        'zero_buffer_and_stack_regions':[{'address':hex(a),'bytes':n} for a,n in ranges],
        'all_storage_within_original_3MiB_reservation':True,
        'private_api_pointers_verified':len(m['private_api']),
        'decoder_initialized_by_wrapper':True,'decoder_cases':cases,'decoded_frames':6,
        'original_40_exports_and_trampolines_identical':True,
        'original_file_backed_runtime_after_header_identical':True,
        'original_bss_tail_difference_count':len(tail_diff),'original_bss_tail_differences':tail_diff,
        'original_query_calls':queries,'original_voice_or_tts_slots_changed_by_decoder':False,
        'full_relinked_workers_and_hooks_executed':False,'speech_synthesis_verified':False,
        'vpm_mounted':False,'signature_acceptance_verified':False,
        'device_io':False,'device_install_candidate':False,'passed':True}


def main():
    manifests = sorted(BUILD.glob('*/manifest.json'))
    assert len(manifests)==3
    stock,reference = NativeImage(),Reference()
    voices = [check_one(stock,reference,path) for path in manifests]
    dependencies = {str(Path(__file__).relative_to(ROOT)):sha(Path(__file__).read_bytes())}
    for path in manifests:
        dependencies[str(path.relative_to(ROOT))]=sha(path.read_bytes())
        dependencies.update(json.loads(path.read_text())['source_sha256'])
    for name in ('emulate_native_loader.py','emulate_native_sbc.py',
                 'emulate_native_sbc_component.py','analyze_native_sections.py',
                 'analyze_native_loader.py','analyze_sdp_activation.py'):
        p=ROOT/'scripts'/name;dependencies[str(p.relative_to(ROOT))]=sha(p.read_bytes())
    out = {'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'voices':voices,'voice_count':len(voices),'decoded_frames':18,
        'reference_library_sha256':sha(reference.library_path.read_bytes()),
        'source_sha256':dependencies,'all_passed':True,'device_io':False,
        'device_install_candidate':False,
        'limits':'Synthetic DLL file callbacks bypass actual VPM mount. All original40 exports preserved, one benign query called; not full original speech. Full worker/event/hook pipeline rebuilt at stock reserved RAM but only wrapper/private API/raw decoder executed here. No tasks auto-started or hooks installed, no safe reload/unload, UI, accepted package, real SDP/SEP/phone or hardware speaker test.'}
    path=ROOT/'evidence/firmware-analysis/native-app-component-emulation.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'voices':3,'decoded_frames':18,
                     'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
