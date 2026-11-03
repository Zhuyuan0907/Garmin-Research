#!/usr/bin/env python3
"""Execute the exact stock icon registry, record copies and click consumer.

Only allocation services and the two audio API boundaries are fixtures.
No SQL/GUI/touch event, module acceptance, Bluetooth, DAC or device I/O is
simulated as established. The compiled ARM callback is reached exclusively
through the original three-instruction stock click dispatcher.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import unicorn

from unicorn import UcError, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from emulate_native_sbc import verify_guard_faults
from emulate_native_vpm_filesystem import VpmFilesystem, REGS, STACK, RETURN, require

BUILD = ROOT / 'staging/native-player-menu'
INPUT = 0x08300000
BIND = 0x08301020
MODULE = 0x09080000

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

class MenuVM(VpmFilesystem):
    def __init__(self, stock, build):
        super().__init__(stock, b'')
        self.build = build
        self.raw_allocations = {}
        self.next_raw = 0x08100020
        self.audio = []
        self.events = []
        self.hooks.update({0x3954cc: 'raw_allocate', 0x3954e4: 'raw_allocate',
            0x3954d8: 'raw_allocate', 0x39544c: 'raw_allocate',
            0x386f04: 'raw_free', 0x386f14: 'raw_free', 0x3954f0: 'raw_free',
            0x525f14: 'audio_register_boundary', 0x36b720: 'audio_start_boundary'})
        binary = (ROOT / build['flat_binary']).read_bytes()
        require(sha(ROOT / build['flat_binary']) == build['flat_binary_sha256'], 'Build changed')
        self.uc.mem_map(MODULE, 8192)
        self.uc.mem_write(MODULE, binary)
        self.uc.mem_protect(MODULE, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_protect(MODULE + 4096, 4096, UC_PROT_READ | UC_PROT_WRITE)
        self.code_before = bytes(self.uc.mem_read(MODULE, 4096))
        self.stock_code_regions = [r for r in stock.copies if r['runtime_start'] != 0xf00000]
        require(self.word(0xf11e04+8) == 0, 'Expected uninitialized original registry fixture')
        # Use the original singleton constructor/observer code, not a host-built
        # Registry or hand-written vector. The observer list is initially empty.
        self.registry = self.invoke(0x31590b, ())
        require(self.registry != 0 and self.word(0xf11e04+8) == self.registry,
                'Original registry singleton did not initialize')

    def observe(self, uc, address, size, user):
        name = self.hooks.get(address)
        if name not in ('raw_allocate', 'raw_free', 'audio_register_boundary', 'audio_start_boundary'):
            return super().observe(uc, address, size, user)
        self.visits[address] += 1
        args = [uc.reg_read(r) for r in REGS]
        value = 0
        if name == 'raw_allocate':
            length = args[0]
            require(0 < length < 0x10000, f'Unexpected C++ allocation {length}')
            value = self.next_raw
            self.next_raw += (length + 127) & ~63
            require(self.next_raw < 0x08200000, 'Fixture raw heap exhausted')
            uc.mem_write(value-32, b'\xa5' * (length+64))
            self.raw_allocations[value] = {'length': length, 'freed': False,
                                          'service': hex(address)}
            self.events.append({'allocate': length, 'pointer': hex(value), 'service': hex(address)})
        elif name == 'raw_free':
            pointer = args[0]
            if pointer:
                entry = self.raw_allocations.get(pointer)
                require(entry is not None and not entry['freed'], f'Unknown/double free {pointer:#x}')
                self.verify_guard(pointer, entry)
                entry['freed'] = True
                self.events.append({'free': hex(pointer), 'service': hex(address)})
        elif name == 'audio_register_boundary':
            sp = uc.reg_read(UC_ARM_REG_SP)
            stack = [self.word(sp+n*4) for n in range(3)]
            path = self.wide(args[3])
            require(args[:3] == [9,22,11] and stack == [38,0,0] and path == '0:/Garmin/test.wav',
                    'Compiled callback did not match the original diagnostic WAV API request')
            self.audio.append({'operation': 'register', 'entry': hex(address),
                               'registers': args[:3], 'path': path, 'stack': stack})
            # Opaque fixture return; stock diagnostic flow ignores this result.
            value = 0x2468
        else:
            require(args[:2] == [9,0], 'Unexpected start arguments')
            self.audio.append({'operation': 'start', 'entry': hex(address), 'arguments': args[:2]})
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def invoke(self, address, args, stack=()):
        self.returned = False
        for register, value in zip(REGS, args): self.uc.reg_write(register, value)
        for n,value in enumerate(stack): self.put(STACK+n*4,value)
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        try:
            self.uc.emu_start(address, RETURN+2, count=6000000, timeout=30000000)
        except (UcError, KeyError) as error:
            raise RuntimeError(f'Call {address:#x} failed: {error}; '
                f'PC={self.uc.reg_read(UC_ARM_REG_PC):#x}; last_events={self.events[-8:]}') from error
        require(self.returned, f'Call did not return: PC={self.uc.reg_read(UC_ARM_REG_PC):#x}')
        require(not any(self.mutexes.values()), 'Synthetic mutex left held')
        value = self.uc.reg_read(UC_ARM_REG_R0)
        self.calls.append({'entry': hex(address), 'result': hex(value)})
        return value

    def wide(self, pointer):
        data = bytearray()
        for n in range(128):
            unit = bytes(self.uc.mem_read(pointer + n*2, 2))
            if unit == b'\0\0': return data.decode('utf-16le')
            data += unit
        raise ValueError('Unterminated fixture caption')

    def symbol(self, name): return self.build['symbols'][name]['address']
    def install(self, id, context, caption='Pi Player'):
        self.uc.mem_write(INPUT, caption.encode('utf-16le') + b'\0\0')
        return self.invoke(self.symbol('native_player_menu_install'),
                           (self.registry,id,context,INPUT))
    def records(self):
        begin,end = self.word(self.registry+12),self.word(self.registry+16)
        require(end >= begin and (end-begin)%100 == 0, 'Original vector size invalid')
        return [begin+n*100 for n in range((end-begin)//100)]
    def describe(self, entry):
        label = self.wide(self.invoke(0x3927f5, (entry+8,)))
        return {'id': self.word(entry), 'caption': label,
                'launch': hex(self.word(entry+84)), 'context': self.word(entry+88),
                'type': bytes(self.uc.mem_read(entry+92,1))[0],
                'appearance': hex(self.word(entry+96))}
    def verify_guard(self, pointer, entry):
        length = entry['length']
        require(bytes(self.uc.mem_read(pointer-32,32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(pointer+length,32)) == b'\xa5'*32,
                f'Original record operation crossed allocation {pointer:#x}')
    def finish(self):
        for pointer,entry in self.raw_allocations.items(): self.verify_guard(pointer,entry)
        require(bytes(self.uc.mem_read(MODULE,4096)) == self.code_before, 'Callback code changed')
        for region in self.stock_code_regions:
            require(bytes(self.uc.mem_read(region['runtime_start'],region['size'])) ==
                    self.stock.read(region['load_start'],region['size']),
                    'Original ROM/conditional code region changed')
        for name in ('__aeabi_idiv0','__aeabi_ldiv0'):
            require(self.visits[self.symbol(name)] == 0, 'Arithmetic trap reached')
        return {'allocation_services_are_fixtures': True, 'audio_API_boundaries_are_fixtures': True,
            'stock_entries_executed': {hex(a):self.visits[a] for a in
                (0x31590a,0x3158c8,0x31592a,0x6b9790,0x6a4d66,0x44f6702,
                 0x44f6874,0x39274e,0x39270c,0x392772,0x31649a)},
            'native_state': list(struct.unpack('<6I', self.uc.mem_read(
                                self.symbol('native_player_menu_state'),24))),
            'audio_requests': self.audio, 'allocations': len(self.raw_allocations),
            'live_resident_allocations': sum(not e['freed'] for e in self.raw_allocations.values()),
            'all_allocation_guards_intact': True, 'RX_code_unchanged': True,
            'all_original_code_regions_unchanged': True,
            'fixture_service_entries_reached': {hex(a):self.visits[a] for a in self.hooks
                                              if self.visits[a]}}

def main():
    stock = NativeImage()
    build = json.loads((BUILD/'build.json').read_text())
    image = RuntimeImage(stock)
    functions = {hex(a):trace(image,a,1500) for a in
        (0x31590a,0x3158c8,0x31592a,0x6b9790,0x6a4d66,0x44f6702,
         0x44f6874,0x39274e,0x39270c,0x392772,0x31649a,0x6acf3a)}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in functions.values()), 'Incomplete bounded private-ABI flow')
    dispatcher = functions['0x31649a']
    require([i['instruction'] for i in dispatcher['instructions']] ==
        ['ldr r0, [r1, #0x58]','ldr r1, [r1, #0x54]','bx r1'], 'Unexpected stock dispatcher')
    require(image.word(0x9e0960+16) == 0x31649b and image.word(0x9e0960+20) == 0,
            'Original normal-button click binding differs')
    cases = []
    vm = MenuVM(stock,build)
    require(vm.install(0x7f000001,0x13528000,'Pi 播放器') == 0, 'First registration failed')
    entry = vm.records()[0]
    row = vm.describe(entry)
    require(row['caption'] == 'Pi 播放器' and row['context'] == 0x13528000 and
            row['launch'] == hex(vm.symbol('native_player_menu_activate')), 'Original record copy differs')
    vm.uc.mem_write(INPUT,b'\xcc'*128)
    require(vm.describe(entry)['caption'] == 'Pi 播放器', 'Catalog retained temporary caption pointer')
    vm.invoke(0x31649b,(vm.registry,entry))
    cases.append({'name':'original_registry_copy_and_click','passed':True,
                  'record':row,'caption_survives_input_overwrite':True, **vm.finish()})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}), flush=True)

    vm = MenuVM(stock,build)
    for n in range(12):
        require(vm.install(0x7f000100+n,0xabc000+n,f'Player {n}') == 0, 'Growth registration failed')
    records = vm.records()
    require(len(records) == 12 and vm.visits[0x6a4d66] > 1, 'Original vector growth not exercised')
    for n,entry in enumerate(records):
        row = vm.describe(entry)
        require(row['id'] == 0x7f000100+n and row['caption'] == f'Player {n}' and
                row['context'] == 0xabc000+n and
                row['launch'] == hex(vm.symbol('native_player_menu_activate')),
                'Growth corrupted a copied icon record')
    for n in (0,5,11): vm.invoke(0x31649b,(vm.registry,records[n]))
    cases.append({'name':'original_vector_growth_keeps_callbacks','passed':True,
                  'records':12,'activated_indices':[0,5,11], **vm.finish()})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}), flush=True)

    vm = MenuVM(stock,build)
    require(vm.install(0x7f000200,42) == 0,'Control registration failed')
    before = bytes(vm.uc.mem_read(vm.registry,44))
    appended = vm.visits[0x31592a]
    require(vm.install(0x7f000200,43) == 2, 'Duplicate ID accepted')
    require(vm.install(0,43) == 1 and vm.install(0x80000000,43) == 1 and
            vm.install(0x7f000201,43,'') == 1 and vm.install(0x7f000201,43,'x'*64) == 1,
            'Invalid wrapper input accepted')
    require(bytes(vm.uc.mem_read(vm.registry,44)) == before and vm.visits[0x31592a] == appended,
            'Rejected wrapper inputs mutated the original catalog')
    capacity = vm.word(vm.registry+20)
    vm.put(vm.registry+20,vm.word(vm.registry+16)-4)
    require(vm.install(0x7f000201,43) == 1,'Malformed catalog accepted')
    vm.put(vm.registry+20,capacity)
    cases.append({'name':'wrapper_rejects_duplicate_and_malformed_input','passed':True,
                  'duplicate_result':2,'invalid_result':1,'no_extra_stock_appends':True,**vm.finish()})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}), flush=True)

    vm = MenuVM(stock,build)
    require(vm.install(0x7f000300,0x55aa) == 0,'Binding control failed')
    entry = vm.records()[0]
    vm.uc.mem_write(BIND-32,b'\xa5'*176)
    method,adjust = image.word(0x9e0970),image.word(0x9e0974)
    vm.invoke(0x6acf3b,(BIND,method,adjust,vm.registry),(entry,))
    require([vm.word(BIND+n*4) for n in range(3)] == [0x31649b,0,vm.registry],
            'Original member binding metadata differs')
    copied = vm.describe(BIND+12)
    require(copied == vm.describe(entry),'Original 112-byte button bind copy differs')
    # Tail-call the original consumer on the actual copy made by its original
    # binder. This does not execute the full Widget/GUI/touch dispatch chain.
    vm.invoke(vm.word(BIND),(vm.word(BIND+8),BIND+12))
    vm.invoke(0x399088,(BIND+12,))
    require(vm.describe(entry)['caption'] == 'Pi Player','Bind destruction invalidated registry label')
    require(bytes(vm.uc.mem_read(BIND-32,32)) == b'\xa5'*32 and
            bytes(vm.uc.mem_read(BIND+112,32)) == b'\xa5'*32,'Original binding crossed fixture buffer')
    cases.append({'name':'original_button_member_bind_copy_and_consumer','passed':True,
                  'bind_bytes':112,'binding_destroyed_catalog_retained':True,
                  'full_Widget_touch_chain_executed':False,**vm.finish()})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}), flush=True)

    files = [Path(__file__).resolve(),ROOT/'scripts/emulate_native_vpm_filesystem.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py',
        ROOT/'scripts/analyze_sdp_activation.py',ROOT/'scripts/emulate_native_sbc.py',
        ROOT/'native/player-menu/player_menu.c',ROOT/'native/player-menu/emulation.ld',
        ROOT/'scripts/build_native_player_menu.py', BUILD/'build.json',
        ROOT/build['elf'],ROOT/build['flat_binary'],BUILD/'preflight.json',BUILD/'stock-call-index.json']
    # Pin every local Python dependency imported by this actual run, including
    # loader helpers imported by the inherited VM, rather than only direct imports.
    for module in tuple(sys.modules.values()):
        name = getattr(module,'__file__',None)
        if name:
            path = Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'): files.append(path)
    files = sorted(set(files))
    output = {'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':'staging/native-player-menu/build.json','build_sha256':sha(BUILD/'build.json'),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'all_passed':all(c['passed'] for c in cases),'case_count':len(cases),'cases':cases,
        'emulator_binding_version':unicorn.__version__,
        'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(),'functions':functions,
        'private_ABI':{'registry_bytes':44,'record_bytes':100,'button_bind_bytes':112,
            'record_launch_offset':84,'record_context_offset':88,'record_appearance_offset':96,
            'normal_button_click_metadata':'0x9e0970','dispatcher':'0x31649a'},
        'device_io':False,'device_files_modified':False,'sounds_emitted':False,
        'native_App_installed':False,'rendered_or_touchable_menu_icon':False,
        'accepted_module_loading':False,'direct_phone_Bluetooth_music':False,
        'limits':'Original private registry construction, icon/string copying/growth, '
            'button member bind copy and click consumer execute exact firmware instructions. '
            'Compiled ARM callback requests stock WAV registration/start at recorded API fixtures; '
            'no WAV decode/DAC/audio kernel is executed here. Allocators and mutex/IRQ services '
            'are fixtures. Initial registry has no production built-ins. Blank visual resources '
            'are placeholders. No SQL icon selection, full GUI/touch chain, actual menu entry, '
            'accepted code loading, UI-thread safety, unloading or hardware Bluetooth is proved. '
            'Resident registry labels, callback and resource pointers must stay alive.'}
    path = ROOT/'evidence/firmware-analysis/native-player-menu-emulation.json'
    path.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'cases':len(cases),
                      'all_passed':output['all_passed'],'device_io':False}))

if __name__ == '__main__': main()
