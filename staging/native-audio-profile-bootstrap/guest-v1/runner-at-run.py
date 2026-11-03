#!/usr/bin/env python3
"""New bounded original cold profile loop -> read-only diagnostic snapshot.

No full cold boot, native condition construction, Timer, hardware or device IO.
The inherited audio raw mutex services and higher file bindings are fixtures.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util, json, hashlib, struct, mmap, traceback
from pathlib import Path
from datetime import datetime, timezone
import unicorn
from unicorn.arm_const import *
ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
WARM = ROOT/'staging/native-player-warm-probe'
spec = importlib.util.spec_from_file_location('frozen_warm_probe_profile', WARM/'emulate_warm_probe_v3.py')
W = importlib.util.module_from_spec(spec); spec.loader.exec_module(W)
B = W.B; require = W.require
LAST = None

def sha(p): return B.filehash(p)
def rel(p): return str(p.relative_to(ROOT))
def create(p, data):
    with p.open('x') as f:
        json.dump(data, f, indent=2); f.write('\n')

class BootstrapVM(W.ProbeVM):
    def __init__(self, *args):
        self.phase = 'construct_fixture'; self.bootstrap_stores = []
        self.profile_pending = None; self.profile_returns = []
        self.profile_calls = []; self.loop_visits = []
        super().__init__(*args)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.bootstrap_write)

    def bootstrap_write(self, uc, access, address, size, value, unused):
        if self.phase != 'original_audio_setup' or not W.AUDIO <= address < W.AUDIO+W.AUDIO_BYTES:
            return
        require(address+size <= W.AUDIO+W.AUDIO_BYTES and size in (1,2,4,8), 'Native bank store extent')
        row = dict(PC=self.last_pc, opcode_hex=bytes(uc.mem_read(self.last_pc,self.last_size)).hex(),
                   address=address, size=size, value=value, before_hex=bytes(uc.mem_read(address,size)).hex(),
                   CPSR=uc.reg_read(UC_ARM_REG_CPSR),
                   registers={name:uc.reg_read(reg) for name,reg in [('r0',UC_ARM_REG_R0),('r1',UC_ARM_REG_R1),('r4',UC_ARM_REG_R4),('r5',UC_ARM_REG_R5),('r6',UC_ARM_REG_R6),('r7',UC_ARM_REG_R7)]})
        self.bootstrap_stores.append(row)

    def observe(self, uc, address, size, unused):
        if self.phase == 'original_audio_setup':
            if address == 0x269ed6:
                self.loop_visits.append(dict(channel=uc.reg_read(UC_ARM_REG_R4), record=uc.reg_read(UC_ARM_REG_R0),
                                             offset=uc.reg_read(UC_ARM_REG_R1), sentinel=uc.reg_read(UC_ARM_REG_R6)))
            if address == 0x277d26:
                require(self.profile_pending is None, 'Nested profile call')
                channel = uc.reg_read(UC_ARM_REG_R0)
                current_record = 0x034e6f08+channel*0x208
                row = dict(channel=uc.reg_read(UC_ARM_REG_R0), requested=uc.reg_read(UC_ARM_REG_R1),
                           override=uc.reg_read(UC_ARM_REG_R2), SP=uc.reg_read(UC_ARM_REG_SP),
                           LR=uc.reg_read(UC_ARM_REG_LR), before_profile=uc.mem_read(current_record+0x15d,1)[0])
                require(row['LR'] == 0x269ee9, 'Profile caller was not exact cold loop')
                self.profile_pending = row; self.profile_calls.append(row)
            if address == 0x269ee8:
                row = self.profile_pending; require(row is not None, 'Unexpected profile return')
                require(uc.reg_read(UC_ARM_REG_SP) == row['SP'], 'Original profile SP did not return')
                require(uc.reg_read(UC_ARM_REG_CPSR)&32, 'Original profile mode did not return')
                record = 0x034e6f08+row['channel']*0x208
                row = dict(row, actual_return=uc.reg_read(UC_ARM_REG_R0),
                           actual_profile=uc.mem_read(record+0x15d,1)[0], callback=self.word(record+0x160))
                self.profile_returns.append(row); self.profile_pending = None
        return super().observe(uc, address, size, unused)

def main():
    global LAST
    require(unicorn.__version__ == '2.1.4', 'Use isolated Unicorn2.1.4')
    runtime = BASE/'guest-v1'; runtime.mkdir(exist_ok=False)
    contract = json.loads((BASE/'original-cold-profile-sentinel-contract-v1.json').read_text())
    require(contract['all_passed'], 'Static writer contract missing')
    manifest = json.loads((WARM/'strict_marker/manifest.json').read_text())
    require(sha(ROOT/manifest['combined_file']) == manifest['binary_sha256'], 'Compiled diagnostic changed')
    rows = json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
    voice = next(r for r in rows if 'Chinese_Big5_MeiLing' in r['file'])
    sources = dict(contract['source_sha256'])
    sources.update(manifest['source_sha256'])
    for module in list(sys.modules.values()):
        name = getattr(module,'__file__',None)
        if name and Path(name).is_file() and Path(name).is_relative_to(ROOT) and 'site-packages' not in Path(name).parts:
            sources[rel(Path(name))] = sha(Path(name))
    for p in [Path(__file__), BASE/'original-cold-profile-sentinel-contract-v1.json',
              WARM/'strict_marker/manifest.json', ROOT/manifest['combined_file'], ROOT/voice['file'],
              ROOT/'evidence/firmware-analysis/tts-vpm-containers.json',
              ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json']:
        sources[rel(p)] = sha(p)
    create(runtime/'inputs-at-run.json',sources)
    (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    try:
        stock = B.NativeImage()
        with (ROOT/voice['file']).open('rb') as f:
            package = mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
            vm = BootstrapVM(stock,[dict(name=Path(voice['file']).name,data=package)],
                             (ROOT/manifest['combined_file']).read_bytes(),manifest); LAST = vm
            enumerated = vm.enumerate(); record = enumerated['registry'][0]
            p = vm.handles[record['handle']]['pointer']
            outer = vm.typed_outer_file(record['filename'],'valid_unique_repeat')
            before_audio = bytes(vm.uc.mem_read(W.AUDIO,W.AUDIO_BYTES))
            require(before_audio == bytes(W.AUDIO_BYTES), 'Input bank is not declared startup zero')
            vm.phase = 'original_audio_setup'
            vm.call(0x277e20,())
            for channel in range(18): vm.call(0x269f6c,(channel,))
            vm.uc.reg_write(UC_ARM_REG_SP,B.STACK); vm.uc.reg_write(UC_ARM_REG_LR,B.RETURN|1)
            before = vm.instructions
            vm.fragment(0x269ec0,0x269ef2)
            setup_instructions = vm.instructions-before
            require(vm.uc.reg_read(UC_ARM_REG_PC) == 0x269ef2, 'Cold loop did not reach exact hardware boundary')
            require(vm.uc.reg_read(UC_ARM_REG_SP) == B.STACK-24, 'Cold loop partial stack boundary differs')
            require(vm.profile_pending is None and len(vm.profile_returns) == 18, 'Not all18 profile calls returned')
            require([r['channel'] for r in vm.loop_visits] == list(range(18)), 'Original loop channel order differs')
            require(all(r['offset']==0x15d and r['sentinel']==2 and r['record']==0x034e6f08+r['channel']*0x208
                        for r in vm.loop_visits), 'Actual sentinel writer GP inputs differ')
            require(all(r['before_profile']==2 and r['actual_return']==0 and r['actual_profile']==0 and r['callback']==0x277c6b
                        for r in vm.profile_returns), 'Original profile did not install all18 callbacks')
            after_audio = bytes(vm.uc.mem_read(W.AUDIO,W.AUDIO_BYTES))
            expected = W.reference_sample(vm); expected_mask = W.mask(expected)
            require(expected_mask == 0xffe and expected[0]==0 and expected[2]==0x277c6b,
                    'Initialized callback / deliberately cold condition boundary differs')
            vm.phase = 'readonly_diagnostic'
            vm.allow_module_execution = True; vm.loader_input = True
            vm.cpu_input_write(B.IMAGE,b'\xa5'*manifest['combined_ram']); vm.begin_journal(p)
            bss=manifest['symbols']['__marker_bss_start']; end=manifest['symbols']['__marker_bss_end']
            vm.zones.update(outer_file=(W.S.FILE,72),slot_record=(W.S.PARENT,36),private_state=(bss,end-bss),
                            provider=(W.S.PROVIDER,64),driver=(W.S.DRIVER,4),map_entry=(W.S.MAP+198,2),
                            native_audio_bank=(W.AUDIO,W.AUDIO_BYTES))
            vm.zone_before={k:bytes(vm.uc.mem_read(a,n)) for k,(a,n) in vm.zones.items()}
            require(vm.call(0x240498,(0,0))==11, 'Original voice raw return differs')
            state=bytes(vm.uc.mem_read(manifest['symbols']['marker_state'],104))
            require(struct.unpack_from('<I',state,24)[0]==0 and struct.unpack_from('<I',state,52)[0]==expected_mask,
                    'Diagnostic reason/mask differs')
            require(list(struct.unpack_from('<12I',state,56))==expected, 'Diagnostic actual samples differ')
            output=0x0801b000; vm.call(0x2744f6,(0,output))
            observed=bytes(vm.uc.mem_read(output,10))
            require(observed=='WFFE\0'.encode('utf-16le') and len(vm.marker_stores)==5 and len(vm.probe_reads)==83,
                    'Native getter / actual diagnostic reads and stores differ')
            zones=vm.finish_journal()
            require(zones['native_audio_bank']['before_hex']==zones['native_audio_bank']['after_hex'] and not vm.audio_writes,
                    'Diagnostic mutated original audio state')
            baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text())
            original=bytes(vm.uc.mem_read(B.IMAGE,2296496))
            require(B.digest(original[12:])==baseline['original_module_postheader_runtime_sha256'] and
                    B.digest(bytes(vm.uc.mem_read(B.STUBS,480)))==baseline['original40_stubs_sha256'] and
                    B.digest(bytes(vm.uc.mem_read(0xf09364,396)))==baseline['original99_imports_sha256'],
                    'Original TTS runtime/40 stubs changed')
            require(all(sha(ROOT/name)==h for name,h in sources.items()), 'Source changed during run')
            proof=dict(all_passed=True, case_count=1, kind='ROOT exact original cold-profile loop bounded before hardware plus readonly diagnostic',
                       source_sha256=sources, original_loop_visits=vm.loop_visits, full_original_profile_returns=vm.profile_returns,
                       stop_before=0x269ef2, setup_instructions=setup_instructions, total_instructions=vm.instructions,
                       startup_audio_before_hex=before_audio.hex(), initialized_audio_after_hex=after_audio.hex(),
                       original_setup_CPU_stores=vm.bootstrap_stores, actual_native_sample=expected,
                       actual_diagnostic_reads=vm.probe_reads, actual_diagnostic_version_stores=vm.marker_stores,
                       diagnostic_CPU_write_journal=vm.journals, diagnostic_whole_zones=zones,
                       actual_original_getter_UTF16_hex=observed.hex(), tag='WFFE', original_voice_raw_return=11,
                       original40_runtime_unchanged=True, native_condition_and_Timer_constructed=False,
                       physical_UI_or_new_candidate_acceptance_or_speaker_or_App=False, device_IO=False,
                       limits='Original sentinel writes/profile calls execute as cold explicit input. Existing raw audio mutex services, channel field/status wrappers, single TCB, higher file/heap/loader input and platform services remain inherited fixtures. The whole native constructor/full cold boot and hardware tails are excluded. Native condition remains zero; WFFE does not prove warm ownership or playable hardware.',
                       typed_outer_file_fixture=outer, updated_utc=datetime.now(timezone.utc).isoformat())
            create(BASE/'original-profile-bootstrap-v1-proof.json',proof)
            W.S.guard('new original profile loop terminal')
            print(json.dumps(dict(all_passed=True,case_count=1,original_profiles_returned=18,
                                  original_sentinel_stores=18,setup_CPU_stores=len(vm.bootstrap_stores),
                                  tag='WFFE',native_condition=False,device_IO=False)),flush=True)
    except BaseException as error:
        failure=dict(all_passed=False,error=repr(error),traceback=traceback.format_exc(),device_IO=False)
        if LAST: failure['partial']=dict(last_PC=LAST.last_pc,profile_returns=LAST.profile_returns,
                                         original_setup_CPU_stores=LAST.bootstrap_stores,probe_reads=LAST.probe_reads)
        create(runtime/'terminal-failure.json',failure); raise

if __name__=='__main__':main()
