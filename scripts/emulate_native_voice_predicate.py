#!/usr/bin/env python3
"""Run the actual outer voice predicate with explicit cached/storage fixtures."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_vpm_filesystem import VpmFilesystem, REGS, sha, require

PREDICATE = 0x278194
CACHE = 0xf070fc
PLATFORM = 0x0691ce40
LAZY_FLAG = 0x05400000
CODE = ((0x278194, 0x26), (0x102d32, 0x48), (0x462b28, 8),
        (0x04400054, 0x12), (0x04400542, 0xc), (0x044004fc, 0x46))


class PredicateVM(VpmFilesystem):
    def __init__(self, stock, storage_value):
        self.storage_value = storage_value
        self.storage_reads = []
        super().__init__(stock, b'')
        self.uc.mem_map(0x0691c000, 4096)

    def observe(self, uc, address, size, unused):
        if address == 0x2cad0a:
            self.visits[address] += 1
            args = [uc.reg_read(r) for r in REGS]
            key, destination, length, flags = args
            require(key == 0x13a and length == 2 and self.word(flags) == 0,
                    'Unexpected persistent-storage request')
            value = 0xffffffff if self.storage_value is None else 0
            if self.storage_value is not None:
                uc.mem_write(destination, self.storage_value.to_bytes(2, 'little'))
            self.storage_reads.append({'key': key, 'bytes': length,
                                       'fixture_value': self.storage_value,
                                       'return': value})
            uc.reg_write(UC_ARM_REG_R0, value)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        return super().observe(uc, address, size, unused)


def run(stock, name, cached, storage, config, expected):
    vm = PredicateVM(stock, storage)
    vm.uc.mem_write(CACHE, cached.to_bytes(2, 'little'))
    # Only the cached branch of the secondary config provider is tested.
    # Its lazy initialization/backend read is intentionally outside this proof.
    vm.uc.mem_write(LAZY_FLAG, b'\x01')
    vm.uc.mem_write(PLATFORM+0x20, bytes([config]))
    original = {a: bytes(vm.uc.mem_read(a, n)) for a, n in CODE}
    result = vm.call(PREDICATE, ())
    require(result == expected, f'{name}: unexpected predicate result')
    after = int.from_bytes(vm.uc.mem_read(CACHE, 2), 'little')
    require(after == (cached or storage or 0), 'Native cache update differs')
    require(all(bytes(vm.uc.mem_read(a, len(raw))) == raw for a, raw in original.items()),
            'Predicate code was changed during execution')
    if cached:
        require(not vm.storage_reads, 'Cached query read persistent backend')
    else:
        require(len(vm.storage_reads) == 1, 'Uncached query did not read key13A once')
    secondary = (cached or storage) == 0xa1e
    require(bool(vm.visits[0x462b28]) == secondary and
            bool(vm.visits[0x04400054]) == secondary and
            bool(vm.visits[0x04400542]) == secondary and
            bool(vm.visits[0x044004fc]) == secondary,
            'Wrong secondary predicate path')
    require(vm.visits[0x0440051c] == 0 and vm.visits[0x04400534] == 0,
            'Untested secondary lazy initialization was executed')
    return {'case': name, 'cached_u16_fixture': cached,
            'storage_u16_fixture': storage, 'config_byte20_fixture': config,
            'result': result, 'native_cache_after': after,
            'storage_reads': vm.storage_reads,
            'native_visits': {hex(a): vm.visits[a] for a, n in CODE},
            'original_code_unchanged': True, 'all_passed': True}


def main():
    stock = NativeImage()
    cases = [run(stock, *args) for args in (
        ('cached_nonmatching_identifier', 0x1234, None, 0x4c, 1),
        ('cached_matching_identifier_and_L', 0xa1e, None, 0x4c, 0),
        ('cached_matching_identifier_and_other', 0xa1e, None, 0, 1),
        ('uncached_matching_storage_and_L', 0, 0xa1e, 0x4c, 0),
        ('uncached_other_storage_and_L', 0, 0x1234, 0x4c, 1),
        ('uncached_storage_read_failure', 0, None, 0x4c, 1),
    )]
    dependencies = {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__).read_bytes())}
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name and Path(name).resolve().parent == ROOT/'scripts' and name.endswith('.py'):
            path = Path(name).resolve()
            dependencies[str(path.relative_to(ROOT))] = sha(path.read_bytes())
    result = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'source_sha256': dependencies, 'cases': cases, 'all_passed': True,
        'cached_and_uncached_primary_query_executed': True,
        'secondary_ARM_veneer_and_cached_Thumb_provider_executed': True,
        'secondary_lazy_initialization_executed': False,
        'actual_unit_storage_fields_or_predicate_result_verified': False,
        'no_inference_that_key13A_is_HWID': True,
        'device_io': False, 'device_install_candidate': False,
        'limits': 'Six fresh ARM1176 offline VMs run original278194/102D32, secondary ARM veneer462B28 and exact startup-backed conditional Thumb routines. Synthetic primary cache or read-only storage key13A values and cached platform byte20 isolate both predicate outcomes and storage failure. Original code fills the primary cache; secondary cached branch only, not its lazy initializer. Field semantic meaning/live unit data are unknown;1234 is an arbitrary control identifier, not HWID1352. This does not execute either outer enumerator, perform real storage I/O, verify modified VPM acceptance or install an App.'
    }
    path = ROOT/'evidence/firmware-analysis/native-voice-predicate-emulation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'evidence': str(path.relative_to(ROOT)), 'cases': len(cases),
                      'dependencies': len(dependencies), 'all_passed': True}))


if __name__ == '__main__':
    main()
