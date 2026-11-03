#!/usr/bin/env python3
"""Independent file-only checks of frozen bounded native queue recordings.

No VM runner is imported; no guest instructions or device APIs are executed.
CPU and host-fixture lists have no common event ordinal. Only zones with one
post-initial event stream are replayed. Mixed stack/heap zones are not promoted
to a chronological whole-zone proof.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import json
import struct
from collections import Counter
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH, ARM_INS_STRD

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'staging/native-player-session-native-call'
OUT = Path(__file__).with_name('native-queue-call-independent-review.json')
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
EXPECTED_MAIN = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
CHANNELS, STRIDE, CHANNEL = 0x34e6f08, 0x208, 8
RECORD = CHANNELS + CHANNEL * STRIDE
CALLBACK = RECORD + 0x160
STACK, PARAMS, ANCHOR, RESULT, ACTOR = 0x880ff00, 0x8a00020, 0x8b00020, 0x8c00020, 0x8820000
LOWER_ARGS = [RECORD + 0x1a8, 0xffff, 10, 12, PARAMS, 0x20c, 0]
HIGH_ARGS = [8, 10, 12, PARAMS, 0x20c, 0, 1]
dependencies = {}
assertion_count = 0


def require(value, reason):
    global assertion_count
    assertion_count += 1
    if not value:
        raise ValueError(reason)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def read_json(path, expected=None):
    digest = sha(path)
    if expected is not None:
        require(digest == expected, 'File hash differs: ' + rel(path))
    dependencies[rel(path)] = digest
    return json.loads(path.read_text())


class ELF:
    """Small independent ELF32 section/symbol reader, with no execution API."""
    def __init__(self, path):
        self.blob = path.read_bytes()
        h = struct.unpack_from('<16sHHIIIIIHHHHHH', self.blob)
        require(h[0][:7] == b'\x7fELF\x01\x01\x01', 'ELF32 little-endian header')
        require(h[1:3] == (2, 40), 'Standalone ET_EXEC ARM image')
        require(h[11] == 40, 'ELF section entry width')
        self.sections = []
        for index in range(h[12]):
            s = struct.unpack_from('<10I', self.blob, h[6] + index * h[11])
            self.sections.append(dict(index=index, name_offset=s[0], type=s[1], flags=s[2],
                address=s[3], offset=s[4], size=s[5], link=s[6], entsize=s[9]))
        strings = self.data(self.sections[h[13]])
        for s in self.sections:
            s['name'] = self.cstring(strings, s['name_offset'])
        self.symbols = {}
        self.undefined = []
        for s in self.sections:
            if s['type'] != 2:
                continue
            require(s['entsize'] == 16, 'ELF symbol entry width')
            names = self.data(self.sections[s['link']])
            for offset in range(s['offset'], s['offset'] + s['size'], 16):
                name, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', self.blob, offset)
                name = self.cstring(names, name)
                if not name:
                    continue  # The mandatory NULL symbol is not an import.
                row = dict(name=name, value=value, size=size, binding=info >> 4,
                    type=info & 15, visibility=other & 3, section_index=shndx)
                self.symbols[name] = row
                if shndx == 0:
                    self.undefined.append(name)
        self.header = dict(type=h[1], machine=h[2], entry=hex(h[4]), flags=hex(h[7]))

    @staticmethod
    def cstring(blob, offset):
        return blob[offset:blob.find(b'\0', offset)].decode('ascii')

    def data(self, section):
        return self.blob[section['offset']:section['offset'] + section['size']]

    def read(self, address, size):
        matches = [s for s in self.sections if s['flags'] & 6 == 6 and
            s['address'] <= address and address + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'ELF opcode lacks unique executable section: ' + hex(address))
        s = matches[0]
        offset = s['offset'] + address - s['address']
        return self.blob[offset:offset + size]


def overlap(address, size, start, length):
    return address < start + length and start < address + size


def region_read(zones, address, length):
    matches = [(start, blob) for start, blob in zones.items()
        if start <= address and address + length <= start + len(blob)]
    require(len(matches) == 1, 'Span lacks unique serialized whole-zone: ' + hex(address))
    start, blob = matches[0]
    return blob[address - start:address - start + length]


def event_bytes(row):
    width = row['size']
    require(width in (1, 2, 4, 8), 'Unexpected CPU store width')
    require(len(bytes.fromhex(row['before_hex'])) == width, 'CPU before-image width')
    return (row['value'] & ((1 << (width * 8)) - 1)).to_bytes(width, 'little')


def replay_single_stream_zones(case):
    initial = {int(k): bytes.fromhex(v) for k, v in case['initial_whole_zones'].items()}
    final = {int(k): bytes.fromhex(v) for k, v in case['final_whole_zones'].items()}
    require(initial.keys() == final.keys(), 'Initial/final whole-zone keys')
    late = [r for r in case['declared_fixture_mutations'] if r['phase'] != 'fixture_setup']
    result = []
    for start, before in initial.items():
        require(len(before) == len(final[start]), 'Initial/final zone sizes')
        cpu = [r for r in case['CPU_store_journal'] if overlap(int(r['address'], 16), r['size'], start, len(before))]
        fixture = [r for r in late if overlap(int(r['address'], 16), len(bytes.fromhex(r['after_hex'])), start, len(before))]
        row = dict(start=hex(start), size=len(before), CPU_events=len(cpu), post_initial_fixture_events=len(fixture),
            before_sha256=hashlib.sha256(before).hexdigest(), after_sha256=hashlib.sha256(final[start]).hexdigest())
        if cpu and fixture:
            row.update(replayed=False, reason='Separate CPU/fixture lists have no common event ordinal.')
        else:
            state = bytearray(before)
            for e in (cpu or fixture):
                address = int(e['address'], 16)
                old = bytes.fromhex(e['before_hex'])
                new = event_bytes(e) if cpu else bytes.fromhex(e['after_hex'])
                require(start <= address and address + len(old) <= start + len(state), 'Replay event within zone')
                offset = address - start
                require(state[offset:offset + len(old)] == old, 'Replay before-image: ' + case['name'] + '/' + hex(address))
                state[offset:offset + len(new)] = new
            require(bytes(state) == final[start], 'Whole-zone replay final mismatch: ' + case['name'] + '/' + hex(start))
            row.update(replayed=True, method='CPU-only' if cpu else 'fixture-only' if fixture else 'unchanged')
        result.append(row)
    return initial, final, result


def validate_stores(case, main, elf, decoded):
    counts = Counter()
    zones = {int(k): bytes.fromhex(v) for k, v in case['initial_whole_zones'].items()}
    for e in case['CPU_store_journal']:
        pc, address = int(e['PC'], 16), int(e['address'], 16)
        raw = bytes.fromhex(e['opcode_hex'])
        require(len(raw) == (2 if e['Thumb'] and len(raw) == 2 else 4), 'Recorded instruction width')
        if 0x50000 <= pc < 0xc00000:
            exact = main[pc - 0x50000:pc - 0x50000 + len(raw)]
            origin = 'exact_MAIN'
        else:
            exact, origin = elf.read(pc, len(raw)), 'compiled_ELF'
        require(raw == exact, 'Store instruction differs from original source: ' + hex(pc))
        key = (pc, bool(e['Thumb']), raw.hex())
        if key not in decoded:
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if e['Thumb'] else CS_MODE_ARM)
            md.detail = True
            instructions = list(md.disasm(raw, pc))
            require(len(instructions) == 1 and instructions[0].size == len(raw), 'One exact writer instruction')
            i = instructions[0]
            require(i.mnemonic.startswith(('str', 'stm', 'swp', 'push', 'vstr', 'vstm', 'stc')), 'Instruction is not a CPU store: ' + hex(pc))
            width = {ARM_INS_STR: 4, ARM_INS_STRB: 1, ARM_INS_STRH: 2, ARM_INS_STRD: 8}.get(i.id)
            decoded[key] = dict(PC=hex(pc), Thumb=bool(e['Thumb']), opcode_hex=raw.hex(),
                origin=origin, instruction=i.mnemonic + ' ' + i.op_str, store_width=width)
        width = decoded[key]['store_width']
        if width is not None:
            require(e['size'] == width, 'Store width differs from original opcode: ' + hex(pc))
        value = event_bytes(e)
        region_read(zones, address, len(value))
        counts[origin] += 1
    for e in case['declared_fixture_mutations']:
        require(len(bytes.fromhex(e['before_hex'])) == len(bytes.fromhex(e['after_hex'])), 'Fixture before/after width')
        region_read(zones, int(e['address'], 16), len(bytes.fromhex(e['after_hex'])))
    return dict(counts)


def push_geometry(case, pc, phase, sp, values):
    events = [r for r in case['CPU_store_journal'] if int(r['PC'], 16) == pc and r['phase'] == phase]
    width = 4 * len(values)
    require(len(events) == len(values), 'Exact native/compiled PUSH event count: ' + hex(pc))
    require([int(r['address'], 16) for r in events] == list(range(sp - width, sp, 4)), 'Original PUSH SP geometry: ' + hex(pc))
    for e, value in zip(events, values):
        if value is not None:
            require(e['value'] & 0xffffffff == value, 'Saved argument/LR in original frame: ' + hex(pc))


def check_fixture_boundaries(case, final, lower_count):
    allowed = {0x3009a0, 0x3008b0, 0x38853c, 0x388804, 0x388b22}
    locks = Counter()
    allocations = []
    for e in case['lower_fixture_calls']:
        entry, args = int(e['entry'], 16), e['args']
        require(entry in allowed and len(args) == 4, 'Exact declared fixture boundary')
        if entry == 0x3009a0:
            locks[args[0]] += 1
        elif entry == 0x3008b0:
            require(locks[args[0]] > 0, 'Fixture release had preceding acquire')
            locks[args[0]] -= 1
        elif entry == 0x388b22:
            require(e['original_BX_LR_executed'] is True, 'Query completion is actual native BX LR')
        elif entry == 0x38853c:
            require(args[:2] == [0x421, 3], 'Lower allocator request is len524 + original overhead533')
            allocations.append(e)
    require(not any(locks.values()), 'All declared fixture mutex counts released')
    require(len(allocations) == lower_count, 'Exactly one fixture allocation per actual lower body')
    for e in case['declared_fixture_mutations']:
        if e['reason'] != 'declared opaque allocation backing and guards':
            continue
        address, blob = int(e['address'], 16), bytes.fromhex(e['after_hex'])
        require(len(blob) == 0x421 + 64 and blob == b'\xa5' * len(blob), 'Opaque backing length and guard fixture')
        pointer, length = address + 32, 0x421
        require(region_read(final, pointer - 32, 32) == b'\xa5' * 32 and
            region_read(final, pointer + length, 32) == b'\xa5' * 32, 'Final opaque canaries unchanged')
        require(region_read(final, pointer + 12, 0x20c) == region_read(final, PARAMS, 0x20c), 'Original memcpy copied owned request payload')
        for r in case['CPU_store_journal']:
            target = int(r['address'], 16)
            require(not overlap(target, r['size'], pointer - 32, 32) and
                not overlap(target, r['size'], pointer + length, 32), 'No recorded CPU writes to opaque canaries')
    return dict(boundary_counts=dict(Counter(e['entry'] for e in case['lower_fixture_calls'])),
        allocator_requests=allocations, mutex_heap_or_scheduler_native=False,
        query_completion_native_BX_LR=True)


def main():
    ordinary_proof = read_json(BASE / 'native-queue-call-emulation-proof.json')
    controls_proof = read_json(BASE / 'queue-reprofile-boundary-proof.json')
    build = read_json(BASE / 'build-v3.json')
    source = dict(ordinary_proof['source_sha256'])
    for p, h in controls_proof['source_sha256'].items():
        require(p not in source or source[p] == h, 'Shared dependency SHA consistent')
        source[p] = h
    for p, expected in source.items():
        require(sha(ROOT / p) == expected, 'Frozen source dependency: ' + p)
    require(source[rel(MAIN)] == EXPECTED_MAIN, 'Exact Taiwan MAIN identity')
    main_bytes = MAIN.read_bytes()
    elf = ELF(ROOT / build['ELF'])
    require(sha(ROOT / build['ELF']) == build['ELF_sha256'], 'Build ELF SHA')
    require(elf.undefined == build['undefined_symbols'] == [], 'No non-NULL undefined symbols')
    require(elf.symbols == build['symbols'], 'Independent ELF symbol parsing matches build')
    require(build['complete_player_image'] is False, 'Bounded queue image does not claim complete player')
    bridge = elf.symbols['mcs_queue_bridge']['value']
    require(bridge == 0x70008f8, 'Exact compiled bridge identity')
    require(main_bytes[0x2704ac - 0x50000:0x2704b4 - 0x50000].hex() == 'f549069aa930b047', 'Original literal load and BLX r6')
    require(struct.unpack_from('<I', main_bytes, 0x270884 - 0x50000)[0] == 0xffff, 'FFFF originates from original270884 literal')
    require(main_bytes[0x277c6a - 0x50000:0x277c76 - 0x50000].hex() == 'ffb50500002083b001908048', 'Lower PUSH9 and SUB12 original bytes')
    require(main_bytes[0x277d20 - 0x50000:0x277d26 - 0x50000].hex() == '200007b0f0bd', 'Lower genuine result/stack-return epilogue')
    require(elf.read(bridge, 4).hex() == '1f402de9', 'Compiled bridge PUSH6')
    require(elf.read(0x7000564, 4).hex() == '60218305', 'Compiled conditional RAM callback store')
    witness = elf.symbols['mcs_native_ownership_snapshot']
    require(witness['size'] == 8 and elf.read(witness['value'], 8).hex() == 'c700e0e31eff2fe1', 'Ownership witness only MVN(-200) / BX LR')
    for folder, runner in [('guest-v1', 'emulate_queue_call.py'), ('boundary-controls-v1', 'emulate_queue_reprofile_controls.py')]:
        inputs = read_json(BASE / folder / 'inputs-at-run.json')
        expected = ordinary_proof['source_sha256'] if folder == 'guest-v1' else controls_proof['source_sha256']
        require(inputs == expected, 'Actual input-ledger matches sealed proof: ' + folder)
        snapshot = BASE / folder / 'runner-at-run.py'
        require(sha(snapshot) == source[rel(BASE / runner)], 'Runner-at-run frozen source matches')
        dependencies[rel(snapshot)] = sha(snapshot)
    receipt = read_json(BASE / 'guest-v1-terminal-receipt.json')
    require(receipt['authoritative_terminal'] is True and receipt['observed_actual_exit_code'] == 0 and
        receipt['actual_terminal_chunk'] == '328887' and receipt['session_id_returned'] is False, 'Recorded six-case terminal receipt')
    controls_receipt = read_json(BASE / 'boundary-controls-terminal-receipt.json')
    actual = controls_receipt['actual_exec_result']
    require(controls_receipt['authoritative_terminal'] is True and actual['exit_code'] == 0 and
        actual['chunk_id'] == 'd83a73' and 'session_id' not in actual, 'Recorded actual controls terminal object')
    erratum = read_json(BASE / 'reprofile-scope-erratum.json')
    require(erratum['all_profile_writes_limited_to_one_slot'] is False, 'Multiple native profile writes erratum retained')
    decoded, cases = {}, []
    require(ordinary_proof['case_count'] == len(ordinary_proof['cases']) == 6, 'Six original cases')
    require(controls_proof['case_count'] == len(controls_proof['cases']) == 2, 'Two additional controls')
    plans = dict(owned_original_queue=(0, 1), original_allocation_failure5=(5, 1), foreign_actor_rejected=(8, 0),
        IRQ_context_rejected=(8, 0), wrong_anchor_rejected=(8, 0), local_Stop_rejected=(8, 0),
        consumed_permit_rejects_second_original_call=(8, 1))
    for item in ordinary_proof['cases'] + controls_proof['cases']:
        case = read_json(ROOT / item['path'], item['sha256'])
        require(case['passed'] is True, 'Sealed case passed field')
        bypass = case['name'] == 'actual_original_reprofile_bypasses_RAM_guard'
        opcode_counts = validate_stores(case, main_bytes, elf, decoded)
        initial, final, replay = replay_single_stream_zones(case)
        lower_args = case['original_lower_seven_arguments'] if bypass else case['original_lower_seven_args']
        returns = case['original_lower_actual_returns'] if bypass else case['original_lower_returns']
        lower_count = 1 if bypass else plans[case['name']][1]
        require(len(lower_args) == len(returns) == lower_count, 'Actual native lower calls and genuine return records')
        for args in lower_args:
            require(args == LOWER_ARGS, 'Actual original lower seven-argument ABI')
        if not bypass:
            expected, count = plans[case['name']]
            require(case['original_high_return'] == expected and case['original_lower_calls'] == count, 'Original case result and call count')
            calls = 2 if case['name'] == 'consumed_permit_rejects_second_original_call' else 1
            require(case['high_calls'] == [HIGH_ARGS] * calls and case['compiled_bridge_calls'] == [LOWER_ARGS] * calls, 'Native high and compiled bridge argument captures')
            require(len(case['original_BLX']) == calls, 'Original BLX callback site captured')
            for e in case['original_BLX']:
                require(e['args'] == LOWER_ARGS and e['target'] == bridge and e['SP'] == STACK - 56 and
                    int(e['PC'], 16) == 0x2704b2 and e['LR'] == 0x27049b, 'Pre-BLX exact args/target/SP and previous mutex LR')
            status = case['compiled_status']
            expected_status = [1, 1, 0, 1, 1, 1, 4, 1, 0, 0, 0, 1] if calls == 2 else \
                [0, 1, 0, 0, 1, 1, 6, 0, 0, 0, 0, 2] if case['name'] == 'local_Stop_rejected' else \
                [1, 0, 0, 1, 1, 1, 4, 1, 0, 0, 0, 1] if count else [0, 1, 0, 0, 1, 1, 4, 1, 0, 0, 0, 1]
            require(status == expected_status, 'Compiled twelve-word local status')
            require(region_read(final, RESULT, 48) == struct.pack('<12I', *status), 'Actual compiled status RAM writes match returned recording')
            if calls == 2:
                require(case['first_actual_original_result'] == 0 and case['original_high_return'] == 8, 'Consumed permit first success / second reject')
            phases = ['first_owned_registration', 'second_owned_registration'] if calls == 2 else ['original_high_registration']
        else:
            require(case['actual_native_reprofile_return'] == 10 and case['compiled_begin_after_reprofile'] == (-201 & 0xffffffff) and
                case['actual_original_high_return'] == 0 and case['compiled_bridge_entries'] == 0, 'Actual profile mode1 bypass control values')
            require(case['native_visits'].get(hex(bridge), 0) == 0, 'Compiled bridge not executed after stock callback restored')
            phases = ['original_call_after_reprofile']
        for phase in phases:
            push_geometry(case, 0x270458, phase, STACK, [8, 10, 12, PARAMS, None, None, None, None, 0x8d00000])
            stack = [e for e in case['CPU_store_journal'] if e['PC'] == '0x27049e' and e['phase'] == phase]
            require([(int(e['address'], 16), e['value']) for e in stack] == [(STACK - 56, PARAMS), (STACK - 52, 524), (STACK - 48, 0)], 'Actual native callback stack arguments STM')
            if not bypass:
                push_geometry(case, bridge, phase, STACK - 56, LOWER_ARGS[:4] + [None, 0x2704b5])
        for e in returns:
            sp = STACK - 56 if bypass else STACK - 80
            return_pc, lr = (0x2704b4, 0x2704b5) if bypass else (0x700092c, 0x700092c)
            expected_r0 = 5 if case['name'] == 'original_allocation_failure5' else 0
            require(e == dict(entry_SP=sp, return_PC=return_pc, entry_LR=lr, args=LOWER_ARGS,
                actual_r0=expected_r0, actual_SP=sp), 'Native lower entry/actual return SP, PC, LR, result')
            require(case['native_visits'].get(hex(return_pc), 0) >= 1 and
                case['native_visits'].get('0x277d24', 0) == 1, 'Original native POP and actual caller continuation visited')
            phase = phases[0]
            push_geometry(case, 0x277c6a, phase, sp, LOWER_ARGS[:4] + [None, None, None, None, lr])
            alloc = [f for f in case['lower_fixture_calls'] if f['entry'] == '0x38853c']
            require(len(alloc) == 1 and alloc[0]['args'][2] == sp - 48 + 4, 'Native allocator output cell relative to genuine lower frame')
        callback_stores = [e for e in case['CPU_store_journal'] if int(e['address'], 16) == CALLBACK]
        require([(e['PC'], e['opcode_hex'], e['value']) for e in callback_stores[:2]] ==
            [('0x277dbc', '2862', 0x277c6b), ('0x7000564', '60218305', bridge)], 'Original profile followed by compiled RAM callback installation')
        require(not any(overlap(int(f['address'], 16), len(bytes.fromhex(f['after_hex'])), CALLBACK, 4)
            for f in case['declared_fixture_mutations']), 'Callback slot never seeded by host fixture')
        if bypass:
            require(len(callback_stores) == 3 and callback_stores[2]['PC'] == '0x277dbc' and
                callback_stores[2]['value'] == 0x277c6b and callback_stores[2]['phase'] == 'actual_original_reprofile', 'Actual native callback restoration store')
            profile = [e for e in case['CPU_store_journal'] if e['phase'] == 'actual_original_reprofile']
            require(len(profile) == erratum['actual_profile_CPU_store_events'] == 46 and
                len(set(e['address'] for e in profile)) == erratum['actual_distinct_store_addresses'] == 44, 'Original reprofile contains multiple RAM/stack writes')
            require(callback_stores[2] == erratum['actual_callback_store'], 'Typed erratum actual callback store matches')
        else:
            require(len(callback_stores) == 2, 'No further callback slot rewrite')
        require(region_read(final, CALLBACK, 4) == struct.pack('<I', 0x277c6b if bypass else bridge), 'Final callback slot matches original/compiled store')
        for i in range(18):
            if i == 8:
                continue
            span = CHANNELS + i * STRIDE
            require(region_read(initial, span, STRIDE) == region_read(final, span, STRIDE), 'Other-channel whole record unchanged')
            require(not any(overlap(int(e['address'], 16), e['size'], span, STRIDE) for e in case['CPU_store_journal']), 'No CPU store to other channel')
        require(case['native_ownership_snapshot'] == -200 and case['native_visits'].get(hex(witness['value']), 0) == 1, 'Originally recorded actual negative ownership witness')
        require(region_read(initial, RESULT + 64, 128) == region_read(final, RESULT + 64, 128), 'Ownership witness output unchanged in serialized whole page')
        require(not any(overlap(int(e['address'], 16), e['size'], RESULT + 64, 128) for e in case['CPU_store_journal']), 'No recorded CPU output write by witness or other phase')
        require(not any(overlap(int(f['address'], 16), len(bytes.fromhex(f['after_hex'])), RESULT + 64, 128)
            for f in case['declared_fixture_mutations']), 'No host witness-output mutation')
        fixture = check_fixture_boundaries(case, final, lower_count)
        require(region_read(initial, PARAMS, 20) == struct.pack('<5I', 1, 16000, 16, ANCHOR, 2), 'Declared request fingerprint')
        require(region_read(initial, 0xf09090, 8) == struct.pack('<2I', ACTOR, 0), 'Declared current TCB / IRQ marker input')
        require(not any('sequence' in e or 'event_index' in e or 'ordinal' in e for e in case['CPU_store_journal'] + case['declared_fixture_mutations']), 'No common chronological event ordinal is serialized')
        require(all(row['replayed'] for row in replay if row['start'] == '0x34e5000'), 'Whole channel bank independently CPU-only replayed')
        cases.append(dict(name=case['name'], path=item['path'], sha256=item['sha256'], all_passed=True,
            CPU_store_count=len(case['CPU_store_journal']), CPU_store_origins=opcode_counts,
            original_lower_arguments=lower_args, genuine_native_lower_returns=returns,
            callback_stores=callback_stores, other_17_channel_records_unchanged=True,
            whole_zones=replay, all_whole_zones_chronologically_reconstructed=all(r['replayed'] for r in replay),
            ownership_witness=-200, witness_output_unchanged=True, fixture_boundaries=fixture))
    source[rel(Path(__file__).resolve())] = sha(Path(__file__).resolve())
    out = dict(all_passed=True, kind='independent frozen-files validation; no new guest execution',
        source_sha256=source, verified_runtime_dependencies=dependencies, assertion_count=assertion_count,
        cases=cases, case_count=len(cases), original_cases=6, additional_boundary_controls=2,
        ELF_header=elf.header, undefined_symbols=elf.undefined, compiled_image_complete_player=False,
        exact_store_instructions=[decoded[k] for k in sorted(decoded)],
        native_lower_ABI=dict(args=LOWER_ARGS, key_source='Original2704AC loads literal270884=FFFF; local compiled ticket5 is separate.',
            high_PUSH_and_locals_bytes=56, compiled_bridge_PUSH_bytes=24, lower_PUSH_and_locals_bytes=48,
            compiled_route_return_PC='0x700092c', compiled_route_entry_and_actual_return_SP='0x880feb0',
            stock_callback_route_return_PC='0x2704b4', stock_callback_route_entry_and_actual_return_SP='0x880fec8'),
        recorded_terminal_receipts_verified=True, new_guest_execution=False, VM_runner_imported=False, device_io=False,
        all_whole_zones_chronologically_reconstructed=False,
        scope_limits=[
            'Initial snapshots occur after declared fixture_setup host writes; these are offline inputs, not physical before-images.',
            'CPU and host-fixture lists lack a common event ordinal. Mixed stack/opaque heap zones are not chronologically replayed.',
            'Single-stream whole channel/compiled BSS/output zones are independently replayed with every before-image and actual final bytes.',
            'Fixture current TCB, SVC CPSR13, local ticket5, resident anchor, native mutex/opaque handle allocation and compiled local wake are explicit.',
            'IRQ rejection is an IRQ-marker fixture in SVC mode; this is not actual hardware IRQ entry or scheduling.',
            'RETURN page zones retains map-time protection3; source later mem_protects this page RX5. Serialized zones is not a final permissions inventory.',
            'Reported store opcodes match unchanged exact MAIN or frozen ELF. Whole final executable RAM bytes are not serialized for independent RX replay.',
            'Witness arguments and return are source-qualified plus result/visit records; a separate witness argument-register/return-PC ledger is absent.',
            'Original reprofile restores stock callback among multiple profile and stack writes. It can bypass the new gate; no global ownership certificate follows.',
            'No native STOP_DONE, complete source-selector/reader lease, audio exclusivity, player App, accepted package, physical device or speaker claim.'
        ],
        native_mutex_heap_wake_scheduler_verified=False, native_STOP_DONE_verified=False,
        complete_native_reader_or_player_or_App_verified=False, physical_audio_verified=False,
        ownership_or_audio_exclusivity_certified=False, reprofile_bypass_observed_in_fixture=True)
    with OUT.open('x') as stream:
        json.dump(out, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(all_passed=True, cases=len(cases), assertions=assertion_count,
        output=rel(OUT), sha256=sha(OUT))))


if __name__ == '__main__':
    main()
