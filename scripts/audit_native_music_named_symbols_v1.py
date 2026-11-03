#!/usr/bin/env python3
"""Finite FILE-only comparison; never imports producers or reads target binaries."""
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-named-symbol-binding-readonly-20261007-v1'
PINS = {
    'v2-metadata.json.gz': (75903, 'ee7d464e806cfc2d2f506989ffc7b2d7b30c6ce5e2d5f068b95f303cc6b76f75'),
    'v3-metadata.json.gz': (77732, '9790e7d3951d9dd1210212fbb303c381eb8c9b6f64ebe7f80746ab074fe91677'),
    'interfaces-metadata.json.gz': (39280, 'c3c77791bec2b7267d17f17f10b21d2260c7581f07c7b87c2a42792426d38521'),
    'v2-producer.py.gz': (10080, '624bc81001a23fbdd4e8ea4da22b8a92e45aca778c44342a6bab69c0b1ae0c85'),
    'v3-producer.py.gz': (10112, '86d537b1ad25299cfa033decea229c969c72ecea7dd82b92a4c0dc033be8497d'),
}
C_PIN = 'ec5907cb0543716539e375a3be24923ecf307ecf5c530a8000464a5ecdd6984f'
H_PIN = 'a10af2e7436530c263e0ba429442514300e3e8d3cd9f28d552905af8ab89136b'
OBJECT = 'staging/native-player-remote-pause/source-build-v2/18-ui_music_control.o'
OBJECT_PIN = '3f31e6ad02428b44a17e556496c1190bd3148a2327b0fd8dcf3653ea3f6ec10a'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    captures = {}
    for name, (size, pin) in PINS.items():
        with gzip.open(OUT / name, 'rb') as stream:
            raw = stream.read(size + 1)
        require(len(raw) == size and sha(raw) == pin, 'Own captured input: ' + name)
        captures[name] = raw
    builds = {v: json.loads(captures[v + '-metadata.json.gz']) for v in ('v2', 'v3')}
    comparison = json.loads(captures['interfaces-metadata.json.gz'])
    table = comparison['table_comparison']
    roles = {}
    for kind, field in (('public', 'public_function_roles'), ('old_adapter', 'old_function_roles')):
        for role in table[field]:
            entry = roles.setdefault(role['symbol'], {'symbol': role['symbol'], 'signature': role['signature'], 'roles': []})
            require(entry['signature'] == role['signature'], 'Common function signature: ' + role['symbol'])
            entry['roles'].append({'table': kind, 'role': role['role'], 'offset': role['byte_offset']})
    require(len(roles) == 12 and not table['cast_compatible'], 'Twelve unique named functions; no table cast')
    absent = {'umc_status_read', 'umc_source_started', 'umc_cleanup_returned', 'umc_kick'}
    rows = []
    for name, role in roles.items():
        row = dict(role)
        row['declared_build_symbols'] = {v: builds[v]['symbols'].get(name) for v in builds}
        for v, symbol in row['declared_build_symbols'].items():
            require((symbol is None) == (name in absent), 'Expected declared-symbol presence: ' + v + '/' + name)
            if symbol is not None:
                require(symbol['name'] == name and symbol['type'] == 2 and symbol['binding'] == 1
                        and symbol['section_index'] == 2 and symbol['visibility'] == 0,
                        'Declared STT_FUNC metadata: ' + v + '/' + name)
        if name not in absent:
            a, b = [row['declared_build_symbols'][v] for v in builds]
            require(b['value'] - a['value'] == 1500 and a['size'] == b['size'], 'Per-build relocation declaration: ' + name)
        rows.append(row)
    producers = []
    for v, build in builds.items():
        pins = build['source_sha256']
        require(pins['native/ui-music-control-prototype/ui_music_control.c'] == C_PIN
                and pins['native/ui-music-control-prototype/ui_music_control.h'] == H_PIN
                and pins[OBJECT] == OBJECT_PIN and OBJECT in build['reused_relocatable_objects'], 'Consistent declared reused controller')
        require(build['symbols'].get('ui_music_control_api') is None, 'Public table getter absent from declaration')
        tree = ast.parse(captures[v + '-producer.py.gz'].decode())
        matches = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'symbols' for t in n.targets)]
        require(len(matches) == 1 and isinstance(matches[0].value, ast.DictComp), 'Producer dictionary construction')
        n = matches[0]
        expression = ast.get_source_segment(captures[v + '-producer.py.gz'].decode(), n)
        require(n.lineno == 120 and expression == "symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}",
                'Nonempty named defined symbols without a name whitelist')
        producers.append({'version': v, 'symbol_assignment_line': n.lineno, 'symbol_assignment': expression,
                          'producer_imported_or_executed': False, 'metadata_symbol_count': len(build['symbols']),
                          'controller_object_reused': True, 'controller_object_declared_sha256': OBJECT_PIN,
                          'controller_C_declared_sha256': C_PIN, 'controller_header_declared_sha256': H_PIN})
    ledger = {
        'schema': 'native-music-named-symbol-binding-FILE-v1', 'scope': 'Own fixed gzip captures of JSON and inert host-builder text only',
        'rows': rows, 'unique_requested_functions': 12, 'present_declared_functions_per_build': 8,
        'absent_from_both_declared_symbol_maps': sorted(absent), 'public_getter_absent_from_both_maps': 'ui_music_control_api',
        'producer_review': producers, 'retention_or_linker_root_cause_established': False,
        'declared_presence_is_fresh_ELF_or_callable_mode_proof': False,
        'mapping_symbol_name_dictionary_preserves_all_intervals': False,
        'old_addresses_reusable_for_new_version': False,
        'inherited_C_observation': {'fresh_C_read_this_scope': False, 'sha256': C_PIN,
            'externally_defined_nonstatic_noninline_unconditional': {'umc_kick': 227, 'umc_status_read': 229,
                'umc_source_started': 313, 'umc_cleanup_returned': 334},
            'getter_lines': [349, 354], 'observer': '/root/continuous_music_binding cached prior captured C'},
        'conclusion': 'The two saved declarations cannot populate either complete controller table by named functions. Verify retention/getter and per-image typed callability before an adapter; do not invent addresses or cast tables.',
        'root_capture_accounting': {'fresh_original_metadata_bytes': 192915, 'fresh_inert_producer_text_bytes': 20192,
            'current_reviewer_reads_only_own_captures': True, 'source_C_H_binary_or_object_fresh_reads': 0},
        'incidental_host_query_failure': {'tool_chunk_id': '2eba18', 'exit_code': 1,
            'reason': 'new_compiles scalar was incorrectly treated as a list', 'corrected_capture_only_chunk_id': '138a53',
            'corrected_exit_code': 0, 'native_or_device_side_effect': False},
        'native_compile_execution_guest_original_ASM_MAIN_binary_RAM_source_changes': False,
        'device_BT_DBUS_audio_or_interrupted_guest_retry': False,
        'native_ownership_STOP_DONE_App_direct_phone_speaker_or_install_verified': False,
        'native_install_ready': False, 'full_goal_complete': False,
    }
    write('symbol-binding-ledger.json', ledger)
    write('proof.json', {'STOP': True, 'all_assigned_FILE_checks_passed': True, 'function_rows': len(rows),
        'present_per_declared_build': 8, 'absent_per_declared_build': 4, 'public_getter_missing_from_maps': True,
        'metadata_pins': {name: {'decompressed_bytes': n, 'sha256': pin} for name, (n, pin) in PINS.items()},
        'no_producer_or_native_execution': True, 'device_IO': False, 'native_install_ready': False, 'full_goal_complete': False})
    names = list(PINS) + ['capture-tool-receipts.json', 'symbol-binding-ledger.json', 'proof.json']
    seal = {'files': [], 'script': {'path': str(Path(__file__).relative_to(ROOT)), 'sha256': sha(Path(__file__).read_bytes())},
            'STOP': True, 'native_install_ready': False}
    for name in names:
        p = OUT / name
        raw = p.read_bytes()
        require(p.stat().st_mode & 0o777 == 0o444, 'Sealed read-only output')
        seal['files'].append({'name': name, 'bytes': len(raw), 'sha256': sha(raw), 'mode': '0444'})
    write('sealed-files.json', seal)
    print(json.dumps({'all_assigned_FILE_checks_passed': True, 'STOP': True, 'ledger': str((OUT / 'symbol-binding-ledger.json').relative_to(ROOT)),
                      'present': 8, 'absent': 4, 'getter_absent': True, 'native_execution': False, 'device_IO': False}))


if __name__ == '__main__':
    main()
