#!/usr/bin/env python3
"""Inspect our six existing Linux-host AA libraries; never execute/load them.

This is a static artifact inventory, not a Garmin runtime or installation test.
No original firmware, device, compiler, emulator, ldd, or dlopen is invoked.
Only fixed own-artifact paths and their completed evidence pins are accepted.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/android-auto-host-portability-v1.json'
TARGETS = (
    ('tls', 'evidence/android-auto-tls-host-v1.json',
     'staging/android-auto-tls-host-v1/libaa-tls-host-test.so', 'library_sha256'),
    ('control', 'evidence/android-auto-control-host-v1.json',
     'staging/android-auto-control-host-v1/libaa-control-host.so', 'compiled_library_sha256'),
    ('h264', 'evidence/android-auto-h264-host-v1.json',
     'staging/android-auto-h264-host-v1/ordinary/libaa-h264-host.so', None),
    ('video', 'evidence/android-auto-video-host-v1.json',
     'staging/android-auto-video-host-v1/libaa-video-host.so', 'compiled_library_sha256'),
    ('audio', 'evidence/android-auto-audio-host-v1.json',
     'staging/android-auto-audio-host-v1/ordinary/libaa-audio-host.so', None),
    ('interactive', 'evidence/android-auto-interactive-host-v1.json',
     'staging/android-auto-interactive-host-v1/libaa-interactive-host.so', 'compiled_library_sha256'),
)


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def pinned_expected(kind, proof, field):
    if field:
        return proof[field]
    if kind == 'audio':
        return proof['shared_library']['sha256']
    rows = proof['builds']
    matching = [r for r in rows if r['name'] == 'ordinary']
    assert len(matching) == 1
    expected = matching[0]['shared_library_sha256']
    manifest = ROOT / 'staging/android-auto-h264-host-v1/build.json'
    d = json.loads(manifest.read_text())
    matching = [r for r in d['builds'] if r['name'] == 'ordinary']
    assert len(matching) == 1
    assert digest(manifest) == proof['build_manifest_sha256']
    assert matching[0]['shared_library_sha256'] == expected
    return expected


def category(symbol):
    if symbol.startswith('aa_'):
        return 'own_component_ABI'
    if symbol.startswith(('pthread_', 'sem_')) or symbol in ('sched_getaffinity', '__sched_cpucount', 'usleep'):
        return 'POSIX_synchronization_or_scheduling'
    if symbol in ('clock_gettime', 'time', 'gettimeofday', 'localtime', 'strftime'):
        return 'clock_or_calendar'
    if symbol in ('malloc', 'calloc', 'realloc', 'free') or symbol.startswith(('_Zn', '_Zd')):
        return 'allocation_and_CPP_new_delete'
    if symbol.startswith(('_ZTVN10__cxxabiv', '__cxa_', '__gxx_', '_Unwind_')):
        return 'CPP_runtime_or_unwind'
    if symbol in ('fopen', 'fclose', 'fprintf', 'fflush', 'fseek', 'fwrite', 'stderr'):
        return 'stdio_or_default_logging'
    if symbol.startswith(('_ITM_', '__gmon_')):
        return 'optional_toolchain_weak_runtime'
    return 'other_libc_math_or_runtime'


def inspect(kind, proof_name, library_name, field):
    p, lib = ROOT / proof_name, ROOT / library_name
    proof = json.loads(p.read_text())
    assert proof['pass'] is True
    expected = pinned_expected(kind, proof, field)
    assert digest(lib) == expected, (kind, 'artifact differs from tested evidence')
    assert lib.stat().st_size < 8 * 1024 * 1024
    with lib.open('rb') as handle:
        magic = handle.read(20)
    assert magic[:4] == b'\x7fELF'
    receipts = []
    raw = {}
    for label, argv in (
        ('header', ['readelf', '-W', '-h', str(lib)]),
        ('dynamic', ['readelf', '-W', '-d', str(lib)]),
        ('imports', ['nm', '-D', '--undefined-only', str(lib)]),
        ('sections', ['size', '-B', str(lib)]),
    ):
        r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=15)
        assert r.returncode == 0 and len(r.stdout) < 200000
        receipts.append({'argv': argv, 'exit_code': r.returncode,
                         'stdout': r.stdout, 'stderr': r.stderr})
        raw[label] = r.stdout
    header = dict(re.findall(r'^\s*(Class|Data|OS/ABI|Type|Machine):\s*(.+)$', raw['header'], re.M))
    assert header['Class'] == 'ELF64' and header['Machine'] == 'AArch64'
    assert magic[4] == 2 and magic[18:20] == b'\xb7\x00'
    needed = re.findall(r'\(NEEDED\).*\[(.+?)\]', raw['dynamic'])
    imports = []
    for line in raw['imports'].splitlines():
        parts = line.strip().split()
        assert len(parts) == 2 and parts[0] in ('U', 'w', 'v'), line
        binding, name = parts
        symbol = name.split('@', 1)[0]
        imports.append({'symbol': symbol, 'versioned_name': name,
                        'weak': binding != 'U', 'category': category(symbol)})
    row = raw['sections'].splitlines()[-1].split()
    assert len(row) >= 6
    sizes = dict(zip(('text', 'data', 'bss', 'decimal_total'), map(int, row[:4])))
    assert sizes['decimal_total'] == sizes['text'] + sizes['data'] + sizes['bss']
    return {'proof': {'path': proof_name, 'sha256': digest(p)},
            'artifact': {'path': library_name, 'sha256': expected,
                         'bytes': lib.stat().st_size},
            'header': header, 'direct_DT_NEEDED': needed,
            'undefined_dynamic_symbols': imports, 'GNU_size_bytes': sizes,
            'static_dependency_only': True, 'runtime_call_reachability_verified': False,
            'actual_inspection_receipts': receipts}


def main():
    objects = {kind: inspect(kind, proof, lib, field)
               for kind, proof, lib, field in TARGETS}
    h264 = objects['h264']
    imports = {r['symbol'] for r in h264['undefined_dynamic_symbols']}
    assert {'pthread_create', 'sem_wait', 'malloc', 'gettimeofday', '_Unwind_Resume'} <= imports
    assert {'libstdc++.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libc.so.6'} <= set(h264['direct_DT_NEEDED'])
    d = {'schema': 'android-auto-host-portability-static-v1',
         'updated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'pass': True, 'artifact_count': len(objects), 'objects': objects,
         'source_sha256': {str(Path(__file__).resolve().relative_to(ROOT)): digest(Path(__file__).resolve())},
         'conclusions': [
             'All six currently tested artifacts are ELF64 AArch64 shared objects; none is an installable ARMv6 Garmin module.',
             'The tested codec still imports POSIX synchronization, allocation, clocks, logging and C++ runtime facilities despite its configured zero decoder threads.',
             'Imported functions and whole-archive membership do not prove that every symbol executes in the selected decode path.',
             'Removing Linux link dependencies requires a real platform port and compatible loader/runtime, not renaming a shared library or copying it into USB storage.',
         ],
         'limitations': [
             'No original Garmin executable is opened or executed; no firmware or devices are queried.',
             'GNU size reports static sections, not codec heap/stack peak or performance.',
             'Composite host artifacts include test helpers; this is not an exact production link closure.',
             'No architecture conversion, platform ABI, native loader acceptance or physical CPU identification is proved.',
             'ELF OS/ABI System V alone does not identify an operating system; versioned GLIBC imports and observed Linux builds support the host dependency conclusion.',
         ],
         'device_IO': False, 'original_Garmin_code_executed': False,
         'native_guest_executed': False, 'ARM_crosscompile': False,
         'current_phone_session_verified': False, 'install_candidate': False,
         'native_Android_Auto_or_Google_Maps_running': False, 'full_goal_complete': False}
    OUT.write_text(json.dumps(d, indent=2) + '\n')
    print(json.dumps({'pass': True, 'artifact_count': len(objects),
                      'proof': str(OUT.relative_to(ROOT)), 'sha256': digest(OUT),
                      'ELF64_AArch64_only': True, 'Garmin_install_candidate': False,
                      'device_IO': False}))


if __name__ == '__main__':
    main()
