#!/usr/bin/env python3
"""Build an independent public-code host decoder with explicit runtime hooks.

No original Garmin code, crosscompiler, device or frozen build is used/changed.
The Linux private header ABI remains; this is not a target-portability proof.
"""
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / 'staging/android-auto-h264-port-v1'
COMMIT = '1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d'
OLD = ROOT / 'staging/android-auto-h264-host-v1'
SOURCE = OLD / ('openh264-' + COMMIT)
ARCHIVE = OLD / ('openh264-' + COMMIT + '.tar.gz')
ARCHIVE_PIN = '3e021e6046dcd79f70fa7842896a85cb2205575ea6170db023c4318fafcb0040'
PORT = ROOT / 'native/aa-h264-port'
WRAPPER = ROOT / 'native/aa-h264'
EXCLUDE = {
    'codec/common/src/WelsTaskThread.cpp', 'codec/common/src/WelsThread.cpp',
    'codec/common/src/WelsThreadPool.cpp', 'codec/common/src/WelsThreadLib.cpp',
    'codec/common/src/crt_util_safe_x.cpp', 'codec/common/src/utils.cpp',
    'codec/common/src/welsCodecTrace.cpp', 'codec/decoder/core/src/wels_decoder_thread.cpp',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def sha(path):
    return digest(path.read_bytes())

def relative(path):
    return str(path.relative_to(ROOT))

def main():
    STAGE.mkdir(parents=True, exist_ok=True)
    attempt = STAGE / 'build-attempts' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    attempt.mkdir(parents=True)
    previous = STAGE / 'build-command-receipts.json'
    if previous.exists():
        (attempt / 'preceding-attempt-receipts.json').write_bytes(previous.read_bytes())
    receipts = []
    lock = threading.Lock()
    def save_receipts():
        (STAGE / 'build-command-receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
        (attempt / 'actual-command-receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
    def run(argv):
        start = time.monotonic()
        argv = [str(a) for a in argv]
        r = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=180)
        record = dict(argv=argv, exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                      elapsed_seconds=time.monotonic() - start)
        with lock:
            receipts.append(record)
            save_receipts()
        if r.returncode:
            raise RuntimeError(json.dumps(record))
        return record

    assert sha(ARCHIVE) == ARCHIVE_PIN
    sources = sorted((SOURCE / 'codec/common/src').glob('*.cpp'))
    sources += sorted((SOURCE / 'codec/decoder/core/src').glob('*.cpp'))
    sources += sorted((SOURCE / 'codec/decoder/plus/src').glob('*.cpp'))
    assert len(sources) == 37
    headers = sorted((SOURCE / 'codec').rglob('*.h'))
    assert EXCLUDE <= {str(p.relative_to(SOURCE)) for p in sources}
    original_pins = {}
    vendor = STAGE / 'vendor'
    with tarfile.open(ARCHIVE) as archive:
        for p in sources + headers:
            name = str(p.relative_to(SOURCE))
            data = p.read_bytes()
            assert archive.extractfile('openh264-' + COMMIT + '/' + name).read() == data, name
            original_pins[relative(p)] = digest(data)
            if name not in EXCLUDE:
                target = vendor / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    timer = vendor / 'codec/common/inc/measure_time.h'
    original_timer = timer.read_text()
    needle = ('  struct timeval tv_date;\n\n'
              '  gettimeofday (&tv_date, NULL);\n'
              '  return ((int64_t) tv_date.tv_sec * 1000000 + (int64_t) tv_date.tv_usec);')
    assert original_timer.count(needle) == 1
    assert original_timer.count('#include "typedefs.h"') == 1
    changed_timer = original_timer.replace('#include "typedefs.h"', '#include "typedefs.h"\n#include "port.h"', 1)
    changed_timer = changed_timer.replace(needle, '  return aa_h264_port_clock_us();', 1)
    timer.write_text(changed_timer)
    overlay = dict(path=relative(timer), original_sha256=digest(original_timer.encode()),
                   overlay_sha256=sha(timer), replaced_exact_body=needle,
                   replacement='  return aa_h264_port_clock_us();', public_copyright_retained=True)
    version = STAGE / 'exports.map'
    version.write_text('{ global: aa_h264_*; local: *; };\n')
    selected = [vendor / p.relative_to(SOURCE) for p in sources if str(p.relative_to(SOURCE)) not in EXCLUDE]
    assert len(selected) == 29
    originals = [PORT / 'port.cpp', PORT / 'port.h', PORT / 'README.md',
                 WRAPPER / 'h264.cpp', WRAPPER / 'h264.h', Path(__file__).resolve()]
    own_pins = {relative(p): sha(p) for p in originals}
    own_copy = attempt / 'own-source-snapshot'
    own_copy.mkdir()
    for p in originals[:5]:
        (own_copy / p.name).write_bytes(p.read_bytes())
    includes = [vendor / 'codec/api/wels', vendor / 'codec/common/inc',
                vendor / 'codec/decoder/core/inc', vendor / 'codec/decoder/plus/inc', own_copy]
    # Public headers include hosted GCC C++ math wrappers; the no-runtime-link
    # contract is verified independently. Do not claim freestanding headers.
    common = ['g++', '-std=c++11', '-fPIC', '-fno-strict-aliasing',
              '-fno-builtin', '-fno-exceptions', '-fno-rtti', '-fcheck-new',
              '-fno-threadsafe-statics'] + ['-I' + str(p) for p in includes]
    run(['g++', '--version'])
    builds = []
    for name, flags in [('ordinary', ['-O2']), ('asan-ubsan', ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        out = STAGE / name
        out.mkdir(exist_ok=True)
        objects = [out / (str(i) + '-' + p.stem + '.o') for i, p in enumerate(selected)]
        commands = [common + flags + ['-fvisibility=hidden', '-c', str(p), '-o', str(obj)]
                    for p, obj in zip(selected, objects)]
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(run, commands))
        port_obj, wrapper_obj = out / 'port.o', out / 'wrapper.o'
        run(common + flags + ['-fvisibility=hidden', '-Wall', '-Wextra', '-Werror', '-c', own_copy / 'port.cpp', '-o', port_obj])
        run(common + flags + ['-fvisibility=default', '-Wall', '-Wextra', '-Werror', '-c', own_copy / 'h264.cpp', '-o', wrapper_obj])
        objects += [port_obj, wrapper_obj]
        so = out / 'libaa-h264-port-host.so'
        link = ['cc', '-shared', '-nostdlib', '-Wl,--no-undefined', '-Wl,-Bsymbolic-functions',
                '-Wl,--version-script=' + str(version)] + objects
        if name == 'asan-ubsan':
            # Instrumentation runtime belongs to the Linux host checker only.
            link += ['-lasan', '-lubsan']
        run(link + ['-o', so])
        undefined = run(['nm', '-D', '--undefined-only', so])['stdout']
        dynamic = run(['readelf', '-d', so])['stdout']
        elf = run(['readelf', '-h', so])['stdout']
        exported = run(['nm', '-D', '--defined-only', so])['stdout']
        if name == 'ordinary':
            assert not undefined.strip(), undefined
            assert '(NEEDED)' not in dynamic, dynamic
        assert 'ELF64' in elf and 'AArch64' in elf
        assert all(line.split()[-1].startswith('aa_h264_') for line in exported.splitlines() if line.strip()), exported
        row = dict(name=name, shared_library=relative(so), shared_library_sha256=sha(so),
                   shared_library_bytes=so.stat().st_size, compile_flags=common[1:] + flags,
                   link_flags=[str(x) for x in link[:6]], object_count=len(objects),
                   undefined_symbols=undefined.splitlines(), dynamic_section=dynamic,
                   exported_symbols=exported.splitlines(), ELF64_AArch64_host=True,
                   no_runtime_imports=name == 'ordinary', sanitizer_runtime_only=name == 'asan-ubsan')
        builds.append(row)
        for obj in objects:
            obj.unlink()
        print(json.dumps({'build': name, 'pass': True, 'sha256': row['shared_library_sha256'],
                          'undefined_count': len(row['undefined_symbols'])}), flush=True)
    for name, pin in original_pins.items():
        assert sha(ROOT / name) == pin, 'Frozen source changed: ' + name
    for name, pin in own_pins.items():
        assert sha(ROOT / name) == pin, 'Own source changed during build: ' + name
    input_pins = dict(own_pins)
    input_pins[relative(version)] = sha(version)
    manifest = dict(schema='android-auto-h264-port-host-build-v1', **{'pass': True},
                    created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    public_commit=COMMIT, archive_path=relative(ARCHIVE), archive_sha256=ARCHIVE_PIN,
                    original_source_sha256=original_pins, own_source_sha256=input_pins,
                    compiled_own_snapshot_sha256={relative(p): sha(p) for p in own_copy.iterdir()},
                    copied_source_sha256={relative(p): sha(p) for p in vendor.rglob('*') if p.is_file()},
                    excluded_cpp=sorted(EXCLUDE), upstream_cpp_count=len(selected), overlay=overlay,
                    builds=builds, receipts_path=relative(STAGE / 'build-command-receipts.json'),
                    receipt_sha256=sha(STAGE / 'build-command-receipts.json'),
                    single_thread_policy=True, logging_discard_policy=True, fatal_OOM_no_recovery=True,
                    retained_Linux_private_header_ABI=True, ordinary_host_only=True,
                    hosted_Linux_headers_required=True, freestanding_target_build=False,
                    original_Garmin_instructions=False, ARM_crosscompile=False, device_IO=False,
                    install_candidate=False, target_ABI_portability_verified=False)
    path = STAGE / 'build.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'pass': True, 'manifest': relative(path), 'manifest_sha256': sha(path),
                      'builds': [{k: b[k] for k in ('name', 'shared_library_sha256', 'no_runtime_imports')}
                                 for b in builds]}, indent=2))

if __name__ == '__main__':
    main()
