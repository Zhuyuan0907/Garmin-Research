#!/usr/bin/env python3
"""Build capacity feedback alongside the validated queue/event worker."""
from datetime import datetime, timezone
import json
from build_native_sbc import ROOT, LOCAL, run, sha

BUILD = ROOT/'staging/native-media-consumer'


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    worker = json.loads((ROOT/'staging/native-media-worker/manifest.json').read_text())
    for path, digest in worker['source_sha256'].items():
        if sha(ROOT/path) != digest: raise ValueError('Worker source changed: '+path)
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler, flags = baseline['commands'][0][0], baseline['commands'][0][1:-4]
    sources = [LOCAL/'media_queue.c', LOCAL/'media_worker.c', LOCAL/'runtime.c', LOCAL/'media_consumer.c']
    original_linker = ROOT/'staging/native-media-worker/worker.ld'
    linker = BUILD/'consumer.ld'
    text = original_linker.read_text()
    if text.count('KEEP(*(.worker_api))') != 1: raise ValueError('Worker linker layout changed')
    linker.write_text(text.replace('KEEP(*(.worker_api))',
                                  'KEEP(*(.worker_api)) KEEP(*(.consumer_api))'))
    commands, objects = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        cmd = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        run(cmd); commands.append(cmd); objects.append(str(obj))
    elf, flat = BUILD/'consumer-armv6.elf', BUILD/'consumer-armv6.bin'
    cmd = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
           '-nostdlib', '-static', '-no-pie',
           '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'consumer.map'),
           '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(cmd); commands.append(cmd)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Undefined consumer symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    attrs = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attrs or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected consumer ISA/runtime')
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    manifest = {**worker, 'updated_utc': datetime.now(timezone.utc).isoformat(),
                'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
                'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
                'flat_binary_bytes': flat.stat().st_size, 'symbols': symbols, 'commands': commands,
                'attributes': attrs, 'segments': segments,
                'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                                  [*sources, LOCAL/'media_queue.h', LOCAL/'media_worker.h', linker,
                                   original_linker, ROOT/'scripts/build_native_media_consumer.py']},
                'original_factory': '0x437764', 'stock_reader': '0x484c05',
                'read_method_offset': 20, 'method_descriptor_bytes': 68,
                'wraps_one_explicit_factory_instance': True,
                'post_selection_refresh_exported': True,
                'refresh_rejects_unrelated_reader_or_format': True,
                'production_post_selection_hook_installed': False,
                'patches_global_factory_or_device': False,
                'limitations': 'Standalone companion ELF, not installed or merged into a VPM. Caller must attach to one original kind17 method instance, explicitly refresh after original selection recreates methods, and detach before allowing new calls to disappear. Refresh accepts only the stock reader or this wrapper with the exact stock format; it does not install a post-selection call-site hook. Neither refresh nor detach establishes in-flight callback quiescence. Wrapper preserves original reader behavior and posts only when pending queue work and capacity exist. Live audio-registration reachability, IRQ entry/exit, ring ownership/navigation policy, cold initialization, package acceptance and hardware remain unverified.'}
    path = BUILD/'manifest.json'
    path.write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'manifest': str(path), 'flat_binary_bytes': flat.stat().st_size,
                      'device_io': False, 'device_install_candidate': False}))


if __name__ == '__main__': main()
