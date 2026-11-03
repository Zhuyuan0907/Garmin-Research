#!/usr/bin/env python3
"""Build an exact standalone scheduled-worker caller of the frozen decoder."""
import hashlib
import json
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-os20-scheduled-decoder-build-v1'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    assert not OUT.exists()
    OUT.mkdir()
    manifest = json.loads((ROOT / 'staging/native-sbc/manifest.json').read_text())
    decoder = ROOT / manifest['elf']
    assert sha(decoder) == manifest['elf_sha256']
    assert manifest['symbols']['garmin_sbc_reset']['address'] == 0x0800223c
    assert manifest['symbols']['garmin_sbc_decode_frame']['address'] == 0x08002284
    source = ROOT / 'native/os20-task-bridge/scheduled_decoder_v1.c'
    linker = ROOT / 'native/os20-task-bridge/scheduled_decoder_v1.ld'
    elf = OUT / 'scheduled-decoder-v1.elf'
    commands = [['arm-linux-gnueabi-gcc', '-mcpu=arm1176jzf-s', '-mthumb',
        '-mfloat-abi=soft', '-Os', '-ffreestanding', '-fno-builtin', '-fno-pie',
        '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
        '-std=c11', '-Wall', '-Wextra', '-Werror', '-nostdlib', '-static', '-no-pie',
        '-Wl,--build-id=none,-T,' + str(linker), str(source), '-o', str(elf)]]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, text=True)
    undefined = subprocess.check_output(['arm-linux-gnueabi-nm', '-u', str(elf)], text=True).strip()
    assert not undefined
    symbols = {}
    for line in subprocess.check_output(['arm-linux-gnueabi-nm', '-n', str(elf)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = dict(address=int(fields[0], 16), type=fields[1])
    assert symbols['scheduled_decode_entry_v1']['address'] == 0x09050000
    sources = {str(p.relative_to(ROOT)): sha(p) for p in
        [source, linker, ROOT / 'native/sbc-prototype/decoder.h',
         ROOT / 'staging/native-sbc/manifest.json', decoder, Path(__file__)]}
    result = dict(all_passed=True, commands=commands, source_sha256=sources,
        ELF=str(elf.relative_to(ROOT)), ELF_sha256=sha(elf), symbols=symbols,
        decoder_ELF=manifest['elf'], decoder_ELF_sha256=manifest['elf_sha256'],
        undefined_symbols=[], device_IO=False, install_candidate=False)
    with (OUT / 'manifest.json').open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps(dict(all_passed=True, ELF=result['ELF'], ELF_bytes=elf.stat().st_size,
        worker_entry='0x09050001', idle_entry=hex(symbols['scheduled_idle_v1']['address'] | 1))), flush=True)


if __name__ == '__main__':
    main()
