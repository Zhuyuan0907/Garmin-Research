#!/usr/bin/env python3
"""Run original backed-up TTS module bootstraps, without device/audio I/O."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_loader import simulate


def main():
    stock = NativeImage()
    containers = json.loads((ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json').read_text())
    cases = []
    for record in containers['containers']:
        if not record['native_module_container']: continue
        path = ROOT / record['module']['extracted_binary']
        binary = path.read_bytes()
        if hashlib.sha256(binary).hexdigest() != record['files']['DLLIMG.BIN']['sha256']:
            raise ValueError('Original module changed since container extraction')
        _, result = simulate(stock, 'original_voice', module_bytes=binary,
                             module_ram_bytes=record['module']['image_header_ram_bytes'],
                             poison_module_ram=True, return_session=True)
        result.update(voice_package=record['file'], module_sha256=record['files']['DLLIMG.BIN']['sha256'],
                      original_module_unmodified=True, ram_poisoned_before_copy=True)
        cases.append(result)
    if len(cases) != 3: raise ValueError('Expected all three backed-up TTS modules')
    output = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'cases': cases, 'all_passed': True, 'device_io': False,
              'audible_output': False, 'signature_validation_emulated': False,
              'native_on_device_modified_code_verified': False,
              'limitations': 'Original module entry/relocation/import/export initialization only, via stock initializer and synthetic file callbacks. No speech synthesis or speaker playback is invoked. VPM mount/signature validation and the conditional real-world voice-selection caller are not executed. These successful original files do not establish that a modified VPM would be accepted.'}
    path = ROOT / 'evidence/firmware-analysis/original-tts-module-emulation.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'original_modules': len(cases),
                      'exports_registered': [r['module_export_registration'][-1]['count'] for r in cases],
                      'loader_returns': [r['status'] for r in cases], 'device_io': False}))


if __name__ == '__main__':
    main()
