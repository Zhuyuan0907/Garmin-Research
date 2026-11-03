#!/usr/bin/env python3
"""Test the actual software video queue/renderer with a synthetic C codec.

No real H.264, TLS, phone, Garmin/native guest, device I/O or hardware output.
The generated negative control is a local copy of our video.c, never firmware.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/android-auto-video-queue-host-v1'
PROOF = ROOT / 'evidence/android-auto-video-queue-host-v1.json'
SOURCES = [ROOT / p for p in (
    'native/aa-video/video.c', 'native/aa-video/rgb565.c',
    'native/aa-video/test_video_queue.c')]
INCLUDE_DIRS = [ROOT / p for p in (
    'native/aa-video', 'native/aa-h264', 'native/aa-control',
    'native/aa-message', 'native/aa-proto', 'native/aa-proto/generated',
    'native/aa-proto/runtime')]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    started = time.monotonic()
    OUT.mkdir(parents=True, exist_ok=True)
    receipts, artifacts, dependencies = [], [], set(SOURCES)
    original_pins = {str(p.relative_to(ROOT)): sha(p) for p in SOURCES}

    def run(argv, expected=0, env=None):
        before = time.monotonic()
        result = subprocess.run([str(a) for a in argv], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=60)
        receipt = dict(argv=[str(a) for a in argv], exit_code=result.returncode,
                       stdout=result.stdout, stderr=result.stderr,
                       elapsed_host_seconds=round(time.monotonic() - before, 6))
        receipts.append(receipt)
        if result.returncode != expected:
            raise AssertionError(receipt)
        return result

    compiler = run(['gcc', '--version']).stdout.splitlines()[0]
    includes = ['-I' + str(p) for p in INCLUDE_DIRS]
    results = []
    for name, flags in [('ordinary', ['-O2']),
                        ('asan-ubsan', ['-O1', '-g', '-fsanitize=address,undefined',
                                        '-fno-omit-frame-pointer'])]:
        build = OUT / name
        build.mkdir(exist_ok=True)
        objects = []
        for source in SOURCES:
            obj, dep = build / (source.stem + '.o'), build / (source.stem + '.d')
            run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic'] +
                flags + includes + ['-MMD', '-MF', dep, '-c', source, '-o', obj])
            objects.append(obj)
            dep_text = dep.read_text().replace('\\\n', ' ')
            for token in dep_text.split(':', 1)[1].split():
                p = Path(token).resolve()
                if p.is_relative_to(ROOT):
                    dependencies.add(p)
        binary = build / 'test_video_queue'
        run(['gcc'] + flags + objects + ['-o', binary])
        env = dict(os.environ)
        if name == 'asan-ubsan':
            env.update(ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        output = run([binary], env=env)
        result = json.loads(output.stdout)
        assert result['pass'] and result['decoder_dependency'] == 'synthetic_C_stub_no_decoding'
        assert len(result['categories']) == 12 and all(x['assertions'] > 0 for x in result['categories'])
        assert result['assertions'] == sum(x['assertions'] for x in result['categories'])
        results.append(dict(build=name, binary=str(binary.relative_to(ROOT)),
                            binary_sha256=sha(binary), flags=flags, runtime=result))
        artifacts.append(dict(path=str(binary.relative_to(ROOT)), sha256=sha(binary)))
    assert results[0]['runtime'] == results[1]['runtime']

    # Regression sensitivity: remove ONLY our owner's busy guard in a staging
    # source copy. The real product sources remain untouched. The C stub models
    # dependency reentry; it does not claim a real codec stop issues callbacks.
    text = SOURCES[0].read_text()
    guarded = 'v->busy=1;r=aa_h264_stop(v->decoder);v->busy=0;\n    zero(v->slots'
    assert text.count(guarded) == 1
    negative = OUT / 'video-stop-negative.c'
    negative.write_text(text.replace(guarded, 'r=aa_h264_stop(v->decoder);\n    zero(v->slots'))
    negative_binary = OUT / 'test_video_queue_stop_negative'
    run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic'] +
        includes + [negative, SOURCES[1], SOURCES[2], '-o', negative_binary])
    failure = run([negative_binary], expected=1)
    assert 'category=serialized_owner_stop' in failure.stderr
    assert 'aa_video_status(d->owner,OWNER)==AA_VIDEO_E_REENTRANT' in failure.stderr
    for name, expected in original_pins.items():
        assert sha(ROOT / name) == expected, 'Product/test source changed during testing: ' + name
    dependencies.add(Path(__file__).resolve())
    pins = {str(p.relative_to(ROOT)): sha(p) for p in sorted(dependencies)}
    proof = dict(
        schema='android-auto-video-queue-host-v1', **{'pass': True},
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        host_arch=platform.machine(), compiler=compiler,
        category_count=len(results[0]['runtime']['categories']),
        assertions_per_build=results[0]['runtime']['assertions'],
        categories=results[0]['runtime']['categories'], builds=results,
        source_sha256=pins, actual_subprocess_receipts=receipts,
        artifacts=artifacts,
        negative_control=dict(
            description='Staging-only owner-stop copy with busy guard removed; regression must fail.',
            path=str(negative.relative_to(ROOT)), sha256=sha(negative),
            binary=str(negative_binary.relative_to(ROOT)), binary_sha256=sha(negative_binary),
            expected_exit_code=1, observed_exit_code=failure.returncode,
            observed_category='serialized_owner_stop'),
        decoder_dependency='synthetic_C_stub_no_decoding',
        actual_video_c_and_rgb565_c_host_tested=True,
        video_queue_and_renderer_ASan_UBSan_verified=True,
        simulated_dependency_callback_guards_verified=True,
        real_codec_stop_callback_observed=False,
        software_H264_decode_verified=False, TLS_integration_verified=False,
        device_IO=False, native_guest_executed=False, original_Garmin_code_executed=False,
        ARM_crosscompile=False, hardware_display_verified=False,
        phone_interoperability_verified=False, install_candidate=False,
        limitations=[
            'The C dependency is explicitly synthetic: no H.264 parser/decoder or real decoded frame.',
            'Calls/reentry are synchronous and serialized; no OS threads, IRQ, cancellation/quiescence or real timing proof.',
            'Capacity is two complete 262144-byte owned compressed indications; acceptance is not frame/display ACK.',
            'Timestamp/session transport is verified only as copied metadata, not a verified phone clock or audiovisual synchronization.',
            'RGB565 black/white endpoint and nearest selection tests cover explicit software matrix/range; no inferred phone VUI or physical framebuffer ABI.',
            'ASan/UBSan applies only to these host C sources/stub, not the separate real decoder integration.'],
        elapsed_host_seconds=round(time.monotonic() - started, 6))
    PROOF.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(**{'pass': True}, proof=str(PROOF.relative_to(ROOT)),
                         sha256=sha(PROOF), assertions_per_build=proof['assertions_per_build'],
                         categories=proof['category_count'], source_sha256=pins), indent=2))


if __name__ == '__main__':
    main()
