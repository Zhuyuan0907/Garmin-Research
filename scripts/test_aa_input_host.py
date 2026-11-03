#!/usr/bin/env python3
"""Actual C input module tests; synthetic readiness gate, independent protobuf.

This is outbound legacy-schema encoding, never phone/native acceptance.
"""
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / 'staging/android-auto-input-host-v1'
PROOF = ROOT / 'evidence/android-auto-input-host-v1.json'
BUILD = STAGE / 'build.json'
PRIOR = ROOT / 'evidence/android-auto-control-host-v1.json'
REVIEW = ROOT / 'evidence/android-auto-input-source-review-v1.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_events():
    # Independent explicit geometry examples: rational viewport mapping,
    # not copied C expressions and not a generated-code decode oracle.
    maximum = (1 << 64) - 1
    result = {}

    def touch(label, timestamp, action, x, y):
        result[label] = dict(timestamp=timestamp, kind='touch_event',
                             action=action, x=x, y=y)

    def key(label, timestamp, pressed, long=False):
        result[label] = dict(timestamp=timestamp, kind='button_event',
                             scan_code=4, pressed=pressed, long=long)

    def wheel(label, timestamp, delta):
        result[label] = dict(timestamp=timestamp, kind='relative_input_event',
                             scan_code=65536, delta=delta)

    touch('origin_press_zero', 0, 0, 0, 0)
    touch('origin_release', 1, 1, 0, 0)
    touch('center_press', 0, 0, 400, 240)
    touch('edge_drag', 2, 2, 798, 478)
    touch('edge_capture_release', 3, 1, 798, 478)
    touch('letterbox_center', 10, 0, 400, 240)
    touch('clamp_bottom_left', 11, 2, 0, 478)
    touch('clamp_top_right', 12, 2, 798, 0)
    touch('capture_loss_release', 13, 1, 798, 0)
    key('back_press', 0, True)
    key('back_longpress', 2, True, True)
    key('back_release', 3, False)
    wheel('wheel_minus_one', 4, -1)
    wheel('wheel_int32_min', 5, -(1 << 31))
    wheel('wheel_int32_max', 6, (1 << 31) - 1)
    touch('clock_zero', 0, 0, 1, 1)
    touch('clock_max', maximum, 1, 1, 1)
    key('clock_max_key_press', maximum, True)
    key('clock_max_key_release', maximum, False)
    touch('full_queue_origin', 0, 0, 0, 0)
    for i in range(1, 8):
        touch('queued_drag_' + str(i), i, 2, (i * 5) // 3, 0)
    touch('full_queue_release_retry', 100, 1, 11, 0)
    key('full_queue_key_retry', 101, True)
    key('full_queue_key_release', 102, False)
    touch('reentry_guard_press', 0, 0, 0, 0)
    touch('reentry_guard_release', 1, 1, 0, 0)
    wheel('binding_error_did_not_poison', 0, -1)
    return result


def main():
    started = time.monotonic()
    build, prior, review = [json.loads(p.read_text()) for p in (BUILD, PRIOR, REVIEW)]
    assert build['pass'] and build['schema_count'] == 10
    assert prior['pass'] and prior['case_count'] == 43
    assert review['runtime_tests_run'] == 0
    pins = dict(prior['source_sha256'])
    for name, pin in build['source_sha256'].items():
        assert name not in pins or pins[name] == pin, name
        pins[name] = pin
    for p in ('native/aa-input/input.c', 'native/aa-input/input.h',
              'native/aa-input/test_input.c', 'scripts/test_aa_input_host.py'):
        pins[p] = sha(ROOT / p)
    for name, pin in pins.items():
        assert sha(ROOT / name) == pin, name

    receipts = []

    def run(argv, env=None):
        before = time.monotonic()
        result = subprocess.run([str(a) for a in argv], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=60)
        record = dict(argv=[str(a) for a in argv], exit_code=result.returncode,
                      stdout=result.stdout, stderr=result.stderr,
                      elapsed_host_seconds=round(time.monotonic() - before, 6))
        receipts.append(record)
        assert result.returncode == 0, record
        return result

    compiler = run(['gcc', '--version']).stdout.splitlines()[0]
    proto_build = json.loads((ROOT / 'staging/android-auto-proto-host-v1/build.json').read_text())
    sources = [ROOT / 'native/aa-input/input.c', ROOT / 'native/aa-input/test_input.c']
    sources += [ROOT / p for p in build['c_sources'] + proto_build['c_sources']]
    assert len(sources) == len(set(sources))
    includes = ['-I' + str(ROOT / p) for p in build['include_dirs'] +
                ['native/aa-control', 'native/aa-message']]
    # The upstream Python protobuf output is separate from nanopb C output.
    # Import no own codec/input implementation into the semantic oracle.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(STAGE / 'python'))
    event_class = importlib.import_module('InputEventIndicationMessage_pb2').InputEventIndication
    expected = expected_events()
    builds, oracles, snapshots = [], [], []
    for label, flags in [('ordinary', ['-O2']),
                         ('asan-ubsan', ['-O1', '-g', '-fsanitize=address,undefined',
                                         '-fno-omit-frame-pointer'])]:
        out = STAGE / ('tests-' + label)
        out.mkdir(exist_ok=True)
        binary = out / 'test_input'
        run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic'] +
            flags + includes + sources + ['-o', binary])
        env = dict(os.environ)
        if label == 'asan-ubsan':
            env.update(ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        runtime = run([binary], env=env)
        rows = [json.loads(line) for line in runtime.stdout.splitlines()]
        summary = rows[-1]
        assert summary['summary'] and summary['pass']
        assert len(summary['categories']) == 10 and all(c['assertions'] for c in summary['categories'])
        assert summary['assertions'] == sum(c['assertions'] for c in summary['categories'])
        assert summary['control_gate'] == 'synthetic_C_stub'
        events = rows[:-1]
        assert summary['events'] == len(events) == len(expected)
        assert len({r['event'] for r in events}) == len(events)
        assert set(r['event'] for r in events) == set(expected)
        details = []
        for r in events:
            e = expected[r['event']]
            raw = bytes.fromhex(r['hex'])
            assert r['channel'] == 1 and r['flags'] == 8 and r['token'] > 0
            assert raw[:2] == b'\x80\x01' and len(raw) <= 256
            message = event_class()
            consumed = message.ParseFromString(raw[2:])
            assert consumed == len(raw) - 2
            assert message.timestamp == e['timestamp'] and message.disp_channel == 0
            choices = ['touch_event', 'button_event', 'absolute_input_event', 'relative_input_event']
            assert [k for k in choices if message.HasField(k)] == [e['kind']]
            if e['kind'] == 'touch_event':
                t = message.touch_event
                assert len(t.touch_location) == 1 and t.action_index == 0 and t.touch_action == e['action']
                p = t.touch_location[0]
                assert (p.x, p.y, p.pointer_id) == (e['x'], e['y'], 0)
            elif e['kind'] == 'button_event':
                assert len(message.button_event.button_events) == 1
                k = message.button_event.button_events[0]
                assert (k.scan_code, k.is_pressed, k.meta, k.long_press) == (4, e['pressed'], 0, e['long'])
            else:
                assert len(message.relative_input_event.relative_input_events) == 1
                w = message.relative_input_event.relative_input_events[0]
                assert (w.scan_code, w.delta) == (65536, e['delta'])
            if r['event'] == 'origin_press_zero':
                # PRESS0 at origin has empty TouchLocation message presence,
                # despite all its scalar fields (and timestamp) being defaults.
                assert raw == b'\x80\x01\x1a\x02\x0a\x00'
            details.append(dict(label=r['event'], encoded_hex=r['hex'], bytes=len(raw),
                                expected_semantics=e, independent_python_decode_passed=True))
        assert len(details) == 33
        builds.append(dict(name=label, flags=flags, binary=str(binary.relative_to(ROOT)),
                           binary_sha256=sha(binary), runtime_summary=summary))
        oracles.append(dict(build=label, event_count=len(details), events=details))
        snapshots.append(rows)
    assert snapshots[0] == snapshots[1]
    for name, pin in pins.items():
        assert sha(ROOT / name) == pin, 'Source changed during verification: ' + name
    proof = dict(
        schema='android-auto-input-host-v1', **{'pass': True},
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        host_arch=platform.machine(), compiler=compiler, source_sha256=pins,
        category_count=10, assertions_per_build=builds[0]['runtime_summary']['assertions'],
        independent_python_oracle_events_per_build=33, builds=builds, semantic_oracles=oracles,
        actual_subprocess_receipts=receipts, outbound_input_encoding_verified=True,
        C_input_state_queue_gate_controls_verified=True, input_C_ASan_UBSan_verified=True,
        control_completion_gate='synthetic_C_stub_OPEN_BIND_PENDING_BOUND',
        real_TLS_control_binding_completion_verified=False, borrowed_view_copied_before_commit=True,
        geometry_examples=[dict(surface=[480,272], viewport=[0,0,480,272], advertised=[800,480]),
                           dict(surface=[480,272], viewport=[0,16,480,240], advertised=[800,480])],
        capacity_limits=dict(queue_slots=8, each_slot_bytes=256, touch_pointers=1,
                             advertised_keys=64, geometry_maximum=4096),
        prerequisite=dict(generation=dict(path=str(BUILD.relative_to(ROOT)), sha256=sha(BUILD)),
                          old_control43=dict(path=str(PRIOR.relative_to(ROOT)), sha256=sha(PRIOR),
                                             source_pins_unchanged=True, old_tests_rerun=False),
                          static_source_review=dict(path=str(REVIEW.relative_to(ROOT)), sha256=sha(REVIEW),
                                                    archive_verified_files=37, static_assertions=38,
                                                    runtime_tests_run=0)),
        phone_interoperability_verified=False, current_Pixel_interoperability_verified=False,
        Google_acceptance_verified=False, multitouch_verified=False, hardware_touch_verified=False,
        original_Garmin_code_executed=False, native_guest_executed=False, device_IO=False,
        ARM_crosscompile=False, install_candidate=False, existing_control_or_proto_modified=False,
        limitations=[
            'Control readiness is an explicit synchronous C stub, not actual binding transport/TLS completion.',
            'Input source timestamps are caller-provided microseconds; clock choice and current phone clock sync are not verified.',
            'Single pointer only; capture loss emits RELEASE at last accepted coordinate, never CANCEL or multi-pointer actions.',
            'Viewport mapping is own declared policy; no hardware calibration, rotation or current phone coordinate interpretation verified.',
            'The 33 events per build are synthetic outbound bytes, not observed Android UI actions or Google Maps interaction.',
            'Owner calls are serialized; reentry guard proves synchronous stub rejection, not threads/IRQ/shutdown quiescence.'],
        elapsed_host_seconds=round(time.monotonic() - started, 6))
    PROOF.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(**{'pass': True}, proof=str(PROOF.relative_to(ROOT)), sha256=sha(PROOF),
                         assertions_per_build=proof['assertions_per_build'], categories=10,
                         semantic_events_per_build=33, outbound_input_encoding_verified=True,
                         header_sha256=pins['native/aa-input/input.h']), indent=2))


if __name__ == '__main__':
    main()
