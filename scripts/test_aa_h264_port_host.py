#!/usr/bin/env python3
"""Independent Linux-host portable-codec tests; no ARM or device claim.

Without --execute print the plan. Execute only after root confirms the new
build manifest is ready. Never run the old Python harness main, which writes
the old proof. Its C++ main is renamed inside our new host-hook harness.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "staging/android-auto-h264-port-v1"
OLD_HARNESS = ROOT / "scripts/test_aa_h264_host.py"
OLD_C_TEST = ROOT / "native/aa-h264/test_h264.cpp"
OLD_PROOF = ROOT / "evidence/android-auto-h264-host-v1.json"
OLD_PROOF_PIN = "ed644cfaa8f8ac7ede4fe4ecafec18758e44219fd95b026ce7176a684f636e05"
BASE = ROOT / "native/aa-h264"
PORT = ROOT / "native/aa-h264-port"
PROOF = ROOT / "evidence/android-auto-h264-port-host-v1.json"
SPECIFICATIONS = [
    ("baseline-small", 96, 64, 8, "baseline", 0, 0),
    ("main-b-small", 128, 96, 12, "main", 2, 0),
    ("high-b-small", 128, 96, 12, "high", 3, 0),
    ("high-800x480", 800, 480, 6, "high", 2, 1),
    ("high-cropped", 78, 62, 7, "high", 2, 0),
    ("main-p-small", 128, 96, 8, "main", 0, 0),
    ("high-p-small", 128, 96, 8, "high", 0, 0),
]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reusable_helpers():
    # Import executes definitions only, not the existing harness's main.
    # Prevent a new __pycache__ file alongside the frozen old source.
    old = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("aa_h264_fixture_helpers", OLD_HARNESS)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    return module.nals, module.annex, module.sps


class Runner:
    def __init__(self):
        self.receipts = []
        self.env = dict(os.environ)
        self.env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        self.env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

    def __call__(self, argv, timeout=180, expected_exit=0, expected_signal=False):
        start = time.monotonic()
        argv = [str(a) for a in argv]
        result = subprocess.run(argv, cwd=ROOT, env=self.env, capture_output=True,
                                text=True, timeout=timeout)
        receipt = dict(argv=argv, exit_code=result.returncode,
                       stdout=result.stdout, stderr=result.stderr,
                       elapsed_seconds=time.monotonic() - start)
        self.receipts.append(receipt)
        receipt["expected_exit"] = expected_exit
        receipt["expected_signal"] = expected_signal
        good = (result.returncode in [-signal.SIGILL, -signal.SIGTRAP] if expected_signal else
                result.returncode == expected_exit)
        if not good:
            raise AssertionError(receipt)
        return result.stdout


def create_independent_fixtures(run, directory):
    nals, annex, sps = reusable_helpers()
    directory.mkdir(parents=True, exist_ok=True)
    assert sha(OLD_PROOF) == OLD_PROOF_PIN, "Frozen old proof changed"
    old_proof = json.loads(OLD_PROOF.read_text())
    assert old_proof["pass"]
    old_fixtures = {f["name"]: f for f in old_proof["fixtures"]}
    fixtures = []
    for name, width, height, frames, profile, bframes, aud in SPECIFICATIONS:
        # Read immutable existing streams; only the NEW reference path is written.
        old = old_fixtures[name]
        encoded = ROOT / old["bitstream"]
        assert sha(encoded) == old["bitstream_sha256"]
        assert (old["width"], old["height"], old["frames"]) == (width, height, frames)
        reference = directory / (name + ".yuv")
        run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-c:v", "h264",
             "-i", encoded, "-f", "rawvideo", "-pix_fmt", "yuv420p",
             "-fps_mode", "passthrough", reference])
        assert reference.stat().st_size == width * height * 3 // 2 * frames
        assert sha(reference) == old["reference_sha256"], "Fresh FFmpeg oracle differs from old pinned oracle"
        units = nals(encoded.read_bytes())
        profile_idc = next(n[1] for n in units if n[0] & 31 == 7)
        assert profile_idc == {"baseline": 66, "main": 77, "high": 100}[profile]
        fixtures.append(dict(name=name, bitstream=str(encoded.relative_to(ROOT)),
                             bitstream_sha256=sha(encoded), reference=str(reference.relative_to(ROOT)),
                             reference_sha256=sha(reference), width=width, height=height,
                             frames=frames, profile_idc=profile_idc, bframes_configured=bframes,
                             nal_types=[n[0] & 31 for n in units], max_nal_bytes=max(map(len, units)),
                             existing_stream_preserved=True, fresh_ffmpeg_reference=True))
    negative = {
        "oversized-coded-816x480": (annex([sps(816, 480)]), -2),
        "oversized-coded-800x496": (annex([sps(800, 496)]), -2),
        "high-oversized-coded": (annex([sps(1920, 1088, 100)]), -2),
        "SPS-reference-count-over-16": (annex([sps(96, 64, 66, 17)]), -2),
        "unsupported-SPS-profile": (annex([sps(96, 64, 88)]), -4),
        "truncated-SPS": (annex([b"\x67\x42"]), -3),
        "forbidden-zero-bit": (annex([b"\x87\x80"]), -3),
        "unsupported-AVCC-input": (b"\x00\x00\x00\x05\x67\x42", -3),
        "unsupported-extension-NAL": (annex([b"\x74\x80"]), -4),
        "PPS-before-SPS": (annex([b"\x68\xce\x3c\x80"]), -3),
        "slice-before-parameter-sets": (annex([b"\x65\xb8\x40"]), -3),
        "bad-emulation-prevention": (annex([b"\x06\x00\x00\x03\x04\x80"]), -3),
        "empty-final-startcode": (b"\x00\x00\x00\x01", -9),
        "split-partial-startcode-at-EOF": (b"\x00\x00", -9),
    }
    for name, (data, code) in negative.items():
        (directory / (name + ".h264")).write_bytes(data)
    return fixtures, negative


def compile_abi_harness(run, build, directory):
    # The old public C ABI test is read-only and relinked against the NEW library.
    # Do not build/modify the old library or execute its Python main.
    flags = (["-O2"] if build["name"] == "ordinary" else
             ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])
    binary = directory / "test_h264_original_abi"
    run(["g++", "-std=c++11", "-Wall", "-Wextra", "-Werror", "-pthread"] + flags
        + ["-I" + str(BASE), "-I" + str(PORT), PORT / "test_port.cpp", ROOT / build["shared_library"],
           "-Wl,-rpath," + str((ROOT / build["shared_library"]).parent), "-o", binary])
    return binary


def results_with_port(stdout):
    results = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert len(results) == 2, results
    original, port = results
    assert port["port_pass"] and port["unbound"]
    assert port["live_allocations"] == 0 and port["live_bytes"] == 0
    assert port["allocation_calls"] == port["deallocation_calls"] == port["alloc_callbacks"] == port["free_callbacks"]
    assert port["allocated_bytes"] == port["freed_bytes"]
    assert port["peak_live_bytes"] <= port["cap"]
    assert port["forbidden_count"] == port["fatal_count"] == 0
    return original, port


def abi_fixture_matrix(run, binary, fixtures, negative, directory):
    cases = []
    guards, port = results_with_port(run([binary, "guards"]))
    assert guards["pass"]
    cases.append(dict(name="existing-ABI-guards", result=guards, port_result=port))
    for fixture in fixtures:
        for chunk, pause in [(0, 0), (1, 1), (65535, 1)]:
            output = directory / "decoded.yuv"
            result, port = results_with_port(run([binary, "decode", ROOT / fixture["bitstream"],
                                                  output, str(chunk), str(pause)]))
            assert result["status"] == 2 and result["frames"] == fixture["frames"]
            assert (result["width"], result["height"]) == (fixture["width"], fixture["height"])
            actual = output.read_bytes()
            oracle = (ROOT / fixture["reference"]).read_bytes()
            assert actual == oracle, (fixture["name"], chunk, pause,
                                      sum(a != b for a, b in zip(actual, oracle)))
            cases.append(dict(name=fixture["name"], chunk=chunk,
                              pause_each_frame=bool(pause), result=result,
                              decoded_sha256=sha(output), byte_exact_ffmpeg=True, port_result=port))
    fixtures_dir = directory.parent / "fixtures-independent"
    for name, (_, code) in negative.items():
        result, port = results_with_port(run([binary, "decode", fixtures_dir / (name + ".h264"),
                                              directory / "decoded.yuv", "1", "0"]))
        assert result["status"] == code and result["frames"] == 0, (name, result)
        cases.append(dict(name=name, expected_error=code, result=result, port_result=port))
    small = fixtures[0]
    for name, nc, ac in [("NAL-limit", 64, 512),
                         ("AU-limit", small["max_nal_bytes"], small["max_nal_bytes"] + 4)]:
        result, port = results_with_port(run([binary, "decode", ROOT / small["bitstream"],
                                              directory / "decoded.yuv", "1", "0", "800", "480", str(nc), str(ac)]))
        assert result["status"] == -2, (name, result)
        cases.append(dict(name=name, expected_error=-2, result=result, port_result=port))
    (directory / "decoded.yuv").unlink(missing_ok=True)
    return cases


def platform_controls(run, binary, fixtures, directory):
    cases = []
    baseline = next(f for f in fixtures if f["name"] == "baseline-small")
    for mode in ["controls", "lifecycle", "clock-equal", "clock-max"]:
        argv = [binary, mode]
        if mode == "lifecycle":
            argv.append(ROOT / baseline["bitstream"])
        result = json.loads(run(argv))
        assert result["port_pass"] and result["unbound"]
        assert result["live_allocations"] == result["live_bytes"] == 0
        assert result["allocation_calls"] == result["deallocation_calls"]
        assert result["allocated_bytes"] == result["freed_bytes"]
        assert result["peak_live_bytes"] <= result["cap"]
        assert result["forbidden_count"] == result["fatal_count"] == 0
        cases.append(dict(name=mode, kind="positive-platform", result=result))
    _, annex, sps = reusable_helpers()
    # PPS: id0, SPS0, entropy0, bottom0, num_slice_groups_minus1=1.
    # It must fail in the unchanged wrapper before reaching codec FMO/math.
    fmo = directory.parent / "fixtures-independent/FMO-PPS.h264"
    fmo.write_bytes(annex([sps(96, 64), b"\x68\xc5"]))
    result, port = results_with_port(run([binary, "decode", fmo,
                                         directory / "fmo-decoded.yuv", "1", "0"]))
    assert result["status"] == -4 and result["frames"] == 0
    assert port["fatal_count"] == port["forbidden_count"] == 0
    cases.append(dict(name="FMO-PPS-wrapper-reject", kind="separate-wrapper-control",
                      expected_error=-4, result=result, port_result=port,
                      fixture_sha256=sha(fmo), hidden_math_stubs_executed=False))
    (directory / "fmo-decoded.yuv").unlink(missing_ok=True)
    failures = [
        ("cap", ["fatal-cap"], 2, False),
        ("allocator-first", ["fatal-allocator", "1"], 2, False),
        ("allocator-second", ["fatal-allocator", "2"], 2, False),
        ("allocator-eighth", ["fatal-allocator", "8"], 2, False),
        ("allocator-alignment", ["fatal-alignment"], 5, False),
        ("clock-negative", ["fatal-clock-negative"], 7, False),
        ("clock-regression", ["fatal-clock-regression"], 7, False),
        ("runtime-hook-reentry", ["fatal-reentry"], 4, False),
        ("thread-op-2", ["fatal-thread", "2"], 3, False),
        ("thread-op-11", ["fatal-thread", "11"], 3, False),
        ("thread-op-109", ["fatal-thread", "109"], 3, False),
        ("fatal-callback-return-traps", ["fatal-return", "11"], 3, True),
    ]
    for name, args, reason, signal in failures:
        stdout = run([binary] + args, expected_exit=80 + reason, expected_signal=signal)
        result = json.loads(stdout)
        assert result["fatal"] and result["reason"] == reason and result["fatal_count"] == 1
        assert result["peak_live_bytes"] <= result["cap"]
        assert result["live_bytes"] <= result["cap"]
        if reason == 3:
            assert result["forbidden_count"] == 1 and result["last_forbidden"] == int(args[1])
        else:
            assert result["forbidden_count"] == 0
        if reason in [2, 5]:
            assert result["allocation_failures"] == 1
        if name == "cap":
            assert result["alloc_callbacks"] == 0
        if name.startswith("allocator-") and name != "allocator-alignment":
            assert result["alloc_callbacks"] == int(args[1])
        cases.append(dict(name=name, kind="isolated-nonreturning-fatal", result=result,
                          actual_exit_code=run.receipts[-1]["exit_code"],
                          recovery_or_cleanup_claim=False))
    stdout = run([binary, "fatal-unbound"], expected_signal=True)
    assert json.loads(stdout)["unbound_before_runtime_call"]
    cases.append(dict(name="unbound-runtime-traps", kind="isolated-unbound-trap",
                      actual_exit_code=run.receipts[-1]["exit_code"],
                      fatal_callback_available=False, recovery_or_cleanup_claim=False))
    return cases


def prepared_plan():
    return {
        "executed": False,
        "old_helpers": ["nals(bytes)->list[bytes]", "annex(units)->bytes",
                        "sps(width,height,profile=66,refs=1)->bytes"],
        "old_C_ABI_harness": "guards; decode input output chunk pause [width height nal_cap au_cap]",
        "fixture_count": len(SPECIFICATIONS),
        "chunk_pause_modes": [[0, 0], [1, 1], [65535, 1]],
        "independent_oracle": "Seven SHA-pinned existing streams, freshly independently decoded by FFmpeg into NEW I420 reference paths",
        "existing_controls": ["original aa_h264 C API", "callback reentry", "owned tight planes",
                              "source overwrite", "PAUSED same pointer/index/content", "STOP/reset",
                              "EOF reorder drain", "sticky error", "geometry/profile/NAL/AU guards"],
        "additional_required_controls": ["stop with held frame discards without retry callback",
                                         "EOF-held final frame retry returns FINISHED=2",
                                         "allocator peak within configured cap",
                                         "cap rejected before external alloc, isolated fatal; no cleanup/recovery",
                                         "selected injected allocation failures terminate isolated child; no recovery/cleanup claim",
                                         "STOP and destroy return live allocations/bytes to zero",
                                         "forbidden platform call counters stay zero",
                                         "binary undefined-symbol audit excludes POSIX thread/time/I/O"],
        "requires_before_execution": "Root confirms ordinary+ASan build manifest ready",
        "runtime_tests": 0, "ARM_crosscompile": False, "device_IO": False,
        "native_guest_executed": False, "installed_on_Garmin": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(prepared_plan(), indent=2))
        return
    manifest_path = STAGE / "build.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["schema"] == "android-auto-h264-port-host-build-v1" and manifest["pass"]
    assert {b["name"] for b in manifest["builds"]} == {"ordinary", "asan-ubsan"}
    frozen = {}
    for field in ["original_source_sha256", "own_source_sha256", "copied_source_sha256"]:
        for name, pin in manifest[field].items():
            assert sha(ROOT / name) == pin, name
            frozen[name] = pin
    for name in [OLD_PROOF, OLD_HARNESS, OLD_C_TEST, Path(__file__).resolve(), PORT / "test_port.cpp"]:
        frozen[str(name.relative_to(ROOT))] = sha(name)
    assert sha(OLD_PROOF) == OLD_PROOF_PIN
    run = Runner()
    abi_cases, platform_cases, audits, binaries = [], [], [], []
    proof = dict(schema="android-auto-h264-port-host-v1", **{"pass": False},
                 created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 build_manifest=str(manifest_path.relative_to(ROOT)),
                 build_manifest_sha256=sha(manifest_path), source_sha256=frozen,
                 actual_subprocess_receipts=run.receipts, abi_cases=abi_cases,
                 platform_cases=platform_cases, production_library_audits=audits,
                 test_binaries=binaries, original_Garmin_code_executed=False,
                 native_guest_executed=False, ARM_crosscompile=False, device_IO=False,
                 ARM32_verified=False, GarminOS_verified=False, installed_on_Garmin=False,
                 current_Pixel_interoperability_verified=False, real_time_performance_proven=False,
                 fatal_OOM_no_recovery=True, overall_RSS_cap_proven=False,
                 allocator_callback_padding_in_cap=False, hidden_math_stubs_runtime_verified=False,
                 scope="Linux ELF64 AArch64 host; external test runtime uses normal Linux/C++ runtime. Ordinary production library independently audited for no runtime imports; ASan/UBSan production library intentionally uses host sanitizer runtime. No original Garmin code, target ABI or hardware tested.")
    try:
        run(["ffmpeg", "-version"])
        run(["g++", "--version"])
        fixtures, negative = create_independent_fixtures(run, STAGE / "fixtures-independent")
        proof["fixtures"] = fixtures
        for build in manifest["builds"]:
            library = ROOT / build["shared_library"]
            assert sha(library) == build["shared_library_sha256"]
            symbols = run(["nm", "-D", "--undefined-only", library])
            dynamic = run(["readelf", "-d", library])
            exports = run(["nm", "-D", "--defined-only", library])
            assert all(line.split()[-1].startswith("aa_h264_") for line in exports.splitlines() if line.strip())
            needed = [line for line in dynamic.splitlines() if "(NEEDED)" in line]
            if build["name"] == "ordinary":
                assert not symbols.strip() and not needed
            audits.append(dict(build=build["name"], shared_library=build["shared_library"],
                               shared_library_sha256=sha(library),
                               undefined_symbols=symbols.splitlines(), DT_NEEDED=needed,
                               runtime_imports_zero=not symbols.strip() and not needed,
                               sanitizer_runtime_scope=build["name"] == "asan-ubsan"))
            directory = STAGE / ("tests-" + build["name"])
            directory.mkdir(exist_ok=True)
            binary = compile_abi_harness(run, build, directory)
            binaries.append(dict(build=build["name"], path=str(binary.relative_to(ROOT)), sha256=sha(binary)))
            these = abi_fixture_matrix(run, binary, fixtures, negative, directory)
            assert len(these) == 38
            abi_cases.extend(dict(build=build["name"], **case) for case in these)
            more = platform_controls(run, binary, fixtures, directory)
            assert len(more) == 18
            platform_cases.extend(dict(build=build["name"], **case) for case in more)
        for name, pin in frozen.items():
            assert sha(ROOT / name) == pin, "Frozen source changed during test: " + name
        assert sha(manifest_path) == proof["build_manifest_sha256"]
        proof.update({"pass": True, "original_ABI_case_count": len(abi_cases),
                      "separate_platform_case_count": len(platform_cases),
                      "independent_ffmpeg_fixture_count": len(fixtures),
                      "unique_reference_frame_count": sum(f["frames"] for f in fixtures),
                      "ffmpeg_byte_exact_all_original_fixtures": True,
                      "original_C_ABI_verified": True,
                      "owned_PAUSED_STOP_EOF_verified": True,
                      "allocator_exact_backing_lifecycle_verified": True,
                      "allocator_alignment_and_canaries_verified": True,
                      "allocator_live_cap_on_tested_workloads_verified": True,
                      "normal_destroy_live_zero_verified": True,
                      "positive_workload_forbidden_count": 0,
                      "nonreturning_fatal_controls_verified": True,
                      "FMO_PPS_rejected_before_codec": True,
                      "ordinary_undefined_symbols_count": 0, "ordinary_DT_NEEDED_count": 0,
                      "ordinary_link_no_runtime_imports_verified": True})
    except BaseException as error:
        proof["failure"] = repr(error)
        PROOF.write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps({"pass": False, "proof": str(PROOF.relative_to(ROOT)),
                          "proof_sha256": sha(PROOF), "failure": repr(error)}, indent=2))
        raise
    PROOF.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"pass": True, "original_ABI_case_count": len(abi_cases),
                      "separate_platform_case_count": len(platform_cases),
                      "ffmpeg_byte_exact_all_original_fixtures": True,
                      "proof": str(PROOF.relative_to(ROOT)), "proof_sha256": sha(PROOF)}, indent=2))


if __name__ == "__main__":
    main()
