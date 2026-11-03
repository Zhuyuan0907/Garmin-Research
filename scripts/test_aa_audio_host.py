#!/usr/bin/env python3
"""Own Linux C PCM provider only. No device, native guest, or audio playback."""
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "staging/android-auto-audio-host-v1"
PROOF = ROOT / "evidence/android-auto-audio-host-v1.json"
RECEIPTS = []
INCLUDES = ["native/aa-audio", "native/aa-control", "native/aa-message",
            "native/aa-proto", "native/aa-proto/generated", "native/aa-proto/runtime"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args, expected=0, env=None):
    start = time.monotonic()
    proc = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True,
                          text=True, timeout=90, env=env)
    receipt = {"command": [str(a) for a in args], "exit_code": proc.returncode,
               "stdout": proc.stdout, "stderr": proc.stderr,
               "wall_time_seconds": time.monotonic() - start}
    RECEIPTS.append(receipt)
    if proc.returncode != expected:
        raise RuntimeError(json.dumps(receipt))
    return proc.stdout


def source_review():
    sources = {}
    snapshots = []
    aasdk = "046b3b381595509d0939fa84b14a90978f46ff63"
    openauto = "aa90412bf93b5a5078495ea85ac9270c6297d369"
    spec = [
        ("aasdk", aasdk, "ff439a3e206edaff6c3cfa2eb458a911ddcf677e86695c0c7785377235add0e9", [
            "include/f1x/aasdk/Messenger/ChannelId.hpp",
            "src/Channel/AV/AudioServiceChannel.cpp",
            "src/Channel/AV/MediaAudioServiceChannel.cpp",
            "src/Channel/AV/SpeechAudioServiceChannel.cpp",
            "src/Channel/AV/SystemAudioServiceChannel.cpp",
            "aasdk_proto/AudioFocusTypeEnum.proto",
            "aasdk_proto/AudioFocusStateEnum.proto"]),
        ("openauto", openauto, "7d1c50b53afd5beb0447ce53414ef7441f500e1205a22c4a303b737befde4823", [
            "src/autoapp/Service/AudioService.cpp",
            "src/autoapp/Service/ServiceFactory.cpp",
            "src/autoapp/Service/AndroidAutoEntity.cpp",
            "src/autoapp/Projection/QtAudioOutput.cpp",
            "src/autoapp/Projection/RtAudioOutput.cpp"])]
    for repo, commit, expected, files in spec:
        directory = ROOT / "sources/android-auto" / f"{repo}-{commit}"
        archive = directory.with_suffix(".zip")
        assert sha(archive) == expected
        with zipfile.ZipFile(archive) as z:
            for name in files:
                file = directory / name
                assert file.read_bytes() == z.read(f"{repo}-{commit}/{name}")
                sources[str(file.relative_to(ROOT))] = sha(file)
        snapshots.append({"repository": f"https://github.com/f1xpl/{repo}",
                          "commit": commit, "archive": str(archive.relative_to(ROOT)),
                          "url": f"https://codeload.github.com/f1xpl/{repo}/zip/{commit}",
                          "sha256": expected, "bytes": archive.stat().st_size})
    base = ROOT / f"sources/android-auto/openauto-{openauto}/src/autoapp"
    factory = (base / "Service/ServiceFactory.cpp").read_text()
    output = (base / "Projection/QtAudioOutput.cpp").read_text()
    service = (base / "Service/AudioService.cpp").read_text()
    channel = (ROOT / f"sources/android-auto/aasdk-{aasdk}/src/Channel/AV/AudioServiceChannel.cpp").read_text()
    assert "RtAudioOutput>(2, 16, 48000)" in factory
    assert factory.count("RtAudioOutput>(1, 16, 16000)") == 2
    assert "QAudioFormat::LittleEndian" in output and "QAudioFormat::SignedInt" in output
    assert "indication.set_value(1);" in service
    assert "audioOutput_->write(timestamp, buffer);" in service
    assert "payload.size >= sizeof(messenger::Timestamp::ValueType)" in channel
    assert "audioOutput_->suspend();" in service
    review = {
        "method": "Static public source review plus exact archive member comparison; no upstream execution",
        "snapshots": snapshots, "archive_verified_source_count": len(sources),
        "contracts": [
            "ChannelId enum order fixes control0/media4/speech5/system6 in pinned legacy sources",
            "Factory media is 48000Hz stereo16; speech/system 16000Hz mono16",
            "Qt backend explicitly PCM signed little endian",
            "ID0 body strips Timestamp::ValueType; ID1 forwards raw media bytes",
            "ACK value1 per indication follows backend write; not per sample frame",
            "RtAudio buffer frame counts are observations, not packet-boundary contract",
            "Old OpenAuto suspend differs from our explicit discard-on-STOP host policy",
            "Old control audio focus response is simplistic; our gate/grant policy is separately declared"
        ], "current_Pixel_interoperability_proven": False}
    return sources, review


def samples(channel, long):
    channels = 2 if channel == 4 else 1
    frames = 4096 if long else 16
    # Independent signed integer construction and explicit little-endian pack.
    literal = [-32768, 32767, -1, 0, 1, 16384, -16384, 21845]
    values = []
    for frame in range(frames):
        for side in range(channels):
            value = ((frame * 7919 + side * 32749 + channel * 997) & 65535) - 32768 if long else literal[(frame + side * 3) % len(literal)]
            values.append(value)
    return struct.pack("<" + "h" * len(values), *values)


def compile_host(directory, sanitizers=False, source="native/aa-audio/audio.c"):
    directory.mkdir(parents=True, exist_ok=True)
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g"]
    flags += ["-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if sanitizers else ["-O2"]
    include = [x for d in INCLUDES for x in ["-I", d]]
    binary = directory / "test_audio"
    run(["cc", *flags, *include, source, "native/aa-audio/test_audio.c", "-o", binary])
    return binary, flags, include


def main():
    STAGE.mkdir(parents=True, exist_ok=True)
    source_pins, review = source_review()
    fixture_records = []
    for channel in (4, 5, 6):
        for long in (False, True):
            data = samples(channel, long)
            name = f"pcm-ch{channel}-{'long' if long else 'literal'}.s16le"
            path = STAGE / name
            path.write_bytes(data)
            fixture_records.append({"channel": channel, "input": str(path.relative_to(ROOT)),
                                    "bytes": len(data), "sha256": sha(path),
                                    "frames": len(data) // (4 if channel == 4 else 2)})
    empty = STAGE / "empty.s16le"
    empty.write_bytes(b"")
    results = []
    for name, sanitize in (("ordinary", False), ("asan-ubsan", True)):
        binary, flags, includes = compile_host(STAGE / name, sanitize)
        env = dict(os.environ)
        if sanitize:
            env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=1"
            env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        guards = json.loads(run([binary], env=env))
        golden = []
        for fixture in fixture_records:
            for chunk in (1, 3, 71, 16384):
                for mode in (0, 8):
                    output = STAGE / name / "actual.s16le"
                    record = json.loads(run([binary, fixture["input"], output,
                                             fixture["channel"], chunk, mode, "host-pcm"], env=env))
                    assert output.read_bytes() == (ROOT / fixture["input"]).read_bytes()
                    record.update({"fixture": fixture["input"], "channel": fixture["channel"],
                                   "indication_chunk_bytes": chunk, "backend_mode": mode,
                                   "actual_sha256": sha(output), "byte_exact": True})
                    golden.append(record)
        for channel in (4, 5, 6):
            output = STAGE / name / "actual-empty.s16le"
            record = json.loads(run([binary, empty, output, channel, 1, 0, "host-pcm"], env=env))
            assert output.read_bytes() == b""
            record.update({"empty_eof": True, "channel": channel, "byte_exact": True})
            golden.append(record)
        results.append({"configuration": name, "compiler_flags": flags,
                        "binary": str(binary.relative_to(ROOT)), "binary_sha256": sha(binary),
                        "selftest": guards, "independent_PCM_golden_cases": golden,
                        "case_count": guards["case_count"] + len(golden)})
    # Negatives run actual mutant C binaries and must fail our ownership oracle.
    text = (ROOT / "native/aa-audio/audio.c").read_text()
    mutations = {
        "lost-owned-copy": ("memcpy(s->data,data,bytes);", "memset(s->data,0,bytes);"),
        "lost-sample-carry": ("memcpy(r->carry,r->output+ready,r->carry_n);", "memset(r->carry,0,r->carry_n);")}
    controls = []
    for label, (old, new) in mutations.items():
        assert text.count(old) == 1
        file = STAGE / "mutations" / f"{label}.c"
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text.replace(old, new))
        binary, _, _ = compile_host(STAGE / "mutations" / label, source=str(file))
        run([binary], expected=2)
        controls.append({"label": label, "mutated_source_sha256": sha(file), "observed_exit_code": 2})
    ordinary = STAGE / "ordinary"
    shared = ordinary / "libaa-audio-host.so"
    includes = [x for d in INCLUDES for x in ["-I", d]]
    run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-fPIC", "-shared", *includes,
         "native/aa-audio/audio.c", "-o", shared])
    library = ctypes.CDLL(str(shared))
    library.aa_audio_context_bytes.restype = ctypes.c_uint32
    context_bytes = library.aa_audio_context_bytes()
    # cc's actual non-system include closure is pinned, not guessed manually.
    deps = run(["cc", "-MM", *includes, "native/aa-audio/audio.c", "native/aa-audio/test_audio.c"])
    files = [token for token in deps.replace("\\\n", " ").split() if not token.endswith(":")]
    files += ["native/aa-audio/README.md", "scripts/test_aa_audio_host.py"]
    for name in set(files):
        path = ROOT / name
        assert path.is_file()
        source_pins[name] = sha(path)
    fixture_hashes = {r["input"]: r["sha256"] for r in fixture_records}
    proof = {
        "schema": "android-auto-audio-host-v1", "pass": True,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Own bounded Linux-host S16LE PCM provider; no Garmin/phone/hardware audio",
        "device_IO": False, "native_guest_executed": False, "original_Garmin_code_executed": False,
        "ARM_crosscompiled": False, "TLS_executed": False, "hardware_audio_playback": False,
        "installation_candidate": False, "current_Pixel_interoperability_proven": False,
        "host_function_claim": {"software_PCM_backend_routing_verified": True,
                                "PCM_sample_frame_reassembly_verified": True,
                                "owned_indication_acceptance_and_partial_backend_retry_verified": True},
        "host_architecture": platform.machine(), "compiler": run(["cc", "--version"]).splitlines()[0],
        "source_sha256": dict(sorted(source_pins.items())), "source_review": review,
        "fixture_sha256": fixture_hashes, "fixtures": fixture_records,
        "oracle": "Independent Python signed integers packed <h; exact routed PCM bytes; no audio device",
        "bounds": {"context_bytes": context_bytes, "context_alignment": 8,
                   "owned_input_slots_per_route": 2, "input_bytes_per_slot": 16384,
                   "output_bytes_per_route": 4096, "sample_carry_max_bytes": 3,
                   "provider_heap_allocation": False, "backend_memory_bounded": False},
        "shared_library": {"path": str(shared.relative_to(ROOT)), "sha256": sha(shared)},
        "build_manifest": {"c_sources": ["native/aa-audio/audio.c"], "include_dirs": INCLUDES,
                           "required_backend": "caller supplies memory-only or explicitly authorized backend"},
        "case_count": sum(r["case_count"] for r in results) + len(controls),
        "runtime_case_count": sum(r["case_count"] for r in results),
        "selftest_categories_per_configuration": results[0]["selftest"]["case_count"],
        "results": results, "mutation_controls": controls, "actual_subprocess_receipts": RECEIPTS,
        "limitations": [
            "No true TLS/control integration in this proof; root harness supplies that separately",
            "No current Pixel, Garmin backend, Bluetooth, speaker, device queries or playback",
            "No conversion/mixing/ducking; explicit host focus policy does not prove navigation coexistence",
            "Whole-indication ACK means owned accepted bytes, not played audio",
            "Transport token guards apply to direct APIs; caller must invalidate stale provider callbacks",
            "STOP discards own data only; accepted backend bytes cannot be retracted or muted",
            "Timestamp remains opaque output assembly metadata, not a synthesized playback clock",
            "Serialized API and rejected reentry are not asynchronous quiescence or thread locks"]}
    PROOF.write_text(json.dumps(proof, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"pass": True, "case_count": proof["case_count"],
                      "runtime_case_count": proof["runtime_case_count"],
                      "proof": str(PROOF.relative_to(ROOT)), "proof_sha256": sha(PROOF),
                      "context_bytes": context_bytes, "shared_library_sha256": sha(shared)}))


if __name__ == "__main__":
    main()
