#!/usr/bin/env python3
"""Relink frozen warm player with one genuine OS20 Source TU; compile only.

Keep the 37 other original leaf-writers object inputs, stock TTS prefix and
selected route/provider/alias/writer barriers. No guest or device operation.
"""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import struct
import subprocess
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native/os20-audio-source-v1"
OUT = ROOT / "staging/native-os20-audio-source-build-v1"
OLD = ROOT / "staging/native-player-leaf-writers/build-v2.json"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def save(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def main():
    assert not OUT.exists(), "New namespace must be empty"
    OUT.mkdir()
    old = json.loads(OLD.read_text())
    source_hashes = dict(old["source_sha256"])
    assert all(sha(ROOT / p) == h for p, h in source_hashes.items())
    command_files = sorted((OLD.parent / "build-v2").glob("command-*.json"))
    commands = [json.loads(p.read_text())["command"] for p in command_files]
    link_commands = [c for c in commands if "-nostdlib" in c]
    assert len(link_commands) == 1
    old_objects = [Path(p) for p in link_commands[0] if p.endswith(".o")]
    assert len(old_objects) == 38 and len(set(old_objects)) == 38
    replaced = [p for p in old_objects if p.name == "mixer_source_warm_retirement_v1.o"]
    assert len(replaced) == 1
    objects = [p for p in old_objects if p not in replaced]
    assert len(objects) == 37
    derivation = json.loads((SOURCE / "source-derivation-v1.json").read_text())
    assert derivation["all_other_Source_bytes_reconstructed_exactly"]
    assert sha(ROOT / derivation["frozen_source"]) == derivation["frozen_source_sha256"]
    assert sha(ROOT / derivation["new_source"]) == derivation["new_source_sha256"]
    dependencies = [Path(__file__), OLD, *command_files, *old_objects,
                    ROOT / old["ELF"], ROOT / old["combined_binary"],
                    ROOT / "native/os20-task-bridge/create_abi_v2.h",
                    SOURCE / "source_os20_v1.c", SOURCE / "source_os20_v1.h",
                    SOURCE / "bridge_fragment_v1.inc", SOURCE / "source-derivation-v1.json",
                    SOURCE / "README.md", SOURCE / "contract-v1.json"]
    for path in dependencies:
        source_hashes[rel(path)] = sha(path)
    ld = OUT / "warm-os20-source.ld"
    ld.write_bytes((OLD.parent / "build-v2/warm-resident.ld").read_bytes())
    source_hashes[rel(OLD.parent / "build-v2/warm-resident.ld")] = sha(
        OLD.parent / "build-v2/warm-resident.ld")
    save(OUT / "inputs-at-build.json", source_hashes)
    build_commands = []

    def run(args):
        result = subprocess.run(args, capture_output=True, text=True)
        row = dict(command=args, exit_code=result.returncode,
                   stdout=result.stdout, stderr=result.stderr)
        save(OUT / f"command-{len(build_commands):02d}.json", row)
        build_commands.append(row)
        if result.returncode:
            raise RuntimeError(result.stderr[-5000:])
        return result.stdout

    flags = ["-mcpu=arm1176jzf-s", "-marm", "-mfloat-abi=soft", "-Os",
             "-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-unwind-tables",
             "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections",
             "-Wall", "-Wextra", "-Werror", "-I" + str(SOURCE),
             "-I" + str(ROOT / "staging/native-player-mixer-handoff"),
             "-I" + str(ROOT / "native/sbc-prototype")]
    new_object = OUT / "source_os20_v1.o"
    run(["arm-linux-gnueabi-gcc", *flags, "-c", str(SOURCE / "source_os20_v1.c"),
         "-o", str(new_object)])
    # Preserve the original object order; replace only the Source object.
    final_objects = [new_object if p in replaced else p for p in old_objects]
    elf = OUT / "warm-os20-source-EMULATION-ONLY.elf"
    flat = OUT / "warm-os20-source-EMULATION-ONLY.bin"
    run(["arm-linux-gnueabi-gcc", "-mcpu=arm1176jzf-s", "-mfloat-abi=soft",
         "-nostdlib", "-static", "-no-pie",
         "-Wl,--no-undefined,--gc-sections,--build-id=none,-Map=" + str(OUT / "warm.map"),
         "-Wl,-T," + str(ld), *map(str, final_objects), "-lgcc", "-o", str(elf)])
    assert not run(["arm-linux-gnueabi-nm", "-u", str(elf)]).strip()
    spec = importlib.util.spec_from_file_location(
        "os20_source_ELF", ROOT / "staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.ELF32(elf)
    symbols = {s["name"]: s for s in parsed.symbols if s["name"] and s["section_index"] != 0}
    wanted = ["mh_boot_source", "mh_source_entry", "mh_source_tcb", "source_stack",
              "source_descriptor", "aas_guard", "aas_media_ingress", "media_queue_step",
              "owned_media_consume", "memory_output_submit", "continuous_media_read",
              "mh_bind_ready_controller", "mh_os20_source_callback", "mh_os20_adapter",
              "mh_os20_create_started", "mh_os20_create_returns", "mh_os20_boot_attempts",
              "mh_os20_worker_entries", "mh_os20_callback_argument", "mh_os20_self_tcb",
              "mh_os20_ready_controller", "mh_os20_ready_posts", "mh_os20_ready_post_returns",
              "mh_os20_publication_checks", "mh_os20_publication_errors",
              "mh_os20_last_error", "mh_os20_ready_status", "mh_os20_context_address",
              "mh_os20_legacy_source_stack", "mh_os20_legacy_source_descriptor"]
    assert all(name in symbols for name in wanted), [name for name in wanted if name not in symbols]
    assert symbols["source_stack"]["size"] == 16384
    run(["arm-linux-gnueabi-objcopy", "-O", "binary", str(elf), str(flat)])
    blob = bytearray(flat.read_bytes())
    image = 0x02D4BB74
    ram = symbols["__resident_end"]["value"] - image
    struct.pack_into("<3I", blob, 0,
                     0xEA000000 | (((parsed.entry - (image + 8)) // 4) & 0xFFFFFF),
                     ram, len(blob))
    flat.write_bytes(blob)
    original = (ROOT / old["original_binary"]).read_bytes()
    assert blob[12:len(original)] == original[12:]
    assert len(blob) < ram <= 0x300000
    assert symbols["__resident_tail_start"]["value"] == old["protected_tail_start"]
    assert symbols["al_clear_fixed_entry"]["value"] == 0x02FB4718
    patch_lists = {}
    for key, prefix_name in (
            ("selected_native_route_entry_barriers", "rg"),
            ("selected_native_provider_entry_barriers", "pg"),
            ("selected_native_backend_alias_barriers", "al"),
            ("selected_native_leaf_writer_barriers", "lw")):
        patches = []
        for row in old[key]:
            address, size = row["address"], row["patch_bytes"]
            name = row["name"]
            if prefix_name == "rg" and name == "allocate":
                prefix = bytes.fromhex("004b1847")
                target = symbols["rg_allocate_gate"]["value"]
                after = prefix + struct.pack("<I", target)
            elif prefix_name == "pg":
                prefix = bytes.fromhex("004b1847" if address % 4 == 0 else "014b1847c046")
                after = prefix + struct.pack("<I", symbols["pg_" + name + "_gate"]["value"])
            elif prefix_name == "al" and name == "clear":
                after = bytes.fromhex("004b") + struct.pack("<I", 0x02FB4718) + bytes.fromhex("c046")
            else:
                prefix = bytes.fromhex("08b4014b1847c046" if address % 4 == 0 else "08b4004b1847")
                after = prefix + struct.pack("<I", symbols[prefix_name + "_" + name + "_entry"]["value"])
            after += bytes.fromhex("c046") * ((size - len(after)) // 2)
            assert len(after) == size
            patches.append(dict(row, after_hex=after.hex()))
        patch_lists[key] = patches
    opcodes = {}
    for name in ("mh_boot_source", "mh_os20_source_callback", "mh_source_entry"):
        opcodes[name] = run(["arm-linux-gnueabi-objdump", "-d", "--disassemble=" + name, str(elf)])
        (OUT / (name + "-opcodes.txt")).write_text(opcodes[name])
    manifest = dict(old)
    manifest.update(patch_lists)
    manifest.update(
        all_passed=True, build_validation="compiled/link/static binary checks only; no guest",
        ELF=rel(elf), ELF_sha256=sha(elf), symbols=symbols,
        source_sha256=source_hashes, generated_sha256={rel(ld): sha(ld)},
        combined_binary=rel(flat), combined_sha256=sha(flat),
        combined_file_bytes=len(blob), combined_ram_bytes=ram,
        extension_added_file_bytes=len(blob)-len(original),
        extension_added_RAM_bytes=ram-old["original_ram_bytes"],
        remaining_loader_capacity=0x300000-ram,
        reused_relocatable_objects=list(map(rel, objects)),
        original_link_object_count=38, new_link_object_count=38,
        replaced_object=rel(replaced[0]), new_Source_object=rel(new_object),
        new_Source_object_sha256=sha(new_object),
        frozen_Source_other_bytes_reconstructed_exactly=True,
        source_bridge_contract="native/os20-audio-source-v1/contract-v1.json",
        original_source_static_stack_retained_but_unused_by_OS20=True,
        requested_OS20_workspace_bytes=16384, actual_OS20_workspace_expected_bytes=16536,
        OS20_priority_index=7, native_priority_byte=89, controller_priority_expected_byte=16,
        ready_event=0x400, worker_self_publication_before_Source_initialization=True,
        native_creator_full_return_before_adapter_publication=True,
        full_TTS_prefix_after_header_retained=True, stock_TTS_export_count=40,
        original_typed_FIFO_and_native_Source_mixer_retirement_objects_retained=True,
        reader_patch=dict(old["reader_patch"], after_hex=(bytes.fromhex("004b1847") +
            struct.pack("<I", symbols["resident_loader_read_gate"]["value"])).hex()),
        native_descriptor_patch=dict(old["native_descriptor_patch"], after_hex=(
            bytes.fromhex("08b4024b9c4608bc6047c046") +
            struct.pack("<I", symbols["nr_reply_dispatch"]["value"])).hex()),
        pcm_pages=[symbols["pcm" + str(i)]["value"] for i in range(4)],
        guest_executed=False, device_IO=False, physical_installation_candidate=False,
        new_genuine_OS20_Source_execution_proven=False,
        original_heap_hardware_navigation_all_writers_or_STOP_DONE_proven=False,
        claim_release_stack_reclamation_or_module_unload=False,
        App_direct_phone_A2DP_DAC_GUI_Android_Auto_Google_Maps_achieved=False)
    assert all(sha(ROOT / p) == h for p, h in source_hashes.items())
    save(OUT / "manifest.json", manifest)
    print(json.dumps(dict(all_passed=True, manifest=rel(OUT / "manifest.json"),
                          reused_objects=37, compiled_Source_objects=1, file_bytes=len(blob),
                          RAM_bytes=ram, ELF_sha256=sha(elf), guest_executed=False,
                          device_IO=False)), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        if OUT.exists() and not (OUT / "terminal-failure.json").exists():
            save(OUT / "terminal-failure.json", dict(all_passed=False, error=str(error),
                 traceback=traceback.format_exc(), guest_executed=False, device_IO=False))
        raise
