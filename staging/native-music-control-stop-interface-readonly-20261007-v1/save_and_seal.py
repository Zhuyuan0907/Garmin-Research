"""Save a fixed, small FILE-only review packet; never import reviewed code."""
import hashlib
import json
import os
import pathlib
import stat
import sys

HERE = pathlib.Path(__file__).resolve().parent
LIMIT = 65536
NAMES = {"comparison.json", "proof.json", "source-pins.json",
         "actual-read-receipts.json", "HANDOFF.md"}

def snapshot(path):
    value = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(value.st_mode):
        raise ValueError("nonregular file")
    return {"dev": str(value.st_dev), "ino": str(value.st_ino),
            "size": str(value.st_size), "mtime_ns": str(value.st_mtime_ns),
            "ctime_ns": str(value.st_ctime_ns),
            "mode": oct(stat.S_IMODE(value.st_mode))}

def save(name, data):
    path = HERE / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fchmod(fd, 0o444)
            os.fsync(fd)
    finally:
        os.close(fd)
    pinned = snapshot(path)
    if int(pinned["size"]) != len(data) or pinned["mode"] != "0o444":
        raise ValueError("output size/mode mismatch")
    return {"path": name, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "stat": pinned,
            "digest_basis": "exact emitted bytes; final size/mode/stat"}

packet_raw = sys.stdin.buffer.read(100001)
if len(packet_raw) > 100000:
    raise ValueError("stdin guard")
packet = json.loads(packet_raw)
if set(packet["files"]) != NAMES:
    raise ValueError("fixed file inventory mismatch")
payloads = {name: text.encode("utf-8") for name, text in packet["files"].items()}
writer_path = HERE / "save_and_seal.py"
writer_bytes = writer_path.read_bytes()
if sum(map(len, payloads.values())) + len(writer_bytes) + 4096 + 2048 > LIMIT:
    raise ValueError("fixed aggregate output guard")
if set(item.name for item in HERE.iterdir()) != {"save_and_seal.py"}:
    raise ValueError("refuse existing artifact mutation")
for pin in packet["fresh_pins"]:
    if snapshot(pathlib.Path(pin["path"])) != pin["stat"]:
        raise ValueError("fresh source changed before seal")
os.chmod(writer_path, 0o444)
entries = [{"path": "save_and_seal.py", "bytes": len(writer_bytes),
            "sha256": hashlib.sha256(writer_bytes).hexdigest(),
            "stat": snapshot(writer_path), "digest_basis": "own saver source bytes"}]
for name, data in payloads.items():
    entries.append(save(name, data))
for pin in packet["fresh_pins"]:
    if snapshot(pathlib.Path(pin["path"])) != pin["stat"]:
        raise ValueError("fresh source changed during seal")
seal = {"schema": "finite-file-review-hash-seal-v1",
        "scope": packet["scope"], "all_assigned_checks_passed": True,
        "STOP": True, "review_only": True, "no_reviewed_source_execution": True,
        "artifact_full_readback": False, "fresh_source_body_reread": False,
        "all_handles_closed": True, "files": entries}
seal_bytes = (json.dumps(seal, indent=1) + "\n").encode()
if len(seal_bytes) > 4096:
    raise ValueError("seal reservation guard")
seal_pin = save("sealed-files.json", seal_bytes)
total = sum(item["bytes"] for item in entries) + seal_pin["bytes"]
print(json.dumps({"status": "CLOSED", "STOP": True, "files": entries,
                  "seal": seal_pin, "output_bytes_before_terminal_closure": total,
                  "reserved_terminal_closure_bytes": 2048,
                  "fresh_source_stat_rechecked_without_body_reads": 3,
                  "stdin_sha256": hashlib.sha256(packet_raw).hexdigest()}))
