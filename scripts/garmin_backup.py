#!/usr/bin/env python3
"""Wait for Garmin USB storage and save verified, read-only logical disk images.

This does not dump firmware-only flash regions and never flashes the device.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
GARMIN_VENDOR = "091e"
CHUNK = 4 * 1024 * 1024


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def emit(event, **details):
    record = {"time": now(), "event": event, **details}
    print(json.dumps(record, ensure_ascii=False), flush=True)
    with (ROOT / "evidence" / "backup-events.jsonl").open("a") as log:
        log.write(json.dumps(record, ensure_ascii=False) + "\n")


def usb_identity(path):
    """Only USB devices whose actual sysfs ancestor is Garmin are eligible."""
    for parent in (path, *path.parents):
        vendor = parent / "idVendor"
        if vendor.is_file():
            if vendor.read_text().strip().lower() != GARMIN_VENDOR:
                return None
            result = {"sysfs": str(parent)}
            for key in ("idVendor", "idProduct", "manufacturer", "product", "serial"):
                file = parent / key
                if file.is_file():
                    result[key] = file.read_text().strip()
            return result
    return None


def garmin_usb_devices():
    result = []
    for path in Path("/sys/bus/usb/devices").iterdir():
        if ":" in path.name or path.name.startswith("usb"):
            continue
        identity = usb_identity(path.resolve())
        if identity:
            result.append(identity)
    return result


def disks():
    command = ["lsblk", "--json", "--bytes", "--output",
               "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS,RO,MODEL,TRAN"]
    data = json.loads(subprocess.run(command, check=True, capture_output=True,
                                    text=True, timeout=10).stdout)
    result = []
    for disk in data["blockdevices"]:
        if disk["type"] != "disk":
            continue
        identity = usb_identity((Path("/sys/class/block") / disk["name"]).resolve())
        if identity:
            disk["usb"] = identity
            result.append(disk)
    return result


def nodes(disk):
    yield disk
    for child in disk.get("children", []):
        yield from nodes(child)


def ensure_source(disk):
    source = Path(disk["path"])
    if not stat.S_ISBLK(source.stat().st_mode):
        raise RuntimeError("Source is not a block device")
    identity = usb_identity((Path("/sys/class/block") / disk["name"]).resolve())
    if not identity or identity != disk["usb"]:
        raise RuntimeError("Garmin USB identity changed or disappeared")
    # Consult mountinfo by major:minor too, including other mount namespaces.
    device_numbers = set()
    for node in nodes(disk):
        device = Path(node["path"]).stat().st_rdev
        device_numbers.add(f"{os.major(device)}:{os.minor(device)}")
    for path in Path("/proc").glob("[0-9]*/mountinfo"):
        try:
            for line in path.read_text().splitlines():
                fields = line.split()
                if fields[2] in device_numbers:
                    raise RuntimeError("Source is mounted; leave it unmounted for a stable image")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass


def copy_verified(source, destination, size):
    """A short read is a failed backup; output is hashed again after fsync."""
    partial = destination.with_suffix(destination.suffix + ".partial")
    digest = hashlib.sha256()
    copied = 0
    progress_at = time.monotonic()
    with source.open("rb", buffering=0) as src, partial.open("xb", buffering=0) as dst:
        while copied < size:
            chunk = src.read(min(CHUNK, size - copied))
            if not chunk:
                raise RuntimeError(f"Source ended after {copied} of {size} bytes")
            dst.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
            if time.monotonic() - progress_at >= 30:
                emit("copy_progress", image=destination.name, copied=copied, size=size)
                progress_at = time.monotonic()
        os.fsync(dst.fileno())
    saved = hashlib.sha256()
    with partial.open("rb") as image:
        for chunk in iter(lambda: image.read(CHUNK), b""):
            saved.update(chunk)
    if partial.stat().st_size != size or saved.digest() != digest.digest():
        raise RuntimeError("Saved image verification failed")
    partial.rename(destination)
    return digest.hexdigest()


def backup(disk, directory):
    ensure_source(disk)
    size = int(subprocess.run(["blockdev", "--getsize64", disk["path"]],
                             check=True, capture_output=True, text=True,
                             timeout=10).stdout.strip())
    if size != int(disk["size"]) or size <= 0:
        raise RuntimeError("Block size is invalid or changed")
    free = shutil.disk_usage(directory).free
    if free < size + 512 * 1024 * 1024:
        raise RuntimeError(f"Insufficient host space: need {size} bytes plus reserve; have {free}")
    image = directory / (disk["name"] + ".img")
    metadata = {"started": now(), "state": "copying", "disk": disk,
                "size": size, "image": image.name,
                "scope": "Entire USB-exposed logical disk, including hidden files and partitions; firmware-only flash regions are not included."}
    manifest = directory / (disk["name"] + ".json")
    manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
    emit("backup_started", device=disk["path"], image=str(image), size=size)
    try:
        checksum = copy_verified(Path(disk["path"]), image, size)
        ensure_source(disk)
        metadata.update(state="verified", completed=now(), sha256=checksum)
        (directory / (image.name + ".sha256")).write_text(f"{checksum}  {image.name}\n")
        emit("backup_verified", image=str(image), sha256=checksum, size=size)
    except Exception as error:
        metadata.update(state="failed", error=str(error), completed=now())
        raise
    finally:
        manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", type=int, default=0, help="Wait up to this many seconds")
    parser.add_argument("--probe", action="store_true", help="Only report Garmin USB and disks")
    args = parser.parse_args()
    for name in ("evidence", "backups"):
        (ROOT / name).mkdir(exist_ok=True)
    if args.probe:
        print(json.dumps({"time": now(), "usb": garmin_usb_devices(), "disks": disks()},
                         ensure_ascii=False, indent=2))
        return 0
    emit("watch_started", seconds=args.wait, pid=os.getpid())
    deadline = time.monotonic() + max(0, args.wait)
    previous = None
    heartbeat = time.monotonic()
    while True:
        try:
            usb = garmin_usb_devices()
            available = disks()
            state = json.dumps({"usb": usb, "disks": available}, sort_keys=True)
            if state != previous:
                emit("device_state", usb=usb, disks=available)
                previous = state
            # Multi-LUN Garmin devices expose an empty SD reader as a disk too.
            # It is not a readable source and must not turn a valid backup into
            # a failure or cause an empty directory to count as a backup.
            if any(int(disk["size"] or 0) > 0 for disk in available):
                folder = ROOT / "backups" / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                folder.mkdir()
                failures = []
                for disk in available:
                    if int(disk["size"] or 0) <= 0:
                        emit("backup_skipped", device=disk["path"],
                             reason="No readable media (zero-capacity storage LUN)")
                        continue
                    try:
                        backup(disk, folder)
                    except Exception as error:
                        failures.append({"device": disk["path"], "error": str(error)})
                        emit("backup_failed", **failures[-1])
                emit("watch_finished", directory=str(folder), failures=failures)
                return 1 if failures else 0
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            emit("probe_error", error=str(error))
        if time.monotonic() >= deadline:
            emit("watch_finished", reason="No Garmin USB storage became available before deadline")
            return 2
        if time.monotonic() - heartbeat >= 60:
            emit("watch_heartbeat", remaining_seconds=int(deadline - time.monotonic()))
            heartbeat = time.monotonic()
        time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
