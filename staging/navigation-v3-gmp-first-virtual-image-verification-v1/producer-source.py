"""Verify a complete projected image without writing a second large IMG.

Only ordinary file data are read. No native code, device, or installer is run.
"""
import hashlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-v3-gmp-first-virtual-image-verification-v1'
BASE = ROOT / 'staging/navigation-v3-expanded4k-offline-isolation-v1'
META = ROOT / 'staging/navigation-v3-gmp-first-metadata-control-v1'
PINS = {
    BASE / 'proof.json': '7b5315087aebfda01db11d72bc206aaba23780031d90b92edcfcee3c0188c41a',
    BASE / 'plan.json': '8c45831edac70c2b17b187136acf38f8767eb7c617f59afd38dd9c9156fda5f0',
    BASE / 'sealed-files.json': '8cdbc17f8c8bf8f3210de5d08208c92148fdd23ece02d6cb5008d790c23ddf0d',
    META / 'proof.json': 'f5fa0022f3744e3e7bd8427661e945fc9a879baab004497294efbe6a99b9863f',
    META / 'execution-seal.json': '456eb76ca975f1453975bca207f11b58a297952eb664b873955a7cfcf4dce371',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def save(name, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    (OUT / name).chmod(0o444)
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def directory(raw, image_size):
    """Parse actual directory bytes, with no producer placement map as input."""
    block = 1 << (raw[0x61] + raw[0x62])
    assert block == 4096
    metadata_size = struct.unpack_from('<I', raw, 4108)[0]
    assert metadata_size == len(raw)
    count = image_size // block
    assert image_size == count * block
    owned = set(range(metadata_size // block))
    files = {}
    for at in range(4608, metadata_size, 512):
        row = raw[at:at + 512]
        if row[0] == 0:
            assert not any(row)
            continue
        assert row[0] == 1
        name = row[1:9].decode('ascii') + '.' + row[9:12].decode('ascii')
        value = files.setdefault(name, dict(size=None, blocks=[], rows=[]))
        part = struct.unpack_from('<H', row, 17)[0]
        assert part == len(value['rows'])
        size = struct.unpack_from('<I', row, 12)[0]
        if part == 0:
            value['size'] = size
        else:
            assert size == 0
        ended = False
        for number in struct.unpack_from('<240H', row, 32):
            if number == 0xFFFF:
                ended = True
            else:
                assert not ended and metadata_size // block <= number < count
                assert number not in owned
                owned.add(number)
                value['blocks'].append(number)
        value['rows'].append(at)
    assert owned == set(range(count)) and len(files) == 6
    for value in files.values():
        assert (value['size'] + block - 1) // block == len(value['blocks'])
    return block, files


class Projection:
    def __init__(self, stream, original, proposed, size):
        self.stream = stream
        self.metadata = proposed
        self.size = size
        self.source_bytes = 0
        self.calls = 0
        self.block, self.files = directory(proposed, size)
        old_block, old = directory(original, size)
        assert self.block == old_block and self.files.keys() == old.keys()
        mapping = {}
        for name, value in self.files.items():
            other = old[name]
            assert value['size'] == other['size'] and value['rows'] == other['rows']
            assert len(value['blocks']) == len(other['blocks'])
            for new, previous in zip(value['blocks'], other['blocks']):
                mapping[new] = previous
        self.mapping = mapping

    def read_at(self, offset, length):
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise ValueError('outside projected image')
        result = bytearray()
        self.calls += 1
        while length:
            if offset < len(self.metadata):
                n = min(length, len(self.metadata) - offset)
                result.extend(self.metadata[offset:offset + n])
            else:
                block, within = divmod(offset, self.block)
                previous = self.mapping[block]
                n = min(length, self.block - within)
                # Merge only consecutive source blocks from the decoded FAT map.
                while n < length and (within + n) % self.block == 0:
                    following = block + (within + n) // self.block
                    if self.mapping.get(following) != previous + (within + n) // self.block:
                        break
                    n += min(self.block, length - n)
                self.stream.seek(previous * self.block + within)
                chunk = self.stream.read(n)
                assert len(chunk) == n
                self.source_bytes += n
                result.extend(chunk)
            offset += n
            length -= n
        return bytes(result)

    def read_file_at(self, name, offset, length):
        value = self.files[name]
        if offset < 0 or length < 0 or offset > value['size'] or length > value['size'] - offset:
            raise ValueError('outside logical component')
        result = bytearray()
        while length:
            index, within = divmod(offset, self.block)
            n = min(length, self.block - within)
            result.extend(self.read_at(value['blocks'][index] * self.block + within, n))
            offset += n
            length -= n
        return bytes(result)


def main():
    assert not OUT.exists()
    inputs = {}
    for path, expected in PINS.items():
        raw = path.read_bytes()
        assert sha(raw) == expected
        inputs[str(path.relative_to(ROOT))] = dict(bytes=len(raw), sha256=expected)
    previous = json.loads((BASE / 'proof.json').read_text())
    seal = json.loads((BASE / 'sealed-files.json').read_text())
    metadata_seal = json.loads((META / 'sealed-files.json').read_text())
    source = ROOT / previous['output']
    frozen = next(f for f in seal['files'] if f['path'] == previous['output'])
    before = identity(source)
    assert before == frozen['frozen_stat'] and before[2] == 153337856
    raw_metadata = {}
    for file in metadata_seal['files']:
        if file['path'].endswith(('.bin', '.bin.disabled')):
            path = ROOT / file['path']
            raw = path.read_bytes()
            assert sha(raw) == file['sha256'] and len(raw) == file['bytes']
            inputs[file['path']] = dict(bytes=len(raw), sha256=file['sha256'])
            raw_metadata[path.name] = raw
    original = raw_metadata['original-metadata.bin']
    proposed = raw_metadata['gmp-first-metadata.bin.disabled']
    expected = {row['name']: row for row in previous['complete_actual_logical_component_readback']}
    image_hash = hashlib.sha256()
    receipts = []
    windows = []
    with source.open('rb') as stream:
        assert stream.read(len(original)) == original
        source_metadata_read = len(original)
        view = Projection(stream, original, proposed, before[2])
        image_hash.update(view.read_at(0, len(proposed)))
        order = sorted(view.files, key=lambda name: view.files[name]['blocks'][0])
        cursor = len(proposed)
        for name in order:
            entry = view.files[name]
            begin = entry['blocks'][0] * view.block
            assert begin == cursor
            assert entry['blocks'] == list(range(entry['blocks'][0], entry['blocks'][-1] + 1))
            allocated = len(entry['blocks']) * view.block
            logical_hash = hashlib.sha256()
            logical_left = entry['size']
            for at in range(0, allocated, 1 << 20):
                chunk = view.read_at(begin + at, min(1 << 20, allocated - at))
                image_hash.update(chunk)
                n = min(logical_left, len(chunk))
                logical_hash.update(chunk[:n])
                assert not any(chunk[n:])
                logical_left -= n
            assert logical_left == 0
            digest = logical_hash.hexdigest()
            assert digest == expected[name]['sha256'] and entry['size'] == expected[name]['logical_bytes']
            receipts.append(dict(name=name, logical_bytes=entry['size'], sha256=digest,
                                 allocated_bytes=allocated, zero_padding_bytes=allocated - entry['size'],
                                 projected_start=begin, projected_end=begin + allocated))
            cursor += allocated
        assert cursor == view.size
        # Separate logical FAT walks, including a block boundary and each final byte.
        _, old_files = directory(original, view.size)
        for name in order:
            entry = view.files[name]
            probes = [(max(0, entry['size'] - 33), min(33, entry['size']))]
            if entry['size'] > 4101:
                probes.append((4089, 23))
            for at, count in probes:
                actual = view.read_file_at(name, at, count)
                expected_bytes = bytearray()
                left, off = count, at
                while left:
                    block, within = divmod(off, view.block)
                    n = min(left, view.block - within)
                    stream.seek(old_files[name]['blocks'][block] * view.block + within)
                    chunk = stream.read(n)
                    assert len(chunk) == n
                    source_metadata_read += n  # count all direct verification reads below
                    expected_bytes.extend(chunk)
                    off += n
                    left -= n
                assert actual == bytes(expected_bytes)
                windows.append(dict(name=name, offset=at, bytes=count, SHA256=sha(actual)))
        # Physical reads spanning relocated component boundaries.
        for at in [len(proposed)] + [r['projected_end'] for r in receipts[:-1]]:
            joined = view.read_at(at - 11, 29)
            split = view.read_at(at - 11, 11) + view.read_at(at, 18)
            assert joined == split
        for at, count in [(-1, 1), (0, -1), (view.size, 1), (view.size + 1, 0)]:
            try:
                view.read_at(at, count)
            except ValueError:
                pass
            else:
                raise AssertionError('bounds guard did not reject')
        assert view.read_at(view.size, 0) == b''
        actual_bytes = view.source_bytes + source_metadata_read
        calls = view.calls
    assert identity(source) == before
    OUT.mkdir(mode=0o700)
    saved = [save('producer-source.py', Path(__file__).read_bytes()), save('input-pins.json', inputs),
             save('logical-window-witnesses.json', windows)]
    result = dict(schema='complete-projected-GMP-first-image-byte-verification/v1',
        all_assigned_checks_passed=True, complete_projected_stream_bytes=before[2],
        projected_stream_sha256=image_hash.hexdigest(), full_projected_stream_hashed=True,
        actual_existing_IMG_bytes_read=actual_bytes, projected_read_calls=calls,
        source=previous['output'], frozen_source_stat_unchanged=before,
        source_full_SHA_inherited_not_rehashed=previous['output_sha256'],
        six_logical_components_reverified_from_actual_source=True, components=receipts,
        logical_FAT_boundary_and_tail_windows_verified=len(windows),
        physical_component_crossings_verified=6, projected_bounds_controls_verified=5,
        all_tail_padding_zero=True, source_handles_closed=True,
        new_full_IMG_created=False, duplicate_large_payload_bytes_written=0,
        only_small_source_pins_witnesses_and_proof_written=True,
        original_renderer_or_AP_admission_executed=False, native_CPU_executed=False,
        actual_128MiB_guard_proved=False, v3_regression_fixed=False,
        device_IO=False, installable=False, installer_and_public_download_unchanged=True,
        current_device_v2_unchanged=True, full_goal_complete=False,
        limits=['This is a complete virtual byte stream, not an on-disk relocated IMG.',
                'Reverified component bytes do not prove original renderer acceptance.',
                'Original opaque header checksum/CHS and expanded capacity remain unchanged from the preceding experiment.',
                'Physical device comparison is pending the user independently notifying their return.'])
    saved.append(save('proof.json', result))
    save('sealed-files.json', dict(files=saved, all_assigned_checks_passed=True,
                                  source_handles_closed=True, installable=False))
    print(json.dumps(dict(all_assigned_checks_passed=True, projected_bytes=before[2],
        projected_sha256=result['projected_stream_sha256'], actual_IMG_bytes_read=actual_bytes,
        full_IMG_created=False, six_components_verified=True, device_IO=False)))


if __name__ == '__main__':
    main()
