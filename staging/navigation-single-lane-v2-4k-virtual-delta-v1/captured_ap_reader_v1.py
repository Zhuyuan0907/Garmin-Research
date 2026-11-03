# Ordinary read-only parser of actual captured virtual-stream windows; no writer/native import.
import hashlib
import struct
from pathlib import Path
ROOT = Path('/root/garmin')
LIMIT = 2 * 1024 * 1024
NAMES = ('00004171.MD2', '00004171.MDR', '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')
READS = []
OPEN_HANDLES = []


def need(test, reason):
    if not test:
        raise ValueError(reason)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

class Image:
    # Adapted read-only allocation mapping from sealed independent Image8K.
    # Explicit block_bytes permits actual v2 4K and actual v3 8K; not a writer.
    def __init__(self, name, handle, size, block_bytes):
        self.name, self.path, self.block_bytes = name, Path("actual-virtual-stream"), block_bytes
        self.size = size
        self.f = handle
        need(self.size > 0 and self.size % block_bytes == 0, 'Whole physical blocks')
        h = self.physical(0, 512, 'actual AP header')
        self.header = h
        need(h[0] == 0 and h[16:23] == b'DSKIMG\0' and h[65:72] == b'GARMIN\0' and h[510:512] == b'\x55\xaa', 'AP markers/XOR0')
        need((h[97], h[98]) == (9, 3 if block_bytes == 4096 else 4), 'Actual block exponent profile')
        blocks = struct.unpack_from('<H', h, 99)[0]
        sectors = struct.unpack_from('<I', h, 458)[0]
        self.capacity = blocks * block_bytes
        need(blocks == 32768 and self.capacity == sectors * 512 and self.size <= self.capacity, 'Coherent declared capacity')
        start = h[64] * 512
        need(512 <= start < self.size, 'Root directory start')
        root = self.physical(start, 512, 'actual root DIR row')
        need(root[0] == 1 and root[1:12] == b' ' * 11 and root[16] == 3 and struct.unpack_from('<H', root, 17)[0] == 0, 'Canonical root DIR')
        end = struct.unpack_from('<I', root, 12)[0]
        need(start + 512 <= end <= min(self.size, 1000000) and end % block_bytes == 0, 'Bounded aligned metadata extent')
        need(self.blocks(root) == tuple(range(end // block_bytes)), 'Metadata allocation exact')
        directory = root + self.physical(start + 512, end - start - 512, 'actual bounded FAT allocation rows')
        owners = {n: '<metadata>' for n in range(end // block_bytes)}
        components, order, last = {}, [], None
        for at in range(512, len(directory), 512):
            row = directory[at:at + 512]
            if row[0] == 0:
                need(row == bytes(512), 'Unused FAT row zero')
                continue
            need(row[0] == 1 and row[16] != 3, 'Allocated component row')
            name = row[1:9].decode('ascii').rstrip(' ') + '.' + row[9:12].decode('ascii').rstrip(' ')
            part = struct.unpack_from('<H', row, 17)[0]
            size = struct.unpack_from('<I', row, 12)[0]
            if part == 0:
                need(name not in components and size > 0, 'Unique component')
                components[name] = {'size': size, 'blocks': [], 'part_count': 0}
                order.append(name)
                last = name
            need(name == last and part == components[name]['part_count'], 'Ordered FAT continuation')
            need(part == 0 or size == 0, 'Continuation size zero')
            ids = self.blocks(row)
            need(bool(ids), 'Nonempty allocated part')
            for b in ids:
                need(b not in owners, 'No overlapping block allocation')
                owners[b] = name
            components[name]['blocks'].extend(ids)
            components[name]['part_count'] += 1
        need(tuple(order) == NAMES, 'Exact six component names/order')
        for c in components.values():
            need(len(c['blocks']) == (c['size'] + block_bytes - 1) // block_bytes, 'Logical allocation count')
            need(c['part_count'] == (len(c['blocks']) + 239) // 240, 'Allocation part count')
        need(set(owners) == set(range(self.size // block_bytes)), 'No unallocated physical blocks')
        self.components = components
        self.metadata_start, self.metadata_end = start, end

    def blocks(self, row):
        result, sentinel = [], False
        for b in struct.unpack_from('<240H', row, 32):
            if b == 65535:
                sentinel = True
            else:
                need(not sentinel and b < self.size // self.block_bytes, 'Block after sentinel/outside image')
                result.append(b)
        return tuple(result)

    def physical(self, at, n, reason):
        need(type(at) is int and type(n) is int and 0 <= at <= at + n <= self.size, 'Physical range bounds')
        need(sum(x['bytes'] for x in READS) + n <= LIMIT, 'Global 2MiB IMG read budget')
        self.f.seek(at)
        b = self.f.read(n)
        need(len(b) == n, 'Complete actual physical read')
        READS.append({'source': self.name, 'path': str(self.path), 'physical_offset': at,
                      'bytes': n, 'SHA256': sha(b), 'purpose': reason})
        return b

    def logical(self, name, at, n, reason):
        c = self.components[name]
        need(0 <= at <= at + n <= c['size'], 'Logical range bounds')
        result, cursor = bytearray(), at
        while cursor < at + n:
            ordinal, within = divmod(cursor, self.block_bytes)
            amount = min(at + n - cursor, self.block_bytes - within)
            result.extend(self.physical(c['blocks'][ordinal] * self.block_bytes + within, amount,
                                       reason + '; ' + name + ' logical ' + str(cursor)))
            cursor += amount
        return bytes(result)

    def close(self):
        pass  # No filesystem IMG output exists; handle reads only actual captured output windows.

def decode_parent(raw, initial_shift, table):
    value = int.from_bytes(raw, 'little') >> initial_shift & ((1 << table['stride']) - 1)
    widths, refs = table['widths'], table['refs']
    cursor, result = 0, {}
    for name, width, on, isref in [('mapordinal', widths[4], True, False),
          ('secondary_ref', widths[3], bool(refs[1]), True), ('primary_ref', widths[3], bool(refs[0]), True),
          ('first_child', widths[0], bool(widths[0]), False), ('child_count', widths[5], bool(widths[5]), False),
          ('raw_flags', widths[1], bool(widths[1]), False), ('raw_location_a', widths[2], bool(widths[2]), False),
          ('raw_location_b', widths[2], bool(widths[2]), False)]:
        v = value >> cursor & ((1 << width) - 1) if on else None if isref else 0
        result[name] = None if on and isref and v == (1 << width) - 1 else v
        cursor += width if on else 0
    need(cursor == table['stride'], 'Full descriptor-based bit decode')
    result.update({'raw_record_value': value, 'raw_record_hex': raw.hex(), 'initial_bit_shift': initial_shift,
                   'next_level': result['raw_flags'] & 7})
    return result
