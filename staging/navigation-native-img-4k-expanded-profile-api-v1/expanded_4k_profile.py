#!/usr/bin/env python3
"""Experimental AP4K expanded capacity/header planning, never image writing.

The old 128MiB writer is not imported or changed. This module prepares bounded
metadata for offline controls only. It does not implement an accepted AP
container, native renderer, checksum, image writer, installer or device API.
"""
from dataclasses import dataclass
import hashlib
import struct

BLOCK_BYTES = 4096
SECTOR_BYTES = 512
SOURCE_BLOCKS = 32768
SOURCE_SECTORS = 262144
MAX_DECLARED_BLOCKS = 65534
SOURCE_HEADER_SHA256 = 'b8afc5f2833a380541e1caf6ce729cb523bcf16739769f935ce17fbd9fbeb191'
NAMES = ('00004171.MD2', '00004171.MDR', '00004171.SRT',
         'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')


class Rejection(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Rejection(message)


def finite(value, name, low=0, high=0xffffffff):
    need(type(value) is int and low <= value <= high, name + ' outside explicit integer range')
    return value


def aligned(value, multiple):
    return ((value + multiple - 1) // multiple) * multiple


@dataclass(frozen=True)
class HeaderBinding:
    raw: bytes
    source_kind: str
    sha256: str


@dataclass(frozen=True)
class ComponentAllocation:
    name: str
    logical_bytes: int
    block_count: int
    first_block: int
    end_block_exclusive: int
    fat_parts: int


@dataclass(frozen=True)
class Expanded4KPlan:
    binding: HeaderBinding
    components: tuple[ComponentAllocation, ...]
    directory_rows: int
    metadata_bytes: int
    metadata_blocks: int
    image_blocks: int
    image_bytes: int
    declared_blocks: int
    declared_sectors: int
    declared_capacity_bytes: int

    @property
    def installable(self):
        return False

    def require_installable(self):
        raise Rejection('Expanded4K header/checksum/AP admission policy is incomplete; installation is prohibited')

    def report(self):
        return {
            'schema': 'experimental-explicit-AP4K-expanded-profile-plan/v1',
            'source_kind': self.binding.source_kind, 'source_header_sha256': self.binding.sha256,
            'block_bytes': BLOCK_BYTES, 'exponents': [9, 3],
            'directory_start': 4096, 'directory_rows': self.directory_rows,
            'metadata_bytes': self.metadata_bytes, 'metadata_blocks': self.metadata_blocks,
            'image_blocks': self.image_blocks, 'image_bytes': self.image_bytes,
            'declared_blocks': self.declared_blocks, 'declared_sectors': self.declared_sectors,
            'declared_capacity_bytes': self.declared_capacity_bytes,
            'highest_allocated_block': self.image_blocks - 1,
            'component_allocations': [c.__dict__ for c in self.components],
            'planned_header_fields': [
                {'offset': '0x63', 'bytes': 2, 'original': SOURCE_BLOCKS, 'planned': self.declared_blocks},
                {'offset': '0x1ca', 'bytes': 4, 'original': SOURCE_SECTORS, 'planned': self.declared_sectors},
            ],
            'byte_0x0F_policy': 'Preserve exact source byte219; do not synthesize or zero an unknown checksum.',
            'CHS_policy': 'Keep original CHS fields unchanged for a narrow experimental patch; expanded-size coherence/acceptance is not proved.',
            'unknown_policy_fields': [
                '0x0F original AP checksum algorithm, covered ranges and high-level enforcement',
                '0x18/0x1A/0x1C and0x5D/0x5F CHS capacity meaning/enforcement for an expanded AP',
                '0x1BF..0x1C5 partition CHS mirror consistency/enforcement',
                'Opaque source header fields including0x24..0x38 and0x83 onward',
                'AP high-level admission/map-layer registry/ownership/priority/rendering policy',
            ],
            'unsigned16_FAT_bound_respects_0xFFFF_sentinel': True,
            'six_component_bytes_must_be_supplied_and_verified_separately': True,
            'original_writer_capacity_guard_changed': False,
            'generic_DSKIMG_parser_not_claimed_AP_renderer': True,
            'installable': False, 'device_verified': False, 'checksum_verified': False,
            'full_IMG_writer_implemented': False, 'current_rendering_bug_fixed': False,
        }


def bind_original_4k_header(raw, *, source_kind):
    """Bind either an explicit synthetic fixture or the exact sealed AP header.

    This is metadata identity only. Even a real sealed header binding never
    grants installation or AP renderer/admission claims.
    """
    need(type(raw) is bytes and len(raw) == 512, 'Expected exactly512 immutable header bytes')
    need(source_kind in ('synthetic-fixture', 'sealed-stock-header'), 'Source provenance must be explicit')
    need(raw[0] == 0 and raw[16:23] == b'DSKIMG\0' and raw[65:72] == b'GARMIN\0' and
         raw[510:512] == b'\x55\xaa', 'Exact XOR0/DSKIMG/GARMIN/end signature required')
    need(raw[97:99] == b'\x09\x03' and raw[64] == 8, 'Exact original4KiB/directory profile required')
    need(raw[15] == 219, 'Original opaque byte0x0F must be retained as219')
    need(all(struct.unpack_from('<H', raw, at)[0] == value for at, value in
        ((0x18, 16), (0x1a, 16), (0x1c, 1024), (0x5d, 16), (0x5f, 16), (0x63, SOURCE_BLOCKS))) and
         struct.unpack_from('<I', raw, 0x1ca)[0] == SOURCE_SECTORS, 'Exact original geometry/count declaration required')
    digest = hashlib.sha256(raw).hexdigest()
    if source_kind == 'sealed-stock-header':
        need(digest == SOURCE_HEADER_SHA256, 'Sealed original AP header hash mismatch')
    return HeaderBinding(raw, source_kind, digest)


def plan_expanded_4k(binding, component_sizes, *, declared_blocks):
    """Plan exact six-component capacity/ranges without reading any payload.

    Explicit expanded declaration is mandatory. This is not a fallback around
    the stock-profile capacity guard. No source data or file is allocated.
    """
    need(type(binding) is HeaderBinding, 'Validated immutable header binding required')
    # Revalidate a forged dataclass rather than treating its type as authority.
    checked = bind_original_4k_header(binding.raw, source_kind=binding.source_kind)
    need(checked == binding, 'Header binding identity changed')
    need(type(component_sizes) in (tuple, list) and len(component_sizes) == len(NAMES), 'Exactly six explicit component size pairs required')
    rows = []
    for index, pair in enumerate(component_sizes):
        need(type(pair) in (tuple, list) and len(pair) == 2, 'Invalid component size pair')
        name, size = pair
        need(name == NAMES[index], 'Exact unique original component names/order required')
        finite(size, 'Component logical size', 1)
        count = (size + BLOCK_BYTES - 1) // BLOCK_BYTES
        rows.append((name, size, count, (count + 239) // 240))
    finite(declared_blocks, 'Declared block count', SOURCE_BLOCKS + 1, MAX_DECLARED_BLOCKS)
    directory_rows = 1 + sum(parts for _, _, _, parts in rows)
    metadata_bytes = aligned(4096 + directory_rows * 512, BLOCK_BYTES)
    metadata_blocks = metadata_bytes // BLOCK_BYTES
    need(metadata_blocks <= 240, 'Root continuation is outside the supported single-row profile')
    image_blocks = metadata_blocks + sum(count for _, _, count, _ in rows)
    need(image_blocks > SOURCE_BLOCKS, 'Use the original profile for images within its128MiB declaration')
    need(image_blocks <= declared_blocks <= MAX_DECLARED_BLOCKS, 'Expanded declaration cannot cover all image allocations')
    image_bytes = image_blocks * BLOCK_BYTES
    declared_sectors = declared_blocks * (BLOCK_BYTES // SECTOR_BYTES)
    finite(image_bytes, 'Image bytes', 1)
    finite(declared_sectors, 'Declared sector mirror', 1)
    allocations, cursor = [], metadata_blocks
    for name, size, count, parts in rows:
        last = cursor + count
        need(0 <= cursor < last <= image_blocks and last <= declared_blocks and last - 1 < 65535,
             'Component allocation exceeds finite non-sentinel block bounds')
        allocations.append(ComponentAllocation(name, size, count, cursor, last, parts))
        cursor = last
    need(cursor == image_blocks, 'Allocation arithmetic left unowned blocks')
    return Expanded4KPlan(binding, tuple(allocations), directory_rows, metadata_bytes, metadata_blocks,
                          image_blocks, image_bytes, declared_blocks, declared_sectors, declared_blocks * BLOCK_BYTES)


def header_bytes_for_offline_control(plan):
    """Return a512-byte experimental patch in memory; no path/output API exists.

    Only declared count and LBA sector mirror change. All CHS, checksum and
    opaque fields remain exact source values, with unproved acceptance stated.
    """
    need(type(plan) is Expanded4KPlan and plan.installable is False, 'Experimental plan required')
    pairs = tuple((c.name, c.logical_bytes) for c in plan.components)
    need(plan_expanded_4k(plan.binding, pairs, declared_blocks=plan.declared_blocks) == plan,
         'Plan integrity changed')
    raw = bytearray(plan.binding.raw)
    struct.pack_into('<H', raw, 0x63, plan.declared_blocks)
    struct.pack_into('<I', raw, 0x1ca, plan.declared_sectors)
    allowed = {0x63, 0x64, 0x1ca, 0x1cb, 0x1cc, 0x1cd}
    need(all(a == b or at in allowed for at, (a, b) in enumerate(zip(plan.binding.raw, raw))), 'Unexpected experimental header change')
    need(raw[15] == plan.binding.raw[15] == 219 and raw[97:99] == b'\x09\x03', 'Opaque checksum/exponent policy changed')
    return bytes(raw)


def fat_row_for_offline_control(plan, component_name, part, template):
    """Render one512-byte FAT row in memory, retaining all opaque row metadata.

    This does not supply or validate component payloads or real continuation
    template uniformity. Never call it a completed container writer.
    """
    need(type(plan) is Expanded4KPlan, 'Expanded4K plan required')
    header_bytes_for_offline_control(plan)  # Validate complete plan integrity.
    need(type(template) is bytes and len(template) == 512, 'Exactly512 immutable template bytes required')
    component = next((c for c in plan.components if c.name == component_name), None)
    need(component is not None, 'Unknown component name')
    finite(part, 'FAT continuation ordinal', 0, component.fat_parts - 1)
    filename, extension = component_name.split('.')
    expected = filename.encode('ascii').ljust(8, b' ') + extension.encode('ascii').ljust(3, b' ')
    need(template[0] == 1 and template[1:12] == expected and template[16] != 3, 'Exact component FAT template identity required')
    start = component.first_block + part * 240
    end = min(start + 240, component.end_block_exclusive)
    need(start < end and end - 1 < 65535, 'Invalid FAT block range')
    raw = bytearray(template)
    struct.pack_into('<I', raw, 12, component.logical_bytes if part == 0 else 0)
    struct.pack_into('<H', raw, 17, part)
    values = list(range(start, end)) + [65535] * (240 - (end - start))
    struct.pack_into('<240H', raw, 32, *values)
    need(raw[:12] == template[:12] and raw[16] == template[16] and raw[19:32] == template[19:32],
         'Opaque FAT row metadata changed')
    return bytes(raw)
