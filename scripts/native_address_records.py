"""Pure offline stock-AP packed-record serialization, bounded to known layouts.

No file, IMG, database, firmware or device operations. Logical label references
are caller inputs; this module does not allocate labels or construct a map.
"""
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP

UINT32_SENTINEL = 0xFFFFFFFF

# Exact profiles from the original six-record directory consumer. Slots 6 and
# 7 have no demonstrated record meaning and must remain zero.
VERIFIED_LAYOUTS = {
    ((16, 9, 24, 19, 1, 10, 0, 0), (1, 1), 122),
    ((22, 9, 24, 19, 1, 12, 0, 0), (1, 0), 111),
    ((22, 9, 24, 19, 1, 10, 0, 0), (1, 1), 128),
    ((21, 9, 24, 19, 1, 9, 0, 0), (1, 1), 126),
    ((0, 0, 24, 19, 1, 0, 0, 0), (1, 0), 68),
}


def _integer(value, name):
    if type(value) is not int:
        raise ValueError(name + ' must be an explicit integer')
    return value


@dataclass(frozen=True)
class RecordLayout:
    widths: tuple[int, ...]
    reference_flags: tuple[int, int]  # primary(+10), secondary(+1C)
    record_bits: int

    def validate(self):
        if len(self.widths) != 8 or len(self.reference_flags) != 2:
            raise ValueError('exact eight widths and two reference flags required')
        if any(type(x) is not int or not 0 <= x <= 32 for x in self.widths):
            raise ValueError('widths must be explicit 0..32 integers')
        if self.widths[6] or self.widths[7]:
            raise ValueError('unverified width slots 6/7 are rejected')
        if any(type(x) is not int or x not in (0, 1) for x in self.reference_flags):
            raise ValueError('unverified reference flag bits are rejected')
        identity = (self.widths, self.reference_flags, self.record_bits)
        if identity not in VERIFIED_LAYOUTS:
            raise ValueError('layout is outside the original verified directory profiles')
        w = self.widths
        consumed = w[4] + sum(self.reference_flags) * w[3] + w[0] + w[5] + w[1] + 2 * w[2]
        if consumed != self.record_bits:
            raise ValueError('conditional fields differ from native record stride')


@dataclass(frozen=True)
class AddressRecord:
    mapordinal: int
    primary_ref: int | None
    secondary_ref: int | None
    first_child: int
    child_count: int
    child_level_and_flags: int  # Preserve complete +04; only low3bits are named.
    raw_location_a: int
    raw_location_b: int

    @property
    def next_level(self):
        return self.child_level_and_flags & 7


@dataclass(frozen=True)
class EncodedRecord:
    payload: bytes
    initial_bit_offset: int
    used_bits: int
    field_plan: tuple[dict, ...]


def encode_record(layout: RecordLayout, record: AddressRecord, *, initial_bit_offset=0,
                  pad_to_bytes=0) -> EncodedRecord:
    """Encode only this record's LSB-first bits; outside bits are zero padding.

    None is the explicit missing-reference sentinel. Non-sentinel refs may not
    use the all-ones bit pattern because the original reader maps it to -1.
    """
    layout.validate()
    _integer(initial_bit_offset, 'initial bit offset')
    _integer(pad_to_bytes, 'buffer padding size')
    if not 0 <= initial_bit_offset <= 7 or not 0 <= pad_to_bytes <= 64:
        raise ValueError('bounded initial offset / small buffer required')
    w, flags = layout.widths, layout.reference_flags
    values = (record.mapordinal, record.primary_ref, record.secondary_ref,
              record.first_child, record.child_count, record.child_level_and_flags,
              record.raw_location_a, record.raw_location_b)
    for name, value in zip(('mapordinal', 'first_child', 'child_count', 'child_level_and_flags',
                            'raw_location_a', 'raw_location_b'),
                           (values[0], values[3], values[4], values[5], values[6], values[7])):
        _integer(value, name)
    if record.mapordinal != 1:
        raise ValueError('only the source-proved AP mapordinal1 is supported')
    if record.child_count:
        if record.first_child < 1 or not 1 <= record.next_level <= 6:
            raise ValueError('nonempty child range needs one-based first ID and known next level')
    elif record.first_child != 0 or record.child_level_and_flags != 0:
        raise ValueError('leaf record requires explicit zero child fields')
    # Output offsets match original reader order, not C struct member order.
    sequence = (
        ('mapordinal', '+08', w[4], True, record.mapordinal, False),
        ('secondary_ref', '+1c', w[3], bool(flags[1]), record.secondary_ref, True),
        ('primary_ref', '+10', w[3], bool(flags[0]), record.primary_ref, True),
        ('first_child', '+00', w[0], bool(w[0]), record.first_child, False),
        ('child_count', '+0c', w[5], bool(w[5]), record.child_count, False),
        ('child_level_and_flags', '+04', w[1], bool(w[1]), record.child_level_and_flags, False),
        ('raw_location_a', '+14', w[2], bool(w[2]), record.raw_location_a, False),
        ('raw_location_b', '+18', w[2], bool(w[2]), record.raw_location_b, False),
    )
    bits, cursor, plan = 0, initial_bit_offset, []
    for name, offset, width, enabled, value, reference in sequence:
        if not enabled:
            invalid_absent = (value is not None) if reference else (value != 0)
            if invalid_absent:
                raise ValueError(name + ' is absent in this original layout')
            encoded = None
        else:
            maximum = (1 << width) - 1
            if reference and value is None:
                encoded = maximum
            else:
                _integer(value, name)
                if not 0 <= value <= maximum or (reference and value == maximum):
                    raise ValueError(name + ' overflows width or collides with reference sentinel')
                encoded = value
            bits |= encoded << cursor
            cursor += width
        plan.append({'field': name, 'output_offset': offset, 'width': width,
                     'enabled': enabled, 'wire_value': encoded,
                     'record_bits_consumed': cursor - initial_bit_offset})
    if cursor - initial_bit_offset != layout.record_bits:
        raise ValueError('native stride mismatch')
    size = max((cursor + 7) // 8, pad_to_bytes)
    return EncodedRecord(bits.to_bytes(size, 'little'), initial_bit_offset,
                         layout.record_bits, tuple(plan))


def quantize_point24(latitude, longitude):
    """Explicit prototype policy: nearest signed 24-bit global-circle grid.

    A record's raw24 <<8 rescale is source backed. Signed-circle geographic
    meaning and this rounding policy remain explicit host prototype choices;
    no claim of the stock compiler's rounding or a verified house location.
    """
    lat, lon = Decimal(str(latitude)), Decimal(str(longitude))
    if not lat.is_finite() or not lon.is_finite() or not -90 <= lat <= 90 or not -180 <= lon < 180:
        raise ValueError('bounded finite latitude/longitude required')
    result = []
    for degrees in (lat, lon):
        signed = int((degrees * Decimal(1 << 24) / Decimal(360)).to_integral_value(rounding=ROUND_HALF_UP))
        if not -(1 << 23) <= signed < (1 << 23):
            raise ValueError('signed 24-bit point overflow')
        quantized = Decimal(signed) * Decimal(360) / Decimal(1 << 24)
        result.append({'input_degrees': str(degrees), 'signed24': signed, 'wire_u24': signed & 0xFFFFFF,
                       'quantized_degrees': str(quantized), 'error_degrees': str(quantized - degrees)})
    return {'latitude': result[0], 'longitude': result[1],
            'policy': 'Nearest grid, Decimal ROUND_HALF_UP (ties away from zero); stock rounding unknown.',
            'quantum_degrees': str(Decimal(360) / Decimal(1 << 24)),
            'source_backed_raw_shift': 8, 'complete_native_coordinate_getter_proved_here': False}
