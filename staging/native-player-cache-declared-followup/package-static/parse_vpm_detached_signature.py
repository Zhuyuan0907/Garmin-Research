#!/usr/bin/env python3
"""Pure bounded reader for original OpenPGP v4 DSA/SHA1 signatures.

RFC4880 sections4.2,5.2.3,5.2.4,9.1,9.4 define these fields.
This module parses bytes and computes a candidate document digest only.
It does not find a trusted key, verify DSA, generate signatures, modify a
package, execute native code, or establish Garmin enforcement.
"""
import hashlib


class SignatureFormatError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise SignatureFormatError(message)


def bounded(data, offset, count):
    need(0 <= offset <= len(data) and 0 <= count <= len(data)-offset,
         'Truncated bounded signature field')
    return data[offset:offset+count]


def scalar(data, offset, count):
    return int.from_bytes(bounded(data, offset, count), 'big')


def variable_length(data, offset, subpacket=False):
    first = scalar(data, offset, 1)
    if first < 192:
        return first, 1
    if first < 224 or (subpacket and first < 255):
        return ((first-192) << 8)+scalar(data, offset+1, 1)+192, 2
    if first == 255:
        return scalar(data, offset+1, 4), 5
    raise SignatureFormatError('Partial length outside this bounded signature scope')


def subpackets(data, start, length):
    stop = start+length
    bounded(data, start, length)
    rows = []
    cursor = start
    while cursor < stop:
        count, prefix = variable_length(data, cursor, subpacket=True)
        need(count >= 1 and prefix+count <= stop-cursor,
             'Subpacket crosses its declared bounded area')
        kind = scalar(data, cursor+prefix, 1)
        payload = bounded(data, cursor+prefix+1, count-1)
        row = dict(offset=cursor, length_prefix_bytes=prefix,
                   encoded_body_bytes=count, type=kind & 127,
                   critical=bool(kind & 128), payload_offset=cursor+prefix+1,
                   payload_hex=payload.hex())
        if row['type'] == 2:
            need(len(payload) == 4, 'Creation-time subpacket has wrong length')
            row['creation_time_unix_seconds'] = int.from_bytes(payload, 'big')
        if row['type'] == 16:
            need(len(payload) == 8, 'Issuer subpacket has wrong length')
            row['issuer_key_ID_hex'] = payload.hex()
        rows.append(row)
        cursor += prefix+count
    need(cursor == stop, 'Subpacket area did not end exactly')
    return rows


def parse_v4_dsa_sha1_signature(raw):
    data = bytes(raw)
    first = scalar(data, 0, 1)
    need(first & 128, 'Packet header lacks required leading bit')
    if first & 64:
        packet_tag = first & 63
        length, length_bytes = variable_length(data, 1)
        header_bytes = 1+length_bytes
        header_format = 'new'
    else:
        packet_tag = (first >> 2) & 15
        length_type = first & 3
        need(length_type != 3, 'Indeterminate packet length outside bounded scope')
        length_bytes = [1, 2, 4][length_type]
        length = scalar(data, 1, length_bytes)
        header_bytes = 1+length_bytes
        header_format = 'old'
    need(packet_tag == 2 and header_bytes+length == len(data),
         'Expected one complete Signature packet and no trailing bytes')
    need(length <= 65535, 'Signature body exceeds bounded local scope')
    body = header_bytes
    version, signature_type, public_algorithm, hash_algorithm = bounded(data, body, 4)
    need((version, signature_type, public_algorithm, hash_algorithm) == (4, 0, 17, 2),
         'Outside exact v4 binary-document DSA/SHA1 signature scope')
    hashed_count_offset = body+4
    hashed_count = scalar(data, hashed_count_offset, 2)
    hashed_start = body+6
    hashed = subpackets(data, hashed_start, hashed_count)
    unhashed_count_offset = hashed_start+hashed_count
    unhashed_count = scalar(data, unhashed_count_offset, 2)
    unhashed_start = unhashed_count_offset+2
    unhashed = subpackets(data, unhashed_start, unhashed_count)
    hash_prefix_offset = unhashed_start+unhashed_count
    hash_prefix = bounded(data, hash_prefix_offset, 2)
    cursor = hash_prefix_offset+2
    mpis = []
    for name in ['r', 's']:
        bits = scalar(data, cursor, 2)
        need(0 < bits <= 4096, 'DSA MPI outside bounded positive-integer scope')
        count = (bits+7)//8
        integer = bounded(data, cursor+2, count)
        need(int.from_bytes(integer, 'big').bit_length() == bits,
             'MPI declared bit count differs from canonical integer')
        mpis.append(dict(name=name, bit_count_offset=cursor, bits=bits,
                         integer_offset=cursor+2, integer_bytes=count,
                         integer_hex=integer.hex()))
        cursor += 2+count
    need(cursor == len(data), 'DSA signature fields leave trailing bytes')
    hashed_fields = bounded(data, body, unhashed_count_offset-body)
    trailer = b'\x04\xff'+len(hashed_fields).to_bytes(4, 'big')
    return dict(packet_header_format=header_format, packet_tag=packet_tag,
                packet_header_offset=0, packet_header_bytes=header_bytes,
                packet_header_hex=data[:header_bytes].hex(), body_offset=body,
                body_bytes=length, complete_packet_bytes=len(data),
                version=dict(offset=body, value=version),
                signature_type=dict(offset=body+1, value=signature_type, name='binary document'),
                public_key_algorithm=dict(offset=body+2, value=public_algorithm, name='DSA'),
                hash_algorithm=dict(offset=body+3, value=hash_algorithm, name='SHA1'),
                hashed_subpacket_length=dict(offset=hashed_count_offset, bytes=2, value=hashed_count),
                hashed_subpackets=hashed,
                unhashed_subpacket_length=dict(offset=unhashed_count_offset, bytes=2, value=unhashed_count),
                unhashed_subpackets=unhashed,
                left16_digest=dict(offset=hash_prefix_offset, bytes=2, hex=hash_prefix.hex()),
                signature_MPIs=mpis, fully_consumed=True,
                hashed_signature_fields_hex=hashed_fields.hex(), v4_trailer_hex=trailer.hex(),
                issuer_in_unhashed_area_is_advisory_not_authenticated_identity=True,
                cryptographic_DSA_verification_performed=False,
                Garmin_reader_or_enforcement_proven=False)


def candidate_document_association(document, parsed):
    hashed_fields = bytes.fromhex(parsed['hashed_signature_fields_hex'])
    trailer = bytes.fromhex(parsed['v4_trailer_hex'])
    digest = hashlib.sha1(bytes(document)+hashed_fields+trailer).digest()
    return dict(document_bytes=len(document), document_sha256=hashlib.sha256(document).hexdigest(),
                candidate_signed_digest_SHA1_hex=digest.hex(),
                candidate_left16_hex=digest[:2].hex(),
                stored_left16_hex=parsed['left16_digest']['hex'],
                left16_matches=digest[:2].hex() == parsed['left16_digest']['hex'],
                compared_digest_bits=16, full_DSA_or_trust_verification=False)
