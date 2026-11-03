#!/usr/bin/env python3
"""Inspect hidden backup font candidates; byte transform is an inference.

These files are read only. This does not execute the native external-font
reader, establish actual boot loading, render Chinese, or install fonts.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED, NativeImage
from analyze_native_player_fonts import cmap_glyph


def main():
    backup = ROOT/'backups/20261002T154458Z/files/.System/ExtData'
    inventory = json.loads((ROOT/'staging/native-player-text/embedded-font-tables.json').read_text())
    rows = []
    paths = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_native_player_fonts.py', ROOT/'staging/native-player-text/embedded-font-tables.json']
    im = NativeImage()
    for path in sorted(backup.glob('006-D0952-*.bin')):
        raw = path.read_bytes()
        decoded = bytes(b ^ 0x76 for b in raw)
        assert decoded[:4] == b'\x00\x01\x00\x00'
        count = struct.unpack_from('>H', decoded, 4)[0]
        assert 0 < count < 100 and 12+16*count <= len(decoded)
        tables = {}
        for k in range(count):
            tag, checksum, offset, length = struct.unpack_from('>4sIII', decoded, 12+16*k)
            tag = tag.decode('ascii')
            assert tag not in tables and offset+length <= len(decoded)
            tables[tag] = dict(checksum=hex(checksum), offset=offset, length=length)
        assert {'head', 'name', 'cmap', 'glyf', 'loca', 'maxp'} <= set(tables)
        offset, length = tables['name']['offset'], tables['name']['length']
        form, records, strings = struct.unpack_from('>HHH', decoded, offset)
        assert form in [0, 1] and 6+records*12 <= length
        names = []
        for k in range(records):
            platform, encoding, language, kind, size, position = struct.unpack_from('>6H', decoded, offset+6+12*k)
            assert strings+position+size <= length
            if platform in [0, 3] and kind in [1, 2, 4, 6]:
                text = decoded[offset+strings+position:offset+strings+position+size].decode('utf-16-be')
                names.append(dict(name_ID=kind, text=text, platform=platform, encoding=encoding, language=language))
        names = list({json.dumps(n, sort_keys=True): n for n in names}.values())
        family_names = {n['text'] for n in names if n['name_ID'] == 1}
        related = [r['index'] for r in inventory['fonts'] if r['kind'] != 2 and
            r['external_family_name'] in {n['text'] for n in names}]
        ct = tables['cmap']
        glyphs = {hex(ord(c)): cmap_glyph(decoded[ct['offset']:ct['offset']+ct['length']], ord(c))
            for c in 'Pi播放器竺原'}
        rows.append(dict(file=str(path.relative_to(ROOT)), bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
            inferred_decoded_sha256=hashlib.sha256(decoded).hexdigest(), candidate_transform='each byte XOR 0x76',
            table_count=count, table_ranges_within_file=True, tables=tables, Unicode_names=names,
            families=sorted(family_names), matching_native_descriptor_indices=related, cmap_glyph_queries=glyphs,
            native_external_font_decoder_executed=False, actual_loading_or_rendering_verified=False))
        paths.append(path)
    assert len(rows) == 8
    chinese = next(r for r in rows if 'DFHeiW5-A' in r['families'])
    assert all(any(g['glyph'] for g in chinese['cmap_glyph_queries'][hex(ord(c))]) for c in '播放器竺原')
    proof = dict(updated_utc=datetime.now(timezone.utc).isoformat(), MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        files=rows, candidate_count=len(rows), Chinese_candidate=chinese['file'],
        hidden_backup_directory_included=True, backup_files_modified=False, device_io=False,
        native_byte_transform_recovered_or_executed=False, native_external_font_loading_verified=False,
        actual_Chinese_UI_rendering_verified=False,
        limits='XOR0x76 is inferred from eight valid reconstructed sfnt headers, bounded tables and native-matching names. '
        'The native external-resource reader/byte transform has not yet been recovered or executed. '
        'Static cmap presence is not native glyph lookup, boot/resource loading, actual display or App installation.')
    out = ROOT/'staging/native-player-external-fonts'
    out.mkdir(exist_ok=True)
    (out/'candidate-inventory.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(candidates=len(rows), Chinese_candidate=chinese['file'],
        native_loading_verified=False, device_io=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
