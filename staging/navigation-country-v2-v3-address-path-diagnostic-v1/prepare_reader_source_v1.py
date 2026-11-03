#!/usr/bin/env python3
"""Extract pinned ordinary read-only code into a new isolated data namespace."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-country-v2-v3-address-path-diagnostic-v1'
OLD = ROOT / 'staging/navigation-v2-one-family-lane-delta-plan-v1'
seal_raw = (OLD / 'SEAL.json').read_bytes()
assert hashlib.sha256(seal_raw).hexdigest() == '002b36af0b15da6e74cf795eb34d658cf7b92de9892180933627884a97dbb863'
seal = json.loads(seal_raw)
path = OLD / 'read_exact_profile_parent_v1.py'
pin = next(x for x in seal['files'] if x['path'] == str(path.relative_to(ROOT)))
raw = path.read_bytes()
assert len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256']
text = raw.decode()
tree = ast.parse(text)
names = ['need', 'sha', 'stat', 'Image', 'decode_parent']
parts = {n.name: ast.get_source_segment(text, n) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names}
assert set(parts) == set(names)
old_class = parts['Image']
new_class = old_class.replace("self.f = p.open('rb')", "self.f = p.open('rb')\n        OPEN_HANDLES.append(self.f)")
assert new_class != old_class
parts['Image'] = new_class
header = '''# Ordinary FILE/bit reader copied from pinned previous scope; no writer/native import.
import hashlib
import struct
from pathlib import Path
ROOT = Path('/root/garmin')
LIMIT = 2 * 1024 * 1024
NAMES = ('00004171.MD2', '00004171.MDR', '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')
READS = []
OPEN_HANDLES = []
'''
new_raw = (header + '\n\n' + '\n\n'.join(parts[x] for x in names) + '\n').encode()
(OUT / 'bounded_ap_reader_v1.py').write_bytes(new_raw)
(OUT / 'reader-class.diff').write_text(''.join(difflib.unified_diff(old_class.splitlines(True), new_class.splitlines(True), fromfile='pinned_previous_Image', tofile='isolated_Image_with_handle_registry')))
(OUT / 'reader-dependency-manifest.json').write_text(json.dumps({'source': str(path.relative_to(ROOT)), 'source_bytes': len(raw), 'source_SHA256': pin['sha256'],
    'original_scope_seal_SHA256': hashlib.sha256(seal_raw).hexdigest(), 'copied_definitions': names,
    'class_only_change': 'register each opened readonly source handle for finally cleanup; no byte/bit/label policy change',
    'new_reader_bytes': len(new_raw), 'new_reader_SHA256': hashlib.sha256(new_raw).hexdigest(),
    'old_source_modified_or_executed': False, 'native_or_writer_module_imported': False}, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'status': 'isolated_ordinary_reader_source_prepared', 'new_reader_SHA256': hashlib.sha256(new_raw).hexdigest(), 'old_source_unchanged': True, 'IMG_bytes': 0}))
