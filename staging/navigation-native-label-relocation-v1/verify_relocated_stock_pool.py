"""Finite original-GMP relocation and original-instruction label verification.

Synthetic label text is explicitly a format fixture, never a navigable address.
This does not create an IMG, update JAI, perform a complete getter or use USB.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import struct
import sys

from relocate_lbl_pool import relocate_pool

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
DEPS = [
    ('staging/navigation-native-general-writer-v1/native_ap_writer.py',
     'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'),
    ('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
     'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04'),
]
GMP_SHA = '92d4a1aa7cf84ff17b092d74302fb4d432691bd6cd563ba8da4d7ed51f8d73bd'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    value = path.stat()
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_nlink]


def save(name, value):
    raw = value if type(value) is bytes else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    path = OUT / name
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'Complete new artifact write')
        stream.flush()
        os.fsync(stream.fileno())
    return dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def load(path, digest, name):
    raw = (ROOT / path).read_bytes()
    need(len(raw) < 100_000 and sha(raw) == digest, 'Pinned small helper source')
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod, raw


def relocated_parser(module, source):
    """Change one HOST expected-tuple assertion; original CPU code is unaltered."""
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'parser_case')
    function.args.args.append(ast.arg(arg='expected'))
    modifications = 0
    for node in ast.walk(function):
        if isinstance(node, ast.Tuple) and all(isinstance(item, ast.Constant) for item in node.elts):
            if [item.value for item in node.elts] == [6566, 3805432, 3, 10, 950]:
                node.elts = []  # Replace via NodeTransformer below.
                modifications += 1
    need(modifications == 1, 'Exactly one original host expected tuple')
    class Replace(ast.NodeTransformer):
        def visit_Tuple(self, node):
            if not node.elts:
                return ast.copy_location(ast.Name(id='expected', ctx=ast.Load()), node)
            return self.generic_visit(node)
    updated = ast.fix_missing_locations(Replace().visit(ast.Module(body=[function], type_ignores=[])))
    namespace = dict(vars(module))
    exec(compile(updated, '<new-relocated-parser-host-assertion>', 'exec'), namespace)
    return namespace['parser_case']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', action='append', required=True)
    parser.add_argument('--synthetic-labels', action='store_true')
    parser.add_argument('--source-example')
    args = parser.parse_args()
    need(args.synthetic_labels != bool(args.source_example), 'Choose explicit synthetic or source-bound text')
    need(not (OUT / 'actual-relocation-proof.json').exists(), 'Refuse overwrite previous actual proof')
    source_binding = None
    if args.source_example:
        path = ROOT / args.source_example
        raw = path.read_bytes()
        need(len(raw) <= 256_000, 'Bounded source example')
        source_binding = dict(path=args.source_example, bytes=len(raw), sha256=sha(raw))
    writer, _ = load(*DEPS[0], 'relocation_original_stream_reader')
    methods, helper_raw = load(*DEPS[1], 'relocation_original_label_fragments')
    primitive_sha = sha((OUT / 'relocate_lbl_pool.py').read_bytes())
    before_AP = stat(AP)
    with AP.open('rb') as stream:
        image = writer.StreamIMG(stream)
        need(image.components['I053061A.GMP'].size == 3812824, 'Exact stock GMP size')
        source = b''.join(image.iter_component('I053061A.GMP'))
        need(sha(source) == GMP_SHA, 'Actual original GMP equals inherited closed hash')
        reads = image.read_log
    need(stat(AP) == before_AP, 'Readonly original AP identity/stat unchanged')
    plan = relocate_pool(source, tuple(args.label))
    result = plan.component
    original = bytearray(result[:len(source)])
    original[plan.lbl_header_offset + 21:plan.lbl_header_offset + 29] = source[plan.lbl_header_offset + 21:plan.lbl_header_offset + 29]
    need(bytes(original) == source, 'Every original GMP byte except two pointer/size fields is retained')
    need(result[plan.new_pool_offset:plan.new_pool_offset + plan.original_pool_bytes] ==
         source[plan.original_pool_offset:plan.original_pool_offset + plan.original_pool_bytes],
         'Entire original label arena is copied byte-identically')
    need(plan.new_pool_offset >= len(source), 'New arena cannot overlap original unknown tables')
    header = result[plan.lbl_header_offset:plan.lbl_header_offset + 661]
    expected = (plan.new_pool_offset, plan.new_pool_bytes, 3, 10, 950)
    before_MAIN = stat(MAIN)
    code_reads = {}
    cases = []
    with MAIN.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as memory:
        def read(address, amount):
            key = (address, amount)
            load_at = address - 57525300 if 0x04400000 <= address < 0x0470CE18 else address
            need(0x50000 <= load_at and load_at + amount <= 0x50000 + len(memory), 'Verified MAIN copy mapping')
            raw = bytes(memory[load_at - 0x50000:load_at - 0x50000 + amount])
            code_reads[key] = dict(runtime=hex(address), load=hex(load_at), bytes=amount, sha256=sha(raw))
            return raw
        parsed = relocated_parser(methods, helper_raw)(read, header, expected)
        fields = parsed['actual_metadata_fields']
        need((fields['label_start'], fields['label_size'], fields['shift'], fields['encoding'], fields['codepage']) == expected,
             'Actual original parser stores exactly the relocated header values')
        selections = list(plan.labels) + [dict(text='184號', reference=808, reused_existing=True,
                                             provenance='Previously physically accepted stock reference')]
        for row in selections:
            at = plan.new_pool_offset + row['reference'] * 8
            window = result[at:at + 128]
            case = methods.fragment_case(read, row['reference'], fields, window)
            need(case['host_CP950_display_of_actual_native_output'] == row['text'] and
                 case['actual_byte_copy_and_termination_passed'], 'Original partial native label output')
            cases.append(dict(label=row, window_offset=at, window_bytes=len(window), window_sha256=sha(window), CPU=case))
    need(stat(MAIN) == before_MAIN, 'Original MAIN stat unchanged')
    component_row = save('experimental-relocated.GMP', result)
    proof = dict(schema='garmin-original-GMP-relocated-CP950-labels/v1',
                 created_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
                 source_script_sha256=sha(Path(__file__).read_bytes()), primitive_sha256=primitive_sha,
                 dependencies=[dict(path=p, sha256=s, old_suites_not_replayed=True) for p, s in DEPS],
                 source_AP_readonly=True, source_AP_stat_unchanged=True, source_GMP_sha256=GMP_SHA,
                 actual_source_read_log=reads, original_GMP_bytes=len(source), component=component_row,
                 original_prefix_preserved_except_header_offsets=[plan.lbl_header_offset + 21, plan.lbl_header_offset + 25],
                 original_label_pool_copied_byte_identical=True, unknown_trailing_tables_unchanged=True,
                 original_pool_offset=plan.original_pool_offset, original_pool_bytes=plan.original_pool_bytes,
                 new_pool_offset=plan.new_pool_offset, new_pool_bytes=plan.new_pool_bytes,
                 new_refs=plan.labels, actual_partial_native_parser=parsed,
                 host_assertion_adapter_changes='Added expected parameter; one fixed stock expected tuple replaced. No CPU bytes changed.',
                 partial_native_label_cases=cases, unique_MAIN_fragment_reads=list(code_reads.values()),
                 source_binding=source_binding, labels_are_synthetic_format_fixtures=args.synthetic_labels,
                 new_addresses_or_streets_published=False, complete_IMG_created=False,
                 complete_getter_SQL_query_UI_or_container_load_verified=False,
                 device_IO=False, installable=False, full_Taiwan_update_complete=False,
                 limits=['A standalone experimental GMP component only; unknown full parser/trust and complete native getter are not executed.',
                         'Original partial parser/address/encoding10 byte-copy blocks use explicit staged frames/metadata/windows; no file-I/O success hook.',
                         'Original reference preservation follows whole arena byte identity; finite old184/new-label calls do not execute every old getter.',
                         'This relocation duplicates the original 3.8MB arena; label references retain the original 19-bit profile and sentinel limit.',
                         'MDR street records, JAI search index, IMG FAT/rollback, routing and device acceptance remain separate work.'])
    record = save('actual-relocation-proof.json', proof)
    print(json.dumps(dict(all_passed=True, component_bytes=len(result), label_cases=len(cases),
                         actual_source_bytes_read=sum(row['bytes'] for row in reads), proof=record), ensure_ascii=False))


if __name__ == '__main__':
    main()
