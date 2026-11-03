"""Verify only the small newly written capture; never reopen the full source."""
import hashlib
import json
import os
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/navigation-beitun-source-capture-corrected-v1'
OUT = ROOT / 'staging/navigation-beitun-capture-output-readback-v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    assert not OUT.exists()
    raw_proof = (BASE / 'proof.json').read_bytes()
    raw_seal = (BASE / 'SEAL.json').read_bytes()
    assert sha(raw_proof) == '7333ab592eecdd21e3f02207ba6d3be21c7c491687a9f6fc3a84a1364b650a25'
    assert sha(raw_seal) == '5ba09fac307f25d569cb46fd60a2f948659dc4bb04fcc1cbafeaa3296c24ae3e'
    proof, seal = json.loads(raw_proof), json.loads(raw_seal)
    verified = {}
    content = {}
    for name, entry in seal['files'].items():
        path = BASE / name
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
        assert before == after and len(raw) == entry['bytes']
        assert sha(raw) == entry['SHA256']
        verified[name] = dict(bytes=len(raw), SHA256=sha(raw), observed_mode=oct(after.st_mode & 0o777))
        content[name] = raw
    raw = content['missing-source-groups.jsonl.gz']
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = inflater.decompress(raw) + inflater.flush()
    assert inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail
    assert sha(plain) == proof['complete_groups_gzip']['decompressed_SHA256']
    assert len(plain) == proof['complete_groups_gzip']['decompressed_bytes'] and plain.endswith(b'\n')
    rows = [json.loads(line) for line in plain.splitlines()]
    assert len(rows) == proof['missing_group_count'] == 102
    groups = {}
    names = set()
    for row in rows:
        group = row['original_prepared_group']
        gid = group['group_id']
        assert gid not in groups
        groups[gid] = row
        original = group['raw_address']
        names.add(original[2])
        ids = group['source_ids']
        assert ids and len(ids) == len(set(ids)) == group['source_node_count']
        assert row['original_first_node_ID'] == ids[0]
        keys = ['addr:city', 'addr:district', 'addr:street', 'addr:housenumber']
        assert [row['original_first_node_addr_tag_subset'][key] for key in keys] == original
        assert row['full_original_tags_per_node'] is None
        assert not row['record_ID_reserved'] and not row['formal_address_alias_or_route_verified']
    assert names == set(proof['missing_literal_names']) and len(names) == 28
    mapping = json.loads(content['hold-mapping.json'])
    mapped = set()
    for entry in mapping['roster']:
        for gid, line in zip(entry['group_ids'], entry['source_group_capture_lines'], strict=True):
            assert gid not in mapped
            mapped.add(gid)
            assert rows[line - 1] == groups[gid]
            assert groups[gid]['original_prepared_group']['raw_address'][2] == entry['candidate_literal']
    assert mapped == set(groups)
    examples = json.loads(content['planning-examples.json'])
    assert len(examples) == 2
    for example in examples:
        row = rows[example['source_group_capture_line'] - 1]
        assert example['complete_original_prepared_group'] == row['original_prepared_group']
        assert example['complete_source_node_IDs'] == row['original_prepared_group']['source_ids']
        assert example['original_first_node_addr_tag_subset'] == row['original_first_node_addr_tag_subset']
        assert not example['formal_address_route_alias_or_official_name_verified']
    result = dict(schema='new-small-capture-independent-file-readback/v1', all_assigned_checks_passed=True,
        input_proof_SHA256=sha(raw_proof), input_seal_SHA256=sha(raw_seal), verified_small_files=verified,
        actual_new_capture_compressed_bytes_read=len(raw), actual_new_capture_decompressed_bytes=len(plain),
        valid_single_gzip_member_CRC_and_footer=True, complete_JSONL_rows=102,
        exact_missing_name_roster=28, all_mapping_group_line_links_verified=True,
        complete_prepared_group_IDs_and_first_four_tags_verified=True,
        two_planning_example_links_verified=True, source_whole_gzip_or_PBF_read_bytes=0,
        preceding_root_inspections_separately_recorded=['d158f9 EXIT0: earlier18867B small-capture read/decompression for row shape.', '3eeb59 EXIT0: diagnostic12file SHA/mode checks including18867B compressed capture; no inflation.'],
        initial_audit_mode_assumption_failure_preserved='staging/navigation-beitun-capture-output-readback-v1-preparation-failure;59ecac EXIT1 before gzip body/mapping audit.',
        capture_seal_is_hash_based_not_a_readonly_mode_guarantee=True,
        original_source_raw_lines_or_unavailable_full_tags_not_reconstructed=True,
        formal_alias_or_address_or_device_acceptance=False, original_artifacts_modified=False,
        device_IO=False, native_CPU=False, installable=False, full_goal_complete=False)
    OUT.mkdir(mode=0o700)
    for name, value in [('producer-source.py', Path(__file__).read_bytes()), ('proof.json', result)]:
        raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
        with (OUT / name).open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        (OUT / name).chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True, captured_output_CRC_verified=True,
        complete_rows=102, exact_names=28, all_links_verified=True, large_source_read_bytes=0)))


if __name__ == '__main__':
    main()
