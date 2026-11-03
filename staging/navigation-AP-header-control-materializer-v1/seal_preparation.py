#!/usr/bin/env python3
"""Close only this finite preparation; never open a source IMG."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/materialize_ap_header_control_v1.py'
FILES=[SOURCE,HERE/'test_materializer.py',HERE/'synthetic-test-proof.json',HERE/'catalog-manifest.json',Path(__file__)]
SHA=lambda b:hashlib.sha256(b).hexdigest()
raw={p:p.read_bytes() for p in FILES}
tests=json.loads(raw[HERE/'synthetic-test-proof.json']);catalog=json.loads(raw[HERE/'catalog-manifest.json'])
if not tests['all_assigned_checks_passed'] or tests['unittest_methods']!=17 or tests['errors'] or tests['failures']:
    raise RuntimeError('Required finite synthetic run did not pass')
if tests['source_sha256']!=SHA(raw[SOURCE]) or tests['test_source_sha256']!=SHA(raw[HERE/'test_materializer.py']):
    raise RuntimeError('Executed source/test binding changed')
tree=ast.parse(raw[SOURCE]);assert_nodes=[n.lineno for n in ast.walk(tree) if isinstance(n,ast.Assert)]
if assert_nodes:raise RuntimeError('Production safety checks must not depend on assert')
if '--manifest' in raw[SOURCE].decode():raise RuntimeError('Arbitrary manifest CLI is unsupported')
receipts=tests['receipts'];cases={r['case']:r['receipt'] for r in receipts}
corrupt=cases['corrupt_saved_partial_before_readback'];post=cases['post_link_fsync_failure']
if (corrupt['published'] or corrupt['actual_saved_output_sha256']==corrupt['generated_computed_full_sha256'] or
    corrupt['partial_cleanup']!='owned_partial_removed' or not corrupt['all_handles_closed']):
    raise RuntimeError('Actual synthetic corruption/readback refusal evidence missing')
if not post['published'] or not post['actual_saved_output_fullhash_verified'] or not post['all_handles_closed']:
    raise RuntimeError('Verified published final preservation on fsync error not demonstrated')
engines=[r['receipt'] if r['case']!='python_O_rejection' else r['receipt']['receipt'] for r in receipts
         if 'source_bytes_read' in r['receipt'] or r['case']=='python_O_rejection']
aggregate={key:sum(r.get(key,0) for r in engines) for key in
           ('source_bytes_read','generated_bytes_written','saved_output_bytes_read')}
test_tool={'schema':'ordinary-host-tool-receipt/v1','tool_chunk_id':'396f0a','actual_exit_code':0,
           'wall_time_seconds':0.80723049,'command':'python3 staging/navigation-AP-header-control-materializer-v1/test_materializer.py',
           'terminal':'Ran 17 tests in 0.781s\n\nOK','unittest_methods':17,'native_guest':False,
           'real_IMG_read_or_write':False,'subprocess_scope':'ordinary host python3 -O synthetic refusal only'}
proof={'schema':'AP-header-control-materializer-preparation/v1','all_assigned_checks_passed':True,
       'scope':'fixed two-control catalog, local writer guards and synthetic saved-file integrity; preparation only',
       'source':{'path':str(SOURCE.relative_to(ROOT)),'bytes':len(raw[SOURCE]),'sha256':SHA(raw[SOURCE]),
                 'production_ast_assert_nodes':assert_nodes,'fixed_catalog_only':True,'CHUNK_BYTES':1048576},
       'tests':{'path':str((HERE/'test_materializer.py').relative_to(ROOT)),
                'bytes':len(raw[HERE/'test_materializer.py']),'sha256':SHA(raw[HERE/'test_materializer.py']),
                'proof_sha256':SHA(raw[HERE/'synthetic-test-proof.json']),'actual_tool_chunk_id':'396f0a',
                'actual_exit_code':0,'methods':17,'receipt_cases':len(receipts),
                'canonical_fixture_bytes':4096,'actual_max_synthetic_source_file_bytes':4097,
                'fixture_size_erratum':'The first test proof fixture_max_bytes=4096 names the base fixture; test17 extra-length refusal wrote4097 bytes. Both are below8192.',
                'aggregate_synthetic_engine_counters':aggregate,
                'full_source_hash_computed_virtual_hash_and_actual_saved_readback_separate':True,
                'corrupt_owned_partial_rejected_without_publish':True,
                'post_link_fsync_error_retains_verified_published_final':True,
                'optimized_python_explicit_guard_refusal':cases['python_O_rejection']['rejected']},
       'closed_real_input_catalog':catalog['catalog_pins'],
       'closed_root_virtual_fullhash_receipt_inherited_only':{'tool_chunk_id':'9b63ea','actual_exit_code':0,
                                                            'reexecuted_this_scope':False},
       'budgets':{'artifact_output_limit_bytes':131072,'existing_small_artifact_input_limit_bytes':262144,
                  'known_initial_catalog_capture_bytes':10193,
                  'test_actual_small_catalog_reads_bytes':tests['small_catalog_reads_bytes'],
                  'closure_generated_source_or_output_reads_bytes':sum(len(v) for v in raw.values()),
                  'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,'synthetic_max_source_bytes':4097},
       'metadata_cli_default_and_list_source_IMG_open_or_stat':False,
       'source_IMG_current_stats_refreshed':False,
       'production_source_stats_policy':'Exact inherited dev/inode/size/mtime_ns/ctime_ns pins are checked only in future explicit materialization; metadata listing does not refresh them.',
       'fixed_catalog_sources':[{'name':r['name'],'path':r['source'],'bytes':r['bytes'],
                                'source_sha256':r['source_sha256'],'expected_virtual_sha256':r['expected_generated_sha256'],
                                'stat_pin':r['source_stat_pin']} for r in catalog['controls']],
       'real_materialization_executed':False,'real_candidate_generated':False,'device_IO':False,
       'installable':False,'native_UI_or_renderer_rootcause_verified':False,'checksum_policy_verified':False,
       'all_synthetic_engine_handles_closed':all(r['all_handles_closed'] for r in engines),
       'limits':['Synthetic bodies do not prove real map materialization or acceptance.',
                 'Closed virtual hashes are inherited; no production full-image hash was repeated.',
                 'Opaque header checksum byte15 remains unchanged; admission/checksum/rendering policy remains unknown.',
                 'A CLI error after atomic publication may leave a verified final; published=true reports it. The writer does not delete that final.',
                 'Disabled output suffix is a local safeguard, not an installation or rollback adapter.'],
       'seal_source_handles_closed':True}
handoff='''# Local AP header control materializer preparation

The fixed catalog binds the closed geometry-v2 plan/proof/seal. The two names are `eightK_end_mirror` and `expanded_fourK_geometry`. No source IMG was read or generated in this scope. Ordinary-host synthetic tests passed17 methods (396f0a EXIT0); real512-byte saved headers were used with synthetic bodies.

Metadata only (also the no-argument default):

```
python3 scripts/materialize_ap_header_control_v1.py --list
```

Future explicit local generation, not executed here; the output parent must already exist:

```
python3 scripts/materialize_ap_header_control_v1.py --control eightK_end_mirror --output /root/garmin/staging/AP-eightK-control.img.disabled
```

The CLI has no arbitrary manifest/source option. Source regular-file/inode/stat pins and full512 header are checked before creating a partial. Source EOF/size/fullSHA and computed virtual fullSHA must match the catalog. After fsync, the owned partial is reopened O_RDONLY|O_NOFOLLOW, inode/stat/size/EOF and actual saved fullSHA are verified separately; source stats are checked again. Atomic link publication refuses an existing destination. Symlink destinations and staging parent components are refused. Only the owned partial can be removed.

The error JSON receipt records `published`. A failure after successful publication, including directory fsync failure, preserves the verified final and reports published=true. Do not interpret every nonzero CLI status as no output. Existing foreign output/partial files are preserved. Hash fields are `source_actual_full_sha256`, `generated_computed_full_sha256` and `actual_saved_output_sha256`.

The tests demonstrate actual synthetic saved-file readback (including deliberate corruption), body preservation, wrong hashes/header/stat refusal, atomic race refusal, partial ownership, fsync/write failures and explicit guards under host Python -O. The first synthetic proof's fixture_max_bytes4096 denotes its base; the extra-length refusal uses4097 bytes, still below8KiB. Full real materialization, original-device acceptance/UI/routes/rendering/root cause, opaque checksum policy and installability remain false. No rollback adapter is supplied. No USB, discovery, native guest, PBF, MAIN, audio, installation, ZIP or shared report mutation occurs.

Source code, tests, catalog, proof and actual terminal receipt are sealed. Stop after this finite preparation; production --list may be run independently by root.
'''
def save(name,value):
    b=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode() if not isinstance(value,str) else value.encode()
    p=HERE/name
    if p.exists():raise RuntimeError('Preparation closure output already exists')
    p.write_bytes(b);raw[p]=b
save('actual-test-tool-receipt.json',test_tool);save('proof.json',proof);save('HANDOFF.md',handoff)
rows=[]
for path,b in raw.items():
    path.chmod(0o444);s=path.stat()
    rows.append({'path':str(path.relative_to(ROOT)),'bytes':len(b),'sha256':SHA(b),'mode':'0444',
                 'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]})
seal={'schema':'AP-header-control-materializer-sealed-files/v1','all_assigned_checks_passed':True,
      'real_IMG_read_bytes':0,'real_IMG_write_bytes':0,'all_handles_closed':True,
      'files':rows,'artifact_payload_bytes':sum(len(b) for b in raw.values())}
sealraw=(json.dumps(seal,ensure_ascii=False,indent=2)+'\n').encode()
if sum(len(b) for b in raw.values())+len(sealraw)+2048>131072:raise RuntimeError('Output128KiB cap including reserved post-seal receipt')
if 10193+tests['small_catalog_reads_bytes']+sum(len(v) for v in raw.values())>262144:
    raise RuntimeError('Small artifact262144byte cumulative explicit reads cap')
p=HERE/'sealed-files.json'
if p.exists():raise RuntimeError('No replacing sealed output')
p.write_bytes(sealraw);p.chmod(0o444)
print(json.dumps({'all_assigned_checks_passed':True,'source_sha256':SHA(raw[SOURCE]),
                  'proof_sha256':SHA(raw[HERE/'proof.json']),'seal_sha256':SHA(sealraw),
                  'artifact_bytes_including_seal':sum(len(b) for b in raw.values())+len(sealraw),
                  'methods':17,'receipt_cases':len(receipts),'synthetic_engine_counters':aggregate,
                  'real_IMG_read_bytes':0,'real_IMG_write_bytes':0,'all_handles_closed':True},indent=2))
