#!/usr/bin/env python3
"""Normal small source/proof provenance review; no reviewed code imports or calls."""
import gzip,hashlib,json,os
from pathlib import Path
ROOT=Path('/root/garmin');P=Path(__file__).resolve().parent
LIMIT=262144;used=190522;cache={};receipts=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(x,m):
 if not x:raise ValueError(m)
def read(n):
 global used
 if n in cache:return cache[n]
 p=P/n;nbytes=p.stat().st_size;need(nbytes<=65536 and used+nbytes<=LIMIT,'Normal physical file budget')
 before=stat(p);b=p.read_bytes();used+=len(b);need(stat(p)==before,'Snapshot stat stable')
 cache[n]=b;receipts.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),'stat_before':before,'stat_after':stat(p)})
 return b
def write(n,x):
 b=(json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode();need(len(b)<=16000,'Small output16KiB bound')
 with (P/n).open('xb') as f:
  need(f.write(b)==len(b),'Complete newly created small file write');f.flush();os.fsync(f.fileno())
 need((P/n).stat().st_size==len(b),'Small write size')
 cache[n]=b
 return sha(b)
def decoded(n,pin):
 b=gzip.decompress(read(n));need(len(b)<=65536 and sha(b)==pin,'Full original small source pin recoverable')
 return b
v3=json.loads(decoded('candidate-v3.proof.json.gz','b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'))
house=json.loads(decoded('house-merge-v1.proof.json.gz','bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41'))
lane=json.loads(decoded('lane-tree-cow-append-v1.proof.json.gz','1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9'))
v2=json.loads(decoded('v2.proof.json.gz','5c87ea67ad127f981b24a1d6d2f9fb255814695421fa4f915a368157b576ecc3'))
v2seal=json.loads(decoded('v2.sealed-files.json.gz','659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766'))
cow=decoded('current-profile-writer.source.txt.gz','71673de65c6e94da664ad8bc8b81307c37a6dfbf94d819eebfa888274b688c9e').decode()
stockwriter=decoded('stock-multilevel-writer.source.txt.gz','3508e01e8ba6e3fd3388322c8da575f2dff96a4f1dd836b15eeaa25bd88e3958').decode()
builder=decoded('build_country_native_lane_candidate_v3.source.txt.gz','12fb96184d746d0e72ee246a8b678b1dd7858e891e0e2a2e6c315d022d94f929').decode()
need(v2['all_assigned_checks_passed'] and v3['all_assigned_checks_passed'] and house['all_assigned_checks_passed'] and lane['all_assigned_checks_passed'],'Pinned closed proof gates')
need(v2['build_source_sha256']==next(r['sha256'] for r in v2seal['files'] if r['path']=='scripts/build_country_native_address_candidate_v2.py'),'V2 builder inherited closed seal binding')
comps2={r['name']:r for r in v2['component_checks']};comps3={r['name']:r for r in v3['complete_actual_component_checks']}
componentrows=[]
for name,r in comps3.items():
 if name=='00004171.MDR':continue
 s=comps2[name]
 need(s['unchanged_from_stock'] and r['unchanged'] and r['all_actual_component_bytes_readback'] and
      (r['bytes'],r['sha256'])==(s['bytes'],s['sha256']),'Five components v3=v2=stock closed evidence chain')
 componentrows.append({'name':name,'bytes':r['bytes'],'SHA256':r['sha256'],'v3_equals_v2':True,
   'v2_closed_readback_marks_equals_stock':True,'new_scope_IMG_read':False,
   'semantic_lowerID_reference_absence_proven':False})
need(len(componentrows)==5,'Exactly five unchanged logical components')
need(v2['original_unknown_MDR_prefix_and_L2_L1_bytes_preserved'] and v3['unknown_prefix_and_L2_L1_preserved'],'Closed pretable/upper-table comparison chain')
need("source.chunks(772,self.old_tables[5]['start']-772)" in cow and
 "struct.pack_into('<I',header,600,cursor)" in cow and
 "struct.pack_into('<I',header,600,cursor)" in stockwriter,'Static header/prefix write witnesses')
need("'unknown prefix'" in builder and "'L2-L1'" in builder and
 "adapter.source.exact(old_at+at, n) == read(new_at+at, n)" in builder,'Actual v3 builder direct compare witness')
# Ordinary arithmetic from pinned fixed counts/profile; no directory/IMG reads or writer calls.
def layout(counts,l3stride):
 n={1:22,2:343,3:47870}|counts;stride={1:122,2:122,3:l3stride,4:128,5:126,6:68}
 at=4195100;tables={}
 for level in [6,5,4,3,2,1]:
  size=(n[level]*stride[level]+7)//8
  tables[level]={'start':at,'bytes':size,'end_exclusive':at+size,'count':n[level],'stride':stride[level]};at+=size
 return {'tables':tables,'DIR_start':at,'MDR_bytes':at+120}
stock=layout({int(k):v for k,v in house['original_counts'].items()},111)
current=layout({int(k):v for k,v in v2['proposed_table_counts'].items()},112)
final=layout({int(k):v for k,v in v3['final_lower_counts'].items()},112)
need(stock['MDR_bytes']==92653600 and current['MDR_bytes']==124255307 and final['MDR_bytes']==149220356,'Pinned source size and profile arithmetic consistent')
ranges=[
 {'name':'MDR header before DIR pointer','stock_range':[0,600],'v2_range':[0,600],'v3_range':[0,600],
  'treatment':'Preserved by pinned writer header-copy contract; this review has no independent stock/header raw-byte compare.'},
 {'name':'MDR header DIR offset','stock_range':[600,604],'v2_range':[600,604],'v3_range':[600,604],
  'treatment':'Only explicit4B little-endian DIR start write in both reviewed writer contracts.',
  'stock_DIR':stock['DIR_start'],'v2_DIR':current['DIR_start'],'v3_DIR':final['DIR_start'],
  'semantic_type':'MDR component byte offset, not established lower-record ID.'},
 {'name':'MDR header after DIR pointer','stock_range':[604,772],'v2_range':[604,772],'v3_range':[604,772],
  'treatment':'Preserved by pinned writer header-copy contract; no raw stock/header-byte compare in this new scope.'},
 {'name':'Unknown pretable body','stock_range':[772,4195100],'v2_range':[772,4195100],'v3_range':[772,4195100],
  'bytes':4194328,'treatment':'v2 closed proof states stock byte-preservation; v3 pinned builder explicitly compares every chunk against v2. No new body data written by these paths.'}]
for level in [2,1]:
 a,b,c=stock['tables'][level],current['tables'][level],final['tables'][level]
 need(a['bytes']==b['bytes']==c['bytes'],'Upper table byte lengths unchanged')
 ranges.append({'name':'L'+str(level)+' payload','stock_range':[a['start'],a['end_exclusive']],
  'v2_range':[b['start'],b['end_exclusive']],'v3_range':[c['start'],c['end_exclusive']],
  'bytes':a['bytes'],'treatment':'Byte-identical payload copied at relocated table start; closed v2 preservation plus explicit v3 full L2-L1 byte comparison. Physical/logical offsets change.'})
checklist=[
 {'ID':'P1','result':'Confirmed closed evidence chain, not fresh IMG comparison',
  'detail':'Five complete logical nonMDR component hashes/sizes match v2, whose closed actual component checks mark unchanged_from_stock. GMP/LBL/route-bearing component remains byte-identical, but semantic pointer types/targets are not decoded here.'},
 {'ID':'P2','result':'Prefix payload provenance narrowed',
  'detail':'Pre-table body [772,4195100), length4194328, and L2/L1 payloads are copy-preserved across stock→v2→v3 by closed proof/source comparisons. These producer paths did not introduce new literal field bytes there. Header itself is separately classified; DIR offset is modified.'},
 {'ID':'P3','result':'Header/descriptor modifications identified with evidence boundaries',
  'detail':'Current writer copies772B header then writes uint32 DIRstart at600; copies120B DIR then updates each entry first8B(start/size), preserves remaining stride/bitfields. Stock writer also widens L3 stride111→112 and first22→23 in DIR, in addition to starts/sizes. Header rest is source contract, not an independent actualstock raw-header check. V2 main builder45969B is source-bound by proof/seal but not content-reviewed in this finite budget.'},
 {'ID':'P4','result':'Changes that DO encode poststock record relations remain inside MDR graph',
  'detail':'L3 is widened/selectedfirst-count patched for v2 and further selected7650 roots patched for v3. L4/L5/L6 original significant prefixes are retained; new/cloned lower groups contain explicit new child links. Shared aliases/highflags stay raw. Prior lane producer preserves source identities but does not decode external ABIs.'},
 {'ID':'R1','result':'Conditional exclusion only',
  'detail':'IF an unchanged stock field is proved to be a direct one-based L4/L5/L6 reference valid against the stock table, its target lies<=stockcount; retaining all stock lower prefix IDs preserves it. Same applies to a valid stockfirst/count range whose endpoint stays within stockbounds. Those premises are not established for undecoded bytes merely by equality.'},
 {'ID':'R2','result':'Unknown encodings remain held',
  'detail':'Unchanged bytes can contain reserved/out-of-stock values, encoded/relative IDs, another namespace, indirect refs through modified L3, count-dependent lookups, table byte offsets or sentinels. New table starts move even when old leaf IDs stay fixed. A numeric value that looks like a poststock ID is not a typed reference proof or a typed absence proof.'},
 {'ID':'R3','result':'Runtime and same-MDR consumers unresolved',
  'detail':'Loaded caches/query vectors/handles can acquire new suffix IDs via valid new paths although every external file byte stayed stock. Compaction remap can invalidate them. SameMDR unknown prefix format, highflag8/12/13/14 additional semantics, dynamic source boundaries and all lowerID/offset consumers remain unproved.'},
 {'ID':'R4','result':'No absence, construction or renderer acceptance claim',
  'detail':'Immutable byte lineage narrows which producer paths wrote data; it does not prove external lowerref ABI absence. Required before full compaction: typed oldreference validity or conservative retention/remap of all consumers, full rawbit/unknownfield preservation, complete virtual/inverse/readback proof and separately authorized native/device acceptance.'}]
write('component-and-range-provenance.json',{'schema':'closed-smallproof-nontable-lineage/v1','all_assigned_file_provenance_checks_passed':True,
 'five_components':componentrows,'ranges':ranges,'arithmetic_layouts':{'stock':stock,'v2':current,'v3':final},
 'offset_scope':'Computed from pinned exact counts/strides/prefixstart and writer contract; sizes match closed source guards/proofs. This scope does not read actual directory bytes.',
 'v3_actual_compare_source':'build_country_native_lane_candidate_v3.source.txt.gz spans/adapter.source.exact comparison; source hash12fb... independently observed, not claimed self-bound by v3proof.',
 'header_verification_boundary':'V3 complete readback compares actual header to current writer plan. Stock→v2 header-rest preservation is reviewed underlying writer contract; main v2 builder source only inherited via pinned proof/seal.'})
write('independent-checklist.json',{'schema':'finite-external-lowerref-provenance-checklist/v1','checks':checklist,
 'external_lowerref_ABI_absence_proven':False,'new_prefix_poststock_ID_writes_from_reviewed_copy_paths':False,
 'unchangedbytes_automatically_imply_absence':False})
proofhash=write('proof.json',{'schema':'readonly-nontable-lowerref-lineage-review/v1','all_assigned_readonly_provenance_review_completed':True,
 'positive_result':'Five nonMDR components and pretable/L1/L2 copied payloads have closedstock/v2/v3 lineage. This narrows producer writes only.',
 'conditional_reference_result':'Typed direct stock-valid lower references target retained stock prefixes and stay ID-stable; premises unproved for arbitrary unknown bytes.',
 'reference_absence_proven':False,'header_only_explicit_reviewed_writer_patch':[600,604],
 'unknowns':['Undecoded/indirect/reserved lowerIDs and tablebyteoffsets.','Highflag/cache/query vector/dynamic consumers.','V2 main builder source content not reviewed, header-rest actualstock compare not reproduced.'],
 'source_algorithm_import_compile_execute':False,'IMG_MAIN_PBF_largeledger_CPU_guest_audio_device_bytes_or_calls':0,
 'referenced_large_inputs_opened':False,'actual_compaction_renderer_route_UI_install_App_music_fullgoal':False,
 'original_source_or_closed_seal_or_canonical_modified':False,'read_budget_bytes':LIMIT,
 'physical_normal_reads_before_this_sealer':190522,'physical_normal_reads_in_this_process_at_proof_write':used-190522,
 'raw_smallproof_decompression_is_RAM_parse_not_sourcefile_scan':True,
 'review_source_scope':'Pins/snapshots and receipt ledgers in this namespace; only smallcode/proofs, no reviewed helper calls.'})
handoff=('Closed ordinary provenance review only. Five v3 nonMDR component hashes/sizes equalv2; v2 closed component readback marks them equalstock. Unknown pre-table body[772,4195100) (4194328B) and L2/L1 payloads retain stock/v2 bytes, with relocated uppertable starts. V3builder explicitly compared everychunk againstv2.\n\n'
 'Reviewed writer copies772B MDRheader and changes only[600,604) DIRoffset: stock92653480→v2124255187→v3149220236 (derived pinnedprofile). CurrentDIR changesstart/size only; stock→v2 also changesL3 stride111→112/first22→23. Sourcecontract headerrest preservation is not a new actualstock/header compare; v2mainbuilder45969B is pinned by proof/seal but not content-reviewed.\n\n'
 'Unchanged producer-copy paths did not write new literalfield bytes into externalcomponents/pretablebody/L1/L2. IF fields are typed direct stock-valid lowerreferences, preservingallstockprefixIDs stabilizes them. Equalityalone does not establish those premises or absence: encoded/reserved/relative/differentnamespace/indirect/dynamic refs and tablebyteoffsets remain unknown. Caches may acquire newIDs at runtime through modifiedL3 even with immutablefilebytes. SameMDR highflags/unknownfields remain held.\n\n'
 'NoIMG/ledger/PBF/MAIN read, no reviewed source import/compile/execute, no CPU/audio/device. Small proofs/source snapshots compressed losslessly only within this NEW namespace; forbidden sourcegzip not opened. Physicalnormalfile read budget256KiB includes rereads. Hash-size-stat seal; freshly read snapshots and exact verified smallwrite buffers distinguish hashmethods. No absence/compactIMG/renderfix/install/fullgoal claim. Stop.\n')
with (P/'HANDOFF.md').open('xb') as f:
 b=handoff.encode();need(f.write(b)==len(b),'Full HANDOFF write');f.flush();os.fsync(f.fileno());cache['HANDOFF.md']=b
# Read existing small artifact once per process; reuse cached bytes without repeated file IO.
for p in sorted(P.iterdir()):
 if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-receipt.json']:read(p.name)
originalpins=[]
for n in ['source-capture-read-ledger.json','additional-source-capture-read-ledger.json','stock-writer-capture-read-ledger.json']:
 for r in json.loads(cache[n])['source_reads']:
  need(stat(ROOT/r['source_path'])==r['stat_after'],'Original source stat unchanged at seal');originalpins.append(r)
write('actual-readonly-analysis-receipt.json',{'input_tool_receipts':[{'chunk':'3eaca2','EXIT':0,'operation':'Stats only0contentbytes'},
 {'chunk':'b209d1','EXIT':0,'contentbytes':56322,'operation':'Four exactsmallsource/proofcaptures'},
 {'chunk':'8888fd','EXIT':0,'contentbytes':56322,'operation':'New snapshots lossless gzip conversion/selectedproof fields'},
 {'chunk':'e1cd80','EXIT':0,'contentbytes':54636,'operation':'V2 seal/proof+COW source pins'},
 {'chunk':'86ded3','EXIT':0,'contentbytes':16521,'operation':'Pinned stockmultilevel writer source'},
 {'chunk':'5624af','EXIT':0,'contentbytes':6721,'operation':'New cachedv2 proof gzip readbackfields'}],
 'normal_source_snapshot_reads_this_process':receipts,'aggregate_normal_physical_contentbytes':used,
 'source_stats_unchanged':True,'original_pin_count':len(originalpins),'no_reviewed_algorithm_execution':True,
 'no_actualIMGread_or_absenceproof':True})
files=[]
for p in sorted(P.iterdir()):
 if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-receipt.json']:
  b=cache[p.name];need(p.stat().st_size==len(b),'File size matches cached actual read or complete createdwrite')
  method='fresh_actual_smallfile_read_this_process' if any(r['path'].endswith('/'+p.name) for r in receipts) else 'exact_new_byte_buffer_complete_write_fsync_size_verified'
  files.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),'stat_at_seal':stat(p),'mode':oct(p.stat().st_mode&0o777),'hash_method':method})
sealhash=write('sealed-files.json',{'schema':'finite-readonly-provenance-hash-size-stat-seal/v1','files':files,
 'actual_aggregate_normal_source_artifact_contentbytes_read':used,'physical_content_read_cap':LIMIT,
 'source_pins_at_seal':originalpins,'original_source_stats_unchanged':True,
 'seal_method':'Fresh actual snapshot reads plus exact newly generated bytebuffer completewrite/fsync/size verification; modes preserved, no chmod/read-only claim.',
 'actual_IMG_MAIN_CPU_PBF_guest_audio_device':0,'reference_absence_or_install_renderfix':False})
need(used<=LIMIT,'Final ordinary read budget')
print(json.dumps({'all_assigned_readonly_review_completed':True,'normal_physical_contentbytes_read':used,
 'source_artifact_read_cap':LIMIT,'files_sealed':len(files),'seal_SHA256':sealhash,'proof_SHA256':proofhash,
 'five_components_stock_lineage_confirmed':True,'external_lowerref_absence_proven':False,
 'IMG_reviewed_algorithm_guest_device_audio':0}))
