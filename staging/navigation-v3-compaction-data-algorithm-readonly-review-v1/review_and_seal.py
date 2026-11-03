#!/usr/bin/env python3
"""Read text/hash and write finite static review; never imports/executes reviewed code."""
import hashlib,json,os
from pathlib import Path
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
LIMIT=262144;reads=51349;ledger=[]
prior=[{'tool_chunk':'ffe73c','EXIT':1,'content_bytes':0,'reason':'Description25KB guard before firstsource content; actualclosed27566B. Root corrected eachsource allowance40KiB; aggregate256KiB unchanged.'},
 {'tool_chunk':'eee76f','EXIT':0,'content_bytes':0,'operation':'Three input stats only'},
 {'tool_chunk':'ada451','EXIT':0,'content_bytes':23783,'operation':'Root observed20555B+prepared-source3228B text/hash/static read'},
 {'tool_chunk':'c9c708','EXIT':0,'content_bytes':27566,'operation':'Closed source text/hash/static read after exactsize correction'}]
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 global reads
 n=p.stat().st_size
 if reads+n>LIMIT:raise ValueError('Aggregate256KiB normal file read cap')
 before=stat(p);b=p.read_bytes();reads+=len(b)
 if stat(p)!=before:raise ValueError('Normal source/stat changed')
 ledger.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),'stat_before':before,'stat_after':stat(p)})
 return b
def write(n,x):
 b=(json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode()
 if len(b)>40000:raise ValueError('Review artifact40KB bound')
 (OUT/n).write_bytes(b)
def lines(s,term):return [i+1 for i,l in enumerate(s.splitlines()) if term in l]
closedpath=ROOT/'staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py'
observedpath=ROOT/'staging/navigation-v3-reachable-suffix-compaction-root-observed-v3/observed_analyzer.py'
closed=read(closedpath);observed=read(observedpath)
if len(closed)>40960 or sha(closed)!='a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274':raise ValueError('Exact closed source binding')
if len(observed)>40960 or sha(observed)!='6bf697390bf3440843cd33257c99e9c4de05d828b23122506cf4906d38fcd943':raise ValueError('Exact observed source binding; no review of pending replacement')
(OUT/'closed-source-snapshot.txt').write_bytes(closed)
(OUT/'observed-source-snapshot.txt').write_bytes(observed)
c=closed.decode();o=observed.decode()
checklist=[
 {'ID':'G1','topic':'Root set and forward graph closure','assessment':'Conditionally conservative',
  'witness_lines':lines(c,'for ID in range(1,tables[3]')+lines(c,'if target not in counts or target<=level'),
  'condition':'All47870 L3 records are roots, entire declared lower prefix is marked, and every dependency is a forward first/count range to4/5/6. Level skipping including4→6 works. With forward edges only, level4 then5 is a topological pass; no fixpoint is needed.',
  'guard':'Unknown flags, nonforward targets, invalid ranges or incoherent nonempty child encoding call anomaly and retain ALL lower suffixes.',
  'remaining_hold':'Other roots/relations in MDR non-table prefix, GMP, caches or external consumers are not proven absent.'},
 {'ID':'G2','topic':'Complete range marking and stable rank','assessment':'Static range/rank argument valid under bounds',
  'witness_lines':lines(c,'def mark(')+lines(c,'def make_rank(')+lines(c,'def mapped_ID('),
  'condition':'Require0<=prefix[level]<=count[level], positive first/count for nonempty range and last<=count. mark retains every original ID in interval; rank counts retained IDs in original order. Therefore an n-child interval maps to one contiguous n-child interval, including shared intersections.',
  'stock_prefix':'When every original1..P is kept, rank(ID)=ID for ID<=P. This proves prefix ID identity, not unconditional byte identity of parent first fields.',
  'missing_generic_guard':'prefix_mask does not explicitly reject prefix>count or negative input. Fixed sealed profiles must actually satisfy these bounds before arithmetic is interpreted; do not use as unrestricted generic API.'},
 {'ID':'G3','topic':'Intervals, duplicates and alias analysis','assessment':'Order-preserving map retains aliases; dynamic census can be partial',
  'witness_lines':lines(c,'if len(ranges[target])<RANGE_CAP')+lines(c,'range_alias_analysis_complete=alias_complete')+lines(c,'if newlast-newfirst!=n-1'),
  'condition':'Do not duplicate shared nodes per parent. Apply one stable mapping per level to all retained IDs, and map all child pointers using that mapping. Then duplicate and overlapping original intervals share the same mapped IDs.',
  'census_limit':'Per-target encoded range list is capped2M. Past cap alias_complete=false; overlap/contiguity census is for stored ranges. Per-parent remap loop checks only first, while mathematical full-range marking gives contiguity for every valid marked interval.',
  'finding':'Late force_all can mark previously skipped lower parents after their edge pass. Retaining every lower row makes retention conservative and dense rank identity, but those newly retained earlier parents are absent from range census. alias_complete only reflects range-cap overflow, so a true value does not independently certify full retained-parent census after anomaly.',
  'required_reporting':'Gate complete census on no anomalies/force_all plus no truncation, or enumerate full retained parents again in a separately authorized scope. No algorithm change or rerun done here.'},
 {'ID':'G4','topic':'Unknown flags and invalid child encodings','assessment':'Conservative retention guard exists; extra semantics unknown',
  'witness_lines':lines(c,'KNOWN_RAW_FLAGS=')+lines(c,'if flags not in KNOWN_RAW_FLAGS')+lines(c,'fill_all(keep[target]'),
  'condition':'Any unclassified flag/invalid range forces all three lower tables retained; no removal may be inferred from its uninterpreted pointer. Source fullrawbits must survive any future writer.',
  'known_shape_boundary':'Set0/4/5/6/8/12/13/14 is declared structural knowledge for first/count and flags&7. High bits8/12/13/14 are not semantically decoded by this source. Recognizing their pointer shape does not prove absence of additional references, special lookup/cache/alias semantics.',
  'safe_result_boundary':'If force_all is set, removal is zero and rank identity. Counts/capacity can remain conservative even when pointer_relation_reachability_complete=false; no full graph/alias semantic proof follows.'},
 {'ID':'G5','topic':'Preserve every active v3 leaf and stock lower IDs','assessment':'Conditional structural retention, no reconstructed image evidence',
  'witness_lines':lines(c,'for level in (4,5):')+lines(c,'original_prefix_IDs_unchanged=True')+lines(c,'lower_retained_records_whose_lowID_would_change'),
  'condition':'Complete root set and all valid ranges ensure every descendant leaf of those roots is retained. Copy each retained original full significant record in original order; remap only proven first fields, keep counts/flags/labelrefs/mapordinal/coords and unknown bits. Prefix IDs stay fixed; active suffix IDs can change.',
  'important_distinction':'Keeping prefix records is presence/ID preservation. If such a parent points to a moved suffix, its first pointer must change. Do not claim every prefix parent byte is unchanged. All active leaf identities require source-bound fullbit/label/point verification, not field arrays alone.',
  'not_proven':'Field arrays retain only first/count/flags; source performs no raw-record copy, patched payload emission, everyleaf identity audit or native query verification. Old-v2 leaf preservation is inherited from producer proof, not rechecked here.'},
 {'ID':'G6','topic':'Hardcoded field extraction','assessment':'Exact pinned profile required',
  'witness_lines':lines(c,"f['first'][ID]=")+lines(c,"f['count'][ID]=")+lines(c,"need(directory.hex()==pin"),
  'condition':'Before treating arrays as the graph, the actual directory must match the exact expected descriptor and all field widths/ref layout offsets, not stride alone. Source actualMDR hash/DIR bindings protect fixed fixture; reusable caller must separately enforce full widths/refs/counts and prefix bounds.',
  'mapordinal':'stream_actual records mapordinal counts but does not reject non1 values. One-GMP/mapordinal1 interpretation is conditional on actual counters or inherited fixed-source proof. No corresponding data counters have been produced by this readonly review.'},
 {'ID':'G7','topic':'Capacity arithmetic and future remap','assessment':'Arithmetic possible; construction/acceptance remains held',
  'witness_lines':lines(c,'new_mdr=container')+lines(c,'metadata_min=')+lines(c,'widths_ok='),
  'condition':'Use exact actualcounts/strides, ceil(count*stride/8) per table, unchanged unknown-prefix/upper-table/DIR size, all five component sizes,4K block ceilings,240 allocation IDs per FAT row, one root row and actual metadata start/floor. Incoming limits are retainedL4<2^23,L5<2^22,L6<2^21; original per-parent count bounds stay unchanged.',
  'capacity_is_only_arithmetic':'fits_4K_capacity_arithmetic is computed separately from anomalies/alias_complete/widths_ok. A true fit must not be reported as safe remap or installable output without those conditions and full original4K header/capacity/geometry/allocation validation.',
  'future_writer_requirements':'Recompute proven table start/size and MDR DIR pointer; bit-splice complete records without per-record padding. Preserve descriptor unknown fields and all unchanged components. Locate/remap or prove absent ALL external lowerID and table-byteoffset references. Check exact header/checksum/CHS contract, virtual fullstream and inverse/readback in a new authorized scope.',
  'unresolved_external_refs':'A stale external suffix ID can silently select a different dense record even when file fits, while removed IDs can become invalid. L3/JAI keys fixed does not resolve L4/L5/L6 consumers.'},
 {'ID':'O1','topic':'Observed wrapper and reported initial memory guard','assessment':'Source instrumentation only; initial failure is no graph result',
  'witness_lines':lines(o,'selected=')+lines(o,'ObserveAllocations')+lines(o,'if enforce and ru>RSS_CAP_KIB'),
  'source_scope':'Exact6bf697 source selects eight original RAM helpers and supplies same flags/range cap plus observed allocate_fields. Adds phase/array observations around selected assignments and does not run closed historical main. This review does not import, compile or call helpers/wrapper.',
  'reported_actual_not_our_execution':{'root_reported_terminal':'19798a EXIT1 before all inputs','root_reported_ru_maxrss_KiB':424240,'root_reported_VmHWM_KiB':17824,'cap_KiB':393216},
  'observation_guard':'This source enforces historical ru_maxrss, logs current proc RSS/HWM without enforcing those values. Different ru/proc observations are not proof of algorithm allocations or future peak. Root pending corrected observation source is outside this pinned review.',
  'readiness':'No reachability count, memory success, projected compact size or renderer cause is inferred from the initial failure.'}
]
write('independent-checklist.json',{'schema':'finite-static-compaction-data-review/v1','findings':checklist,
 'all_assigned_static_topics_reviewed':True,'actual_capacity_or_graph_results_computed':False,
 'no_reviewed_source_execution_import_compile':True,'external_lowerID_or_offset_ABI_proven':False})
sourcepins={'closed':{'path':str(closedpath.relative_to(ROOT)),'bytes':len(closed),'SHA256':sha(closed)},
 'observed':{'path':str(observedpath.relative_to(ROOT)),'bytes':len(observed),'SHA256':sha(observed)},
 'firstguard_and_scope_errata':prior,'eachsource_limit':40960,'total_source_artifact_read_limit':LIMIT}
write('source-pins-and-read-receipts.json',sourcepins)
write('proof.json',{'schema':'independent-readonly-compaction-algorithm-review/v1','all_assigned_static_review_completed':True,
 'sources':sourcepins,'findings_count':len(checklist),'positive_conditional_results':['Full valid range marking + stable rank preserves interval contiguity/shared aliases.','Full prefix marking preserves all stock lower prefix IDs.','Unknown/invalid encoding conservatively forces full lower retention.'],
 'holds':['Full retained-parent alias census after force_all is not certified by alias_complete alone.','Declared known high flags do not settle extra semantics.','Actualgraph/mapordinal/fullprofile data and prefixbounds are prerequisites, not computed here.','Everyactive leaf fullbits and all external lowerID/byteoffset references unresolved.','Capacity arithmetic is not a compact IMG or renderer fix.'],
 'reported_root_initial19798a_failure_retained':True,'pending_corrected_observation_source_reviewed':False,
 'source_or_canonical_or_sealed_scope_modified':False,'actual_IMG_PBF_largeledger_MAIN_bytes':0,
 'nativeCPU_guest_audio_device_UI_route_render_install_App_music_fullgoal':False,
 'own_normal_file_read_bytes_before_seal':reads,'readonly_algorithm_only_no_methods_called':True})
(OUT/'HANDOFF.md').write_text('Finite ordinary FILE/source review only. Exact closeda1a7...27566B and observed6bf697...20555B pinned; sources never imported, compiled or executed.\n\nFull range marking/stable rank preserves stockprefix IDs and overlap alias structurally under complete forward roots/valid profile/range bounds. All active descendants then remain, but suffix lowIDs change and prefix parent pointers may require remap; full significant bits must be copied, field arrays are insufficient.\n\nLate force_all conservatively retains ALL lower data; earlier newly-retained parent edges may be absent from census. Existing alias_complete reflects range cap only, so full retained-parent census is not proved when anomalies/force_all exist. Unknown high flags retain bits but extra semantics/external lowerID or byteoffset consumers remain unknown. Capacity fit alone is not safe compaction, install/render fix or allactiveleaf byte proof.\n\nRoot reported19798a EXIT1 before all inputs: historicalru424240KiB vs procVmHWM17824KiB. No algorithm count/size/peak/cause follows. This pinned source enforces ru guard; root pending corrected source is not reviewed. No RSS cap is changed here.\n\nFirst own25KB description guard ffe73c EXIT1 read0; exact27566B corrected by root to40KiB/source within256KiB aggregate; receipts preserve mismatch. Static snapshot/hash reads only, no IMG/ledger/CPU. Hash-size-stat seal with actual modes, no original changes. Stop after finite review.\n')
# Seal reads only these new bounded artifacts, rechecks original stats without source bytes.
for r in ledger:
 if stat(ROOT/r['path'])!=r['stat_after']:raise ValueError('Original source stat changed during review')
files=[]
for p in sorted(OUT.iterdir()):
 if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-receipt.json']:
  b=read(p);files.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),'stat_at_seal':stat(p),'mode':oct(p.stat().st_mode&0o777)})
write('sealed-files.json',{'schema':'hash-size-stat-readonly-review/v1','files':files,'actual_aggregate_source_artifact_content_bytes_read':reads,
 'read_cap_bytes':LIMIT,'all_reviewed_algorithm_execution_IMG_MAIN_CPU_PBF_guest_audio_device':0,
 'seal_kind':'Hash/size/stat, actualmode; no chmod or immutable access claim','original_source_stat_unchanged':True})
raw=(OUT/'sealed-files.json').read_bytes();reads+=len(raw)
if reads>LIMIT:raise ValueError('Including finalseal read≤256KiB')
print(json.dumps({'all_assigned_readonly_review_completed':True,'files_sealed':len(files),'seal_SHA256':sha(raw),
 'proof_SHA256':next(r['SHA256'] for r in files if r['path'].endswith('/proof.json')),'aggregate_normal_file_bytes_including_finalseal_read':reads,
 'reviewed_algorithm_execution':False,'IMG_guest_device_audio_IO':0,'source_pins_unchanged':True}))
