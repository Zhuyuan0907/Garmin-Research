#!/usr/bin/env python3
"""Independent small-file arithmetic/AST review. No producer import, exec, or IMG open."""
import ast,base64,difflib,gzip,hashlib,json,struct
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=Path('/root/garmin');CAP=262144
prior_reads=123171;own_read_bytes=0
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):
 global own_read_bytes
 s=p.stat();before=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 need(s.st_size<=65536 and prior_reads+own_read_bytes+s.st_size<=CAP,'Aggregate finite small artifact limit')
 b=p.read_bytes();own_read_bytes+=len(b);s=p.stat()
 need(before==[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],'Own cached artifact immutable')
 return b
def save(n,x):
 b=(json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode();need(len(b)<30000,'Small new proof')
 (OUT/n).write_bytes(b)
captured=json.loads(gzip.decompress(read(OUT/'input-capture.json.gz')))
failure=json.loads(gzip.decompress(read(OUT/'initial-failure-input-capture.json.gz')))
blobs={k:base64.b64decode(v) for k,v in captured['blobs_base64'].items()}
fb={k:base64.b64decode(v) for k,v in failure['blobs_base64'].items()}
records={r['key']:r for r in captured['receipts']};fr={r['path'].split('/')[-1]:r for r in failure['receipts']}
for tag in ['new','old']:
 seal=json.loads(blobs[tag+'/sealed-files.json'])
 for r in seal['files']:
  key=tag+'/'+r['path'].split('/')[-1];need(key in blobs,'Every closed listed small file captured')
  need(sha(blobs[key])==r['sha256'] and len(blobs[key])==r['bytes'] and records[key]['mode']==r['mode'],'Closed SHA/size/mode row '+key)
for r in json.loads(fb['failed-closure-seal.json'])['files']:
 name=r['path'].split('/')[-1];need(sha(fb[name])==r['sha256'] and len(fb[name])==r['bytes'] and fr[name]['mode']==r['mode'],'Failed original source/seal pin')
def independently_decode(h):
 need(len(h)==512 and h[:1]==b'\0' and h[16:22]==b'DSKIMG' and h[510:512]==b'\x55\xaa','Captured whole header signature')
 u16=lambda at:struct.unpack_from('<H',h,at)[0]
 u32=lambda at:struct.unpack_from('<I',h,at)[0]
 spt=u16(24);heads=u16(26);cylinders=u16(28);spt2=u16(95);heads2=u16(93)
 block=2**h[97]*2**h[98];nblocks=u16(99);decl=u32(458);relative=u32(454)
 endhead=h[451];endsector=h[452]%64;endcyl=h[453]+(h[452]//64)*256
 count=((endcyl*heads+endhead)*spt)+endsector
 need(spt>0 and heads>0 and 1<=endsector<=spt and endhead<heads,'Independent CHS field domain')
 return {'sectors_per_track':spt,'repeat_sectors':spt2,'heads':heads,'repeat_heads':heads2,'cylinders':cylinders,
  'geometry_capacity_bytes':spt*heads*cylinders*512,'block_exponents':[h[97],h[98]],'block_bytes':block,'declared_blocks':nblocks,
  'block_capacity_bytes':block*nblocks,'declared_sectors':decl,'sector_capacity_bytes':decl*512,'relative_LBA':relative,
  'endCHS':[endcyl,endhead,endsector],'CHS_covered_sectors':count,'CHS_matches_declared':count==decl,
  'geometry_covers_declared':spt*heads*cylinders>=decl,'opaque_0x0F':h[15],'sum_first512_mod256':sum(h)%256,
  'sum_first128_mod256':sum(h[:128])%256,'checksum_algorithm_proved':False}
headers={k:independently_decode(blobs[k]) for k in blobs if k.endswith('-header.bin')}
oldproof=json.loads(blobs['old/proof.json']);proof=json.loads(blobs['new/proof.json']);plan=json.loads(blobs['new/prepared-control-plan.json'])
receipt=json.loads(blobs['new/actual-root-tool-receipt.json']);actual=receipt['actual_result']
need(actual['chunk_id']=='9b63ea' and actual['exit_code']==0,'Recorded original actual full-stream terminal')
terminal=json.loads(actual['output']);need(terminal['proof_sha256']==sha(blobs['new/proof.json']),'Actual terminal binds closed producer proof')
specs=[('eightK_end_mirror','old/regressed_v3-header.bin',[452],[208],[224]),
       ('expanded_fourK_geometry','old/expanded_4K-header.bin',[24,95,451,452,453],[16,16,15,208,255],[32,32,14,160,72])]
diffs={};total_stream_bytes=0
for name,oldkey,offsets,oldvalues,newvalues in specs:
 newkey='new/'+name+'-header.bin';a=blobs[oldkey];b=blobs[newkey];idx=[i for i in range(512) if a[i]!=b[i]]
 need(idx==offsets and [a[i] for i in idx]==oldvalues and [b[i] for i in idx]==newvalues,'Whole512 independent exact diff '+name)
 metadata=plan[name];control=proof['controls'][name];stream=json.loads(blobs['new/'+name+'-actual-stream-receipt.json']);d=headers[newkey]
 need(control==stream and control['source_stat_before']==control['source_stat_after'],'Recorded stream controls consistent/immutable source')
 need(control['bytes_read']==metadata['bytes']==control['source_stat_before'][2],'Exact ordinary original full source read length')
 need(control['source_actual_full_SHA256']==metadata['sha256'],'Recorded original SHA equals source pin')
 need(control['virtual_full_SHA256']==terminal['controls'][name]['virtual_SHA256'],'Actual terminal virtual SHA matches stream receipt')
 need(idx==metadata['changed_byte_offsets']==control['changed_byte_offsets'],'Header/plan/receipt complete byte diff consistent')
 need(sha(a)==metadata['source_header_sha256'] and sha(b)==metadata['corrected_header_sha256'],'Prepared whole header digest pins')
 need(d['CHS_matches_declared'] and d['geometry_covers_declared'],'Independent virtualCHS covers declaration')
 need(d['block_capacity_bytes']==d['sector_capacity_bytes'] and d['repeat_sectors']==d['sectors_per_track'] and d['repeat_heads']==d['heads'],'Independent LE block/sector/repeated geometry equal')
 need(d['opaque_0x0F']==a[15] and d['block_exponents']==headers[oldkey]['block_exponents'],'Opaque checksum and block layout unchanged')
 need(d['relative_LBA']==0,'Fixed supported controls relativeLBA0')
 diffs[name]={'old_header_SHA256':sha(a),'new_header_SHA256':sha(b),'full512_diff':[{'offset':i,'hex_offset':hex(i),'old':a[i],'new':b[i]} for i in idx],
  'all_other_512_bytes_identical':True,'independent_old_decode':headers[oldkey],'independent_new_decode':d,
  'stream_full_SHA_recorded_not_recomputed':control['virtual_full_SHA256'],'source_full_SHA_recorded_not_recomputed':control['source_actual_full_SHA256']}
 total_stream_bytes+=control['bytes_read']
need(blobs['old/stock-header.bin']==blobs['old/healthy_v2-header.bin'],'Stock/v2 full512 identical')
need(headers['old/stock-header.bin']['sum_first512_mod256']==headers['old/healthy_v2-header.bin']['sum_first512_mod256']==187,'Stock/v2 sum187, no zero-sum checksum proof')
need(headers['new/expanded_fourK_geometry-header.bin']['endCHS']==[584,14,32] and headers['new/expanded_fourK_geometry-header.bin']['declared_sectors']==299488
 and headers['new/expanded_fourK_geometry-header.bin']['declared_blocks']==37436 and headers['new/expanded_fourK_geometry-header.bin']['block_bytes']==4096,'Exact independent expanded4K result')
need(total_stream_bytes==proof['total_actual_IMG_bytes_read']==terminal['actual_IMG_read_bytes']==306683904<proof['actual_IMG_read_cap']==320000000,'Recorded combined320M stream cap')
need(proof['sampled_current_mm_peak_KiB']==terminal['current_mm_peak_KiB']==19040<proof['current_mm_cap_KiB']==65536,'Recorded current process64MiB guard')
source=blobs['new/producer-source.py'].decode();decoder=blobs['new/header-decoder-source.py'].decode();tree=ast.parse(source);ast.parse(decoder)
fn={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
assign={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
input_ast=assign['IMG_INPUTS'];need(isinstance(input_ast,ast.Dict),'Fixed inputs dict AST')
inputs={}
for k,v in zip(input_ast.keys,input_ast.values,strict=True):
 need(isinstance(v,ast.Call) and isinstance(v.func,ast.Name) and v.func.id=='dict' and not v.args and all(w.arg is not None for w in v.keywords),'Only literal dict keyword input metadata')
 inputs[ast.literal_eval(k)]={w.arg:ast.literal_eval(w.value) for w in v.keywords}
need(len(inputs)==2,'Exactly two fixed producer inputs')
need(ast.literal_eval(assign['IMG_BUDGET'])==320000000 and ast.literal_eval(assign['RAM_BUDGET_KIB'])==65536,'Static bounded ordinary source')
need("with path.open('rb') as stream:" in source and "virtual_hash.update(corrected);virtual_hash.update(memoryview(raw)[512:])" in source
 and 'virtual_hash.update(raw)' in source and 'baseline_hash.update(raw)' in source,'Static full virtual/source dataflow present')
patch_writes=[]
for n in ast.walk(fn['patch']):
 if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Subscript) and isinstance(n.targets[0].value,ast.Name) and n.targets[0].value.id=='output':
  sl=n.targets[0].slice
  if isinstance(sl,ast.Constant):patch_writes.append([sl.value,sl.value+1])
  else:patch_writes.append([ast.literal_eval(sl.lower),ast.literal_eval(sl.upper)])
need(sorted(patch_writes)==[[24,26],[95,97],[451,452],[452,453],[453,454]],'All producer header write ranges finite and exact')
old_source=fb['actual-failed-producer-source.py'].decode()
diff=''.join(difflib.unified_diff(old_source.splitlines(True),source.splitlines(True),fromfile='closed-failed-v1',tofile='new-v2'))
need(diff==fb['v1-to-v2-preparation.diff'].decode(),'Independent full source diff equals closed change manifest')
fail=json.loads(fb['failure.json']);failreceipt=json.loads(fb['actual-root-tool-receipt.json'])
need(fail['actual_IMG_read_bytes']==0 and failreceipt['actual_result']['chunk_id']=='1f2f04' and failreceipt['actual_result']['exit_code']==1,'Initial failure retained before IMG open')
save('independent-header-full512-review.json',{'all_headers':headers,'controls':diffs,'stock_v2_full512_identical':True,'checksum_interpretation':'0x0F is an opaque byte,219 for stock/v2/expanded,0 for8K. First512 sums187/187 and nonzero virtual sums do not prove or disprove unknown exact-device algorithm.'})
checklist=[
 {'item':'Full512 exact captured-header diffs and LE/CHS','verdict':'PASS actual small bytes','evidence':'Onebyte452/D0→E0 and fivebytes24,95,451,452,453; independent decoder confirms exact declarations/last-sector arithmetic.'},
 {'item':'Original/virtual whole hashes','verdict':'CONSISTENT recorded fullstream, not independently recomputed','evidence':'9b63ea terminal/proof/perstreamreceipts match;306683904 originalbytes recorded and originalSHA equals fixedpins. Independent source does not open IMG.'},
 {'item':'Virtual stream transformation scope','verdict':'PASS static ordinary DATA flow','evidence':'First chunk source512 is compared to pinned original; virtual hash consumes corrected512 + same rawtail, all later rawchunks. Input mode rb, no image writes. Blockexponents/FAT/payload bytes untouched.'},
 {'item':'188870 supplement records','verdict':'PRESERVATION by nonheader identity; count inherited','evidence':'No per-record traversal/count performed by producer or independent review. All nonheader bytes source-identical under fixed transformation; native lookup semantics held.'},
 {'item':'Read/RAM resource guards','verdict':'PASS recorded bounded singleprocess scope','evidence':'Fixed320Msumguard,1MiBchunks,lengthchecks,combinedactual_read increments,perchunkprocVmRSS/VmHWM64MiB;actual19040KiB. No historicalru used.'},
 {'item':'Stat and handles','verdict':'PASS flow/record consistency, caveat explicit','evidence':'Regular-file dev/inode/size/mtime/ctime before/after equal in receipts, wholeoriginalSHA recorded; completed with rb infersclose. Producer sets source_handle_closed=True rather than directly measuring stream.closed/fstat.'},
 {'item':'Failure and guard change','verdict':'PASS preserved real failure','evidence':'1f2f04 EXIT1/IMG0 source/failure/receipt sealed. Only OUTv2 and expected endhead-byte list changed; geometry arithmetic/guards unchanged. V1 not called passed.'},
 {'item':'Fakepass/static robustness limits','verdict':'HELD future generalized writer','evidence':'Python assert checks depend on optimization being disabled; command uses python3 with no-O but no sys.flags.optimize attestation. Captured producer/helper bytes are post-run snapshots, not independently bound loadedcode. Fixedinputs relativeLBA0 valid; future nonzeroLBA/general geometry unsupported here. No independent fullstream rerun.'},
 {'item':'Checksum/device/renderer/capacity interpretation','verdict':'HELD','evidence':'Opaque0x0F preserved, no checksum algorithm proved; referenceJava comments are not exact HWID1352 policy. Header coherence is not rendering-cause proof, admission proof, or128MiB hardwarelimit.'}
]
save('independent-checklist.json',{'checks':checklist,'producer_AST_SHA256':sha(ast.dump(tree,include_attributes=False).encode()),'actual_header_write_ranges_half_open':patch_writes,'producer_or_helper_execution':False,'producer_source_SHA256':sha(blobs['new/producer-source.py']),'helper_source_SHA256':sha(blobs['new/header-decoder-source.py'])})
reviewproof={'schema':'independent-small-artifact-AP-coherent-geometry-review/v1','all_assigned_finite_readonly_checks_completed':True,
 'independent_full512_and_arithmetic_passed':True,'reviewed_producer_proof_SHA256':sha(blobs['new/proof.json']),
 'original_actual_terminal':{'chunk':'9b63ea','exit_code':0,'IMG_read_bytes_recorded':306683904},
 'original_failed_terminal':{'chunk':'1f2f04','exit_code':1,'IMG_read_bytes_recorded':0},
 'actual_review_IMG_PBF_MAIN_bytes':0,'producer_or_guest_execution':False,'independent_whole_virtual_hash_recomputed':False,
 'input_integrity':'Alllisted closedfiles actualread SHA/size/mode plus before/afterstatverified; authoritative providedproof/plan/seal/rootreceipt pins checked.',
 'explicit_artifact_reads_before_review':prior_reads,'explicit_owned_capture_reads_this_review':own_read_bytes,'explicit_artifact_reads_after_review':prior_reads+own_read_bytes,
 'aggregate_read_cap':CAP,'input_capture_original_bytes':captured['actual_normal_input_bytes'],'initial_failure_extra_capture_bytes':failure['extra_input_bytes'],
 'header_control_names':list(diffs),'checksum_device_admission_renderer_cause_hardwarelimit_held':True,
 'falseflags':{'new_IMG':False,'image_modification':False,'nativeCPU':False,'guest':False,'device':False,'audio':False,'App':False,
  'install':False,'rendererfix':False,'routeUI':False,'fullgoal':False},'stop_after_seal':True}
save('proof.json',reviewproof)
save('scope-summary.json',{'actual_review':'Finite ordinary artifacts only','header_diff_and_CHS':'PASS actual512byte comparison','8K':[452,208,224],
 'expanded4K_offsets':[24,95,451,452,453],'expanded4K_endCHS':[584,14,32],'declared4K':{'sectors':299488,'blocks':37436,'blockbytes':4096},
 'stock_v2_first512_sum':187,'original_terminal':'9b63ea EXIT0/306683904B recorded','firstfailure':'1f2f04 EXIT1/IMG0',
 'independent_wholehash':False,'new_IMG_native_device_audio':False,'holds':['Checksum/device acceptance/road-losscause/128MiBhardwarelimit','Recordcount188870 inherited; preservedby nonheaderidentity','Assertion optimization/loadedcode/explicitstreamclosed attestations not independently proved']})
(OUT/'actual-source-v1-to-v2-independent.diff').write_text(diff)
print(json.dumps({'all_assigned_readonly_checks_completed':True,'independent_full512_CHS':True,'own_IMGreads':0,
 'explicit_normal_artifact_reads_so_far':prior_reads+own_read_bytes,'cap':CAP,'initialfailure_preserved':True,
 'producer_or_guest_executed':False,'independent_wholehash_recomputed':False,'proof_SHA256':sha((OUT/'proof.json').read_bytes())}),flush=True)
