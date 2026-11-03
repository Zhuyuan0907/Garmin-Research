import hashlib
import json
import os
from pathlib import Path
import struct

P=Path(__file__).resolve().parent
V1=P.parent/'navigation-AP-coherent-expanded4K-restore-binding-preparation-v1'
ROOT=Path.cwd()
receipts=[];img_receipts=[];handles=[];raw_count=0;decoded_count=0
state={'phase':'initial','complete':False}

def stat5(q):
    s=q.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def get(q,want=None,compressed=False):
    global raw_count,decoded_count
    s=stat5(q);assert s[2]<=1024*1024
    with q.open('rb') as h:raw=h.read(1024*1024+1)
    assert h.closed and len(raw)==s[2] and stat5(q)==s
    sha=hashlib.sha256(raw).hexdigest()
    if want is not None:assert sha==want
    raw_count+=len(raw)
    if not compressed:decoded_count+=len(raw)
    assert raw_count<=3145728 and decoded_count<=4194304
    receipts.append({'path':str(q.relative_to(ROOT)),'bytes':len(raw),'SHA256':sha,
                     'stat_before_after':s,'mode':oct(q.stat().st_mode&0o777),'handle_closed':h.closed,
                     'compressed_recipe':compressed})
    return raw

def put(name,value):
    (P/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')

try:
    assembly=json.loads(get(P/'source-assembly-and-preflight-proof.json'))
    raw_count+=assembly['artifact_raw'];decoded_count+=assembly['artifact_decoded']
    preparer_preflight=json.loads(get(P/'preparer-static-preflight-read-receipt.json'))
    raw_count+=preparer_preflight['actual_source_file_read_bytes']
    decoded_count+=preparer_preflight['actual_source_file_read_bytes']
    api_raw=get(P/'expanded_4k_stock_restore.py',assembly['new_API_SHA256'])
    module={'__name__':'bounded_coherent_expanded4K_host'}
    exec(compile(api_raw,str(P/'expanded_4k_stock_restore.py'),'exec'),module)
    for name in assembly['globals_prevalidated_before_IMGread']:assert callable(module[name])
    # Read and bind only already sealed90112/772 return-byte captures from v1.
    oldseal=json.loads(get(V1/'sealed-files.json','7224b4976f617a8de576c8e25012fe5dfae02029ecf7369595cc35234e09ed21'))
    oldpins={Path(r['path']).name:r for r in oldseal['files']}
    for n in ('metadata-actual.bin','MDRheader-actual.bin','coherent-expanded4K-header.bin'):
        assert stat5(V1/n)==oldpins[n]['stat_after_freeze']
    metadata=get(V1/'metadata-actual.bin','8b68a355c596523d5bb5578a7b2475e6bbdf218f97531a5feb05a29e26ffcd8a')
    mdrheader=get(V1/'MDRheader-actual.bin',module['MDR_HEADER_SHA'])
    coherent_header=get(V1/'coherent-expanded4K-header.bin',module['HEADER_SHA'])
    corrected_prefix=coherent_header+metadata[512:]
    # Validate profile, every FAT row/allocation, globals and offset BEFORE any
    # fresh IMG read. Decimal600 is unchanged helper ABI, not relaxed geometry.
    current=module['_parse_candidate_prefix'](corrected_prefix)
    descriptor=struct.unpack_from('<4I',mdrheader,600)
    assert descriptor==(149220236,120,20,1)
    assert len(metadata)==90112 and len(mdrheader)==772
    assert [i for i,(a,b) in enumerate(zip(metadata[:512],coherent_header)) if a!=b]==[24,95,451,452,453]
    assert module['RANGE_OFFSETS']==[None,772,4195100,21728654,70204713,None,149214669,None]
    v3binding=json.loads(get(ROOT/'staging/navigation-country-native-lane-restore-v3/actual-stock-restore-binding.json',
                            '0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89'))
    expected_tables=module['EXPECTED_TABLES']
    assert tuple((x['level'],x['start'],x['bytes'],x['count'],x['stride']) for x in v3binding['candidate_layout']['tables'])==expected_tables
    assert v3binding['MDR_candidate_offsets_by_original_range_index']==module['RANGE_OFFSETS']
    expanded=json.loads(get(ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1/proof.json',
                           '7b5315087aebfda01db11d72bc206aaba23780031d90b92edcfcee3c0188c41a'))
    plan=json.loads(get(ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1/plan.json',
                       '8c45831edac70c2b17b187136acf38f8767eb7c617f59afd38dd9c9156fda5f0'))
    # Seal is pinned from its actual bytes; the closed proof pins component
    # digests. No invented seal digest and no full component reread.
    expandedseal=json.loads(get(ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1/sealed-files.json'))
    controlproof=json.loads(get(ROOT/'staging/navigation-AP-coherent-geometry-virtual-controls-v2/proof.json',
                               'dace2db29b3a7d36dc74e775b78501bbe0d9673da77e8f524a05fe7b662e7683'))
    controlplan=json.loads(get(ROOT/'staging/navigation-AP-coherent-geometry-virtual-controls-v2/prepared-control-plan.json',
                              'dc636ce504acb7ef3a8b0980d4f91b796f05fc6f07dcbb52aed9d73c6740f655'))
    controlseal=json.loads(get(ROOT/'staging/navigation-AP-coherent-geometry-virtual-controls-v2/sealed-files.json',
                              'b3365a9aa57c0181adcbebf80ce3ac3c58463706b9e773280db3433e9eba67da'))
    assert controlproof['controls']['expanded_fourK_geometry']['virtual_full_SHA256']==module['CANDIDATE_SHA']
    assert controlplan['expanded_fourK_geometry']['corrected_header_sha256']==module['HEADER_SHA']
    assert expanded['all_six_logical_components_byte_identical_to_v3'] is True
    assert [x['logical_bytes'] for x in expanded['complete_actual_logical_component_readback']]==[x[1] for x in module['ALLOCATIONS']]
    assert [(x['name'],x['first_block'],x['block_count'],x['fat_parts']) for x in plan['component_allocations']]==[(x[0],x[2],x[3],x[4]) for x in module['ALLOCATIONS']]
    recipe_raw=get(ROOT/'staging/navigation-country-layout-restore-v2/restore-layout.json.gz',module['RECIPE_SHA'],True)
    stock=module['_decode_recipe'](recipe_raw,False)
    decoded_count+=module['RECIPE_PLAIN_BYTES']
    assert stock.uncompressed_sha256=='44ac0746da599dfd67f317bcba70fa891f315576cf0995f8a483ed9ba18401aa'
    assert raw_count<=3145728 and decoded_count<=4194304
    state['phase']='all dependent metadata/globals/recipe prevalidated before new DIR I/O'
    # Fresh only120 bytes. Mapping derives from the fully parsed captured FAT;
    # source stat must match the closed source from which captures originated.
    source=ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled'
    source_pin=[45826,538397,153337856,1791347653105259871,1791347659645611251]
    assert stat5(source)==source_pin and source.stat().st_mode&0o777==0o444
    ci=current['components'][module['MDR']]
    index,inside=divmod(descriptor[0],4096)
    assert inside+120<=4096 and descriptor[0]+120==ci['size']
    physical=ci['blocks'][index]*4096+inside
    with source.open('rb') as h:
        h.seek(physical);directory=h.read(120)
        img_receipts.append({'purpose':'fresh actual native DIR120','physical_offset':physical,
                             'logical_offset':descriptor[0],'bytes':len(directory),
                             'SHA256':hashlib.sha256(directory).hexdigest()})
        assert len(directory)==120 and hashlib.sha256(directory).hexdigest()==module['MDR_DIRECTORY_SHA']
    handles.append({'path':str(source.relative_to(ROOT)),'handle_closed':h.closed})
    assert h.closed and stat5(source)==source_pin
    binding=module['prepare_restore_binding'](stock,corrected_prefix,mdrheader,directory)
    assert binding['MDR']['tables']==module['_decode_directory'](directory)
    put('expanded4K-stock-restore-binding.json',binding)
    assert (P/'expanded4K-stock-restore-binding.json').stat().st_size<=16384
    (P/'actual-native-directory120.bin').write_bytes(directory)
    # <=16KiB isolated helper fixture. It does not represent a supported IMG.
    fixture=b''.join(bytes((j*m+c)&255 for j in range(4096)) for m,c in ((37,11),(51,43),(13,17)))
    assert len(fixture)==12288
    fixture_path=P/'synthetic-host-helper-fixture.bin';fixture_path.write_bytes(fixture)
    checks=[]
    with fixture_path.open('rb') as f:
        component={'size':12288,'blocks':[2,0,1]}
        actual=module['logical_read'](f,component,4096,4090,8192)
        expected=fixture[12282:12288]+fixture[:4096]+fixture[4096:8186]
        assert actual==expected and len(actual)==8192
        checks.append({'case':'unaligned three-block non-monotonic physical mapping','bytes_read':8192,'passed':True})
        for offset,length,name in ((12287,2,'outside logical end'),(0,65537,'bounded logical length'),(-1,1,'negative logical offset')):
            try:module['logical_read'](f,component,4096,offset,length)
            except ValueError:checks.append({'case':name,'bytes_read':0,'passed':True})
            else:raise AssertionError(name+' was admitted')
        module['_hash_file_fresh'](f,12288,hashlib.sha256(fixture).hexdigest())
        checks.append({'case':'fresh complete helper hash and immutable fstat','bytes_read':12288,'passed':True})
        try:module['_hash_file_fresh'](f,12288,'0'*64)
        except ValueError:checks.append({'case':'wrong complete helper SHA rejected','bytes_read':12288,'passed':True})
        else:raise AssertionError('wrong fixture hash accepted')
    assert f.closed
    # Helpers explicitly read the fixture as artifact data; count actual bytes.
    fixture_reads=sum(x['bytes_read'] for x in checks)
    raw_count+=fixture_reads;decoded_count+=fixture_reads
    assert raw_count<=3145728 and decoded_count<=4194304
    put('synthetic-helper-controls.json',{'fixture_bytes':12288,'fixture_SHA256':hashlib.sha256(fixture).hexdigest(),
        'checks':checks,'actual_fixture_bytes_read':fixture_reads,'fixture_handle_closed':f.closed,
        'complete_supported_IMG_fixture':False,'production_restore_generator_run':False})
    inherited=[{'name':x['name'],'logical_bytes':x['logical_bytes'],'SHA256':x['sha256'],
                'scope':'closed expanded4K full component readback, inherited; not rehashed in this scope'}
               for x in expanded['complete_actual_logical_component_readback']]
    state={'phase':'finite binding and helper controls complete','complete':True}
    put('proof.json',{'scope':P.name,'all_assigned_finite_preparation_checks_passed':True,
         'actual_new_IMG_reads':img_receipts,'new_IMGbytes':120,'prior_failed_v1_IMGbytes':90884,
         'cumulative_v1_v2_IMGbytes':91004,'IMGcap':1048576,
         'saved_capture_reuse':'90112 metadata+772 MDR header from sealed v1, exact SHA/stat verified',
         'original_directory_descriptor_offset':600,'guard_relaxed':False,
         'coherent_prefix_SHA256':hashlib.sha256(corrected_prefix).hexdigest(),
         'coherent_prefix_is_virtual_preparation_not_actual_full_candidate':True,
         'source_IMG_stat_before_after':source_pin,'all_source_IMG_handles_closed':handles,
         'recipe_gzip_EOF_CRC_and_both_digests_checked':True,
         'recipe_compressed_SHA256':stock.compressed_sha256,'recipe_decoded_SHA256':stock.uncompressed_sha256,
         'six_logical_component_evidence_inherited':inherited,
         'closed_whole_source_and_virtual_hash_receipt':controlproof['controls']['expanded_fourK_geometry'],
         'old8K_API_and32768_guard_unchanged':True,
         'binding_geometry':'4096B/37436blocks/299488sectors; same MDR149220356 and v3 native tables',
         'actual_artifact_raw_before_final_seal':raw_count,'actual_artifact_decoded_before_final_seal':decoded_count,
         'artifact_caps':{'raw':3145728,'decoded':4194304},'synthetic_fixture_bytes':12288,
         'production_remaining_gate':'Materialize externally reviewed coherent input; this API freshly hashes exact153337856B/8749... plus immutable fstat before first yield, rereads exact metadata/MDR772/DIR120, then consumes all96739328 reconstructed bytes through generator EOF and validates864d... plus unchanged fstat.',
         'falseflags':dict.fromkeys(['production_full_input_hash_run','production_stock_reconstruction_run','full_component_hashes_repeated','fullIMG_output','nativeCPU','guest','MAIN','PBF','firmware','device','audio','services','package','install','hardware_admission','checksum_verified','renderer_fix','UIroute','App','fullgoal'],False)})
    put('scope-summary.json',{'scope':P.name,'finite_preparation_complete':True,
         'old8K_helper_unchanged':True,'supported_target_bytes':153337856,'supported_target_SHA256':module['CANDIDATE_SHA'],
         'header512_SHA256':module['HEADER_SHA'],'block_bytes':4096,'blocks':37436,'sectors':299488,
         'new_IMGbytes':120,'prior_failure_IMGbytes':90884,'cumulative_IMGbytes':91004,
         'whole_components_and_source_hashes':'inherited closed evidence, no fresh rehash',
         'API':'expanded_4k_stock_restore.py: restored_stock_blocks(candidate_path,recipe_path,binding_path,binding_sha256,read_receipts=None)',
         'binding':'expanded4K-stock-restore-binding.json','helper_controls_passed':len(checks),
         'production_whole_restore_run':False,'remaining_gate':'fresh exact coherent full SHA/stat before first yield; exact metadata/FAT/MDR; complete original stock hash at generator EOF',
         'no_device_native_audio_package_install_or_admission_claim':True})
    print(json.dumps({'finite_preparation_passed':True,'new_IMGbytes':120,'cumulative_IMGbytes':91004,
                      'artifact_raw':raw_count,'artifact_decoded':decoded_count,'helper_controls':len(checks),
                      'production_reconstruction_run':False}))
except BaseException as e:
    put('failure.json',{'actual_exception':repr(e),'state':state,'actual_IMG_reads_so_far':img_receipts,
                        'artifact_raw_so_far':raw_count,'artifact_decoded_so_far':decoded_count,
                        'constraint':'stop at first unrelated failure; no broadened guards/retry'})
    raise
finally:
    put('actual-normal-data-read-journal.json',{'state':state,'artifact_reads':receipts,
        'artifact_raw':raw_count,'artifact_decoded':decoded_count,'raw_cap':3145728,'decoded_cap':4194304,
        'actual_new_IMG_reads':img_receipts,'IMG_handles':handles,'prior_v1_IMGbytes':90884,
        'IMG_cap':1048576,'reviewed_old_module_run':False,'new_normal_host_helper_definition_run':True})
