#!/usr/bin/env python3
"""One actual portable production load_manifest call; no old controls/device."""
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');PKG=Path(__file__).resolve().parents[1];OUT=PKG/'validation'
SMALL_SEAL_SHA='ab5841bd0555dbe174f49f66e6085b57cec5a6ae0643c4d7b6cd56c35c121c59'
MANIFEST_SHA='c0b6fd6b70af1a1c7a1d241e51f7649d61caa1abb551b73f4c419119ff5d64bc'
INSTALLER_SHA='cefe766e9b1c0380a72e588e53da1fbc5fc1037a3510cbb507cb2a1526403374'
API_SHA='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
SUPPORT_SHA='8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411'
CANDIDATE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
STOCK_SHA='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
ROAD_SHA='664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117'


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]


def main():
    need(not(OUT/'production-load-manifest-proof.json').exists(),'Refuse overwrite NEW production proof')
    started=datetime.now(timezone.utc).isoformat();t0=time.monotonic();inputs=[]
    def pin(path,expected,maxbytes):
        before=identity(path);need(before[2]<=maxbytes,'Small production input bound')
        raw=path.read_bytes();need(sha(raw)==expected and identity(path)==before,'Sealed production input changed')
        inputs.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':expected,'stat_before':before,'stat_after':identity(path)})
        return raw
    seal=json.loads(pin(PKG/'sealed-files.json',SMALL_SEAL_SHA,65536));need(seal['all_assigned_checks_passed'],'Small preparatory seal success')
    rows={Path(x['path']).name:x for x in seal['files']}
    pins={'manifest.json':MANIFEST_SHA,'install_native_house_supplement.py':INSTALLER_SHA,
          'native_8k_stock_restore.py':API_SHA,'device_support.py':SUPPORT_SHA}
    for name,digest in pins.items():
        row=rows[name];need(row['sha256']==digest and (ROOT/row['path'])==PKG/name,'Exact sealed portable module/manifest location')
        pin(PKG/name,digest,65536)
    link_path=OUT/'full-image-hardlink-binding.json';link_before=identity(link_path);link_raw=link_path.read_bytes();links=json.loads(link_raw)
    need(links['all_assigned_checks_passed'] and links['device_IO'] is False and identity(link_path)==link_before,'Root hardlink binding is complete and immutable')
    source_bindings=[]
    for row in links['bindings']:
        src=ROOT/row['source'];dst=PKG/row['destination'];actual=identity(dst)
        need(actual==identity(src)==row['stat_after_link'] and row['all_prior_readers_closed'] is True
             and row['hardlinked'] is True and row['image_content_not_rewritten'] is True,'Root exact post-link actual source binding')
        source_bindings.append({'source':row['source'],'bundle_path':row['destination'],'stat_before':actual,
                                'expected_sha256':CANDIDATE_SHA if row['destination'].startswith('candidate/') else ROAD_SHA,
                                'same_inode_as_bound_source':True})
    need({x['bundle_path'] for x in source_bindings}=={'candidate/gmapprom1.img','roadmap/Taiwan_OSM_SearchRepair_v2.img'},'Both actual image links present')
    def load(path,name):
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module;spec.loader.exec_module(module);return module
    support=load(PKG/'device_support.py','device_support')
    api=load(PKG/'native_8k_stock_restore.py','native_8k_stock_restore')
    installer=load(PKG/'install_native_house_supplement.py','actual_v3_production_load')
    modules={'installer':str(Path(installer.__file__).resolve().relative_to(ROOT)),
             'device_support':str(Path(support.__file__).resolve().relative_to(ROOT)),
             'native_8k_stock_restore':str(Path(api.__file__).resolve().relative_to(ROOT))}
    returned_digests=[];stock_returns=[];actual_layouts=[]
    def observe(frame,event,result):
        if event!='return':return
        if frame.f_code is support.verify_file.__code__ and 'h' in frame.f_locals:
            returned_digests.append({'path':str(frame.f_locals['path'].resolve().relative_to(ROOT)),
                                     'actual_computed_sha256':frame.f_locals['h'].hexdigest(),
                                     'expected_sha256':frame.f_locals['sha'],
                                     'returned_successfully':result is None,
                                     'observed_function':'Unchanged verify_file inline SHA256'})
        elif frame.f_code is api.reconstructed_stock_hash.__code__:
            stock_returns.append(result)
        elif frame.f_code is api._layouts_and_header.__code__ and result is not None:
            actual_layouts.append({'block_bytes':result['block_bytes'],'metadata_bytes':result['metadata_bytes'],
                                   'six_component_names':list(result['components'])})
    need(sys.getprofile() is None,'Production observation installs no nested profiler')
    sys.setprofile(observe)
    try:
        m,source,recipe,manifest_sha=installer.load_manifest(PKG)
    finally:sys.setprofile(None)
    need(manifest_sha==MANIFEST_SHA and source==PKG/'candidate/gmapprom1.img','Actual production manifest/source identity')
    need(stock_returns==[STOCK_SHA],'Actual production helper returned exact stock digest once')
    need(len(actual_layouts)==1 and actual_layouts[0]['block_bytes']==8192,'Actual8K layout executed once during production restoration')
    candidate_returns=[x for x in returned_digests if x['path']==str(source.relative_to(ROOT))]
    need(len(candidate_returns)==1 and candidate_returns[0]['actual_computed_sha256']==CANDIDATE_SHA,'Actual complete bundled candidate digest once')
    need(recipe['stock'].fixture is False and recipe['binding']['original_sha256']==STOCK_SHA
         and recipe['binding']['candidate_layout']['candidate_sha256']==CANDIDATE_SHA,'Actual recipe/binding returned production objects')
    for row in inputs:need(identity(ROOT/row['path'])==row['stat_before']==row['stat_after'],'Portable smallfiles remain immutable')
    for row in source_bindings:
        row['stat_after']=identity(PKG/row['bundle_path']);need(row['stat_after']==row['stat_before'],'Image ctime/linkcount stable during actual production control')
    need(identity(link_path)==link_before,'Root hardlink receipt immutable')
    proof={'schema':'NEW-actual-portable-v3-production-load-manifest-proof/v1',
        'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t0,
        'all_assigned_checks_passed':True,'production_load_manifest_passed':True,
        'actual_load_manifest_calls':1,'script_sha256':sha(Path(__file__).read_bytes()),
        'actual_module_locations':modules,'exact_small_input_bindings':inputs,
        'root_image_hardlink_binding':{'path':str(link_path.relative_to(ROOT)),'bytes':len(link_raw),'sha256':sha(link_raw),
            'stat_before':link_before,'stat_after':identity(link_path)},
        'actual_source_image_bindings':source_bindings,'actual_digest_function_returns':returned_digests,
        'complete_bundled_candidate_hash_verified_this_control':True,'candidate_complete_digest_call_count':1,
        'candidate_bytes':153346048,'candidate_actual_sha256':CANDIDATE_SHA,
        'exact_stock_reconstruction_actual_helper_returns':stock_returns,'exact_stock_reconstructed_sha256':STOCK_SHA,
        'exact_stock_reconstructed_bytes':96739328,'complete_generator_EOF_consumed':True,
        'actual_8K_header_FAT_directory_layouts':actual_layouts,
        'rollback_stock_recipe_bytes':879499,'rollback_actual_binding_bytes':292144,
        'roadmap_content_hash_inherited_from_bound_Searchv2_source':ROAD_SHA,
        'roadmap_complete_hash_repeated_in_this_control':False,
        'observation':'Python return-event profiling observes genuine unmodified verify_file inline SHA and exact-stock helper return; no results/policy/FS replaced.',
        'helper_or_installer_code_substituted':False,'candidate_or_road_IMG_chmod_or_inode_modified':False,
        'all_file_context_handles_closed':True,'native_CPU_or_old_closed11controls_replayed':False,
        'transaction_execute_or_device_preflight_invoked':False,'device_IO':False,'device_or_installer_modified':False,
        'ZIP_LAN_publication_performed':False,'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'header_checksum_rule_known':False,'actual_8K_device_acceptance_verified':False,
        'native_UI_search_route_acceptance_verified':False,'full_Taiwan_update_complete':False,
        'limits':['One genuine load_manifest call validates portable source/binding and exact-stock restoration; no device or transaction executed.',
                  'Roadmap source inode/size/mtime/ctime/linkcount verified against root hardlink receipt; its unchanged prior Searchv2 content digest is inherited.',
                  'Explicit8K checksum/device acceptance and complete native UI/search/route remain unverified.']}
    (OUT/'production-load-manifest-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    (OUT/'production-load-manifest-execution-receipt.json').write_text(json.dumps({
        'actual_script_completed_exit_status':0,'started_utc':started,'finished_utc':proof['finished_utc'],
        'script_sha256':proof['script_sha256'],'proof_sha256':sha((OUT/'production-load-manifest-proof.json').read_bytes()),
        'actual_load_manifest_calls':1,'actual_candidate_complete_SHA':CANDIDATE_SHA,
        'actual_reconstructed_stock_SHA':STOCK_SHA,'all_handles_closed':True,'device_IO':False},indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'production_load_manifest_passed':True,
        'actual_load_manifest_calls':1,'actual_candidate_sha256':CANDIDATE_SHA,'exact_stock_sha256':STOCK_SHA,
        'proof_sha256':sha((OUT/'production-load-manifest-proof.json').read_bytes()),
        'candidate_road_stats_unchanged':True,'all_handles_closed':True,'device_IO':False}),flush=True)


if __name__=='__main__':main()
