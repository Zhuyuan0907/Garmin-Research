#!/usr/bin/env python3
"""NEW finite portable8K adapter controls; no closed suite or actual IMG."""
import ast
import copy
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');PKG=Path(__file__).resolve().parents[1];OUT=PKG/'validation'
V2=ROOT/'staging/navigation-country-address-package-v2'
API_SOURCE=ROOT/'staging/navigation-native-8k-layout-restore-api-v1'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def need(ok,message):
    if not ok:raise AssertionError(message)


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def load_package(path,name):
    support=load(path/'device_support.py','device_support')
    api=load(path/'native_8k_stock_restore.py','native_8k_stock_restore')
    installer=load(path/'install_native_house_supplement.py',name)
    return support,api,installer


def main():
    need(not(OUT/'portable-v3-focused-proof.json').exists(),'Refuse overwrite NEW focused proof')
    started=datetime.now(timezone.utc).isoformat()
    original=(V2/'install_native_house_supplement.py').read_bytes()
    need(sha(original)=='663a40fb404e44598574035b0ea5d651342720864a41973459ef87f5affe5f5d','Pinned originalv2 source')
    current=(PKG/'install_native_house_supplement.py').read_bytes()
    oldnodes={x.name:x for x in ast.parse(original).body if isinstance(x,ast.FunctionDef)}
    newnodes={x.name:x for x in ast.parse(current).body if isinstance(x,ast.FunctionDef)}
    need(set(oldnodes)==set(newnodes),'No added production function or fixture entry')
    changed={'validate_recipe','load_manifest','image_blocks'}
    identical={name:ast.dump(node,include_attributes=False)==ast.dump(newnodes[name],include_attributes=False)
               for name,node in oldnodes.items() if name not in changed}
    need(all(identical.values()),'transaction/execute/image_state/device_preflight/main retain all exact ASTs')
    need(sha((PKG/'device_support.py').read_bytes())=='8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411',
         'Exact unchanged portable device_support source')
    need(sha((PKG/'native_8k_stock_restore.py').read_bytes())=='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f',
         'Exact unchanged sealed portable8K helper')
    m2=json.loads((V2/'manifest.json').read_bytes());m=json.loads((PKG/'manifest.json').read_bytes())
    need(all(m[k]==m2[k] for k in ('device','preserved_stock_files','required_files')),'Exact authorized unit/USB/protectedfiles/Searchv2 identities')
    need(m['target']['accepted_predecessors'][:-1]==m2['target']['accepted_predecessors']
         and m['target']['accepted_predecessors'][-1]=={'state':'previous_country_v2_candidate','bytes':128356352,
             'sha256':'925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'},'Exact newly accepted countryv2 predecessor')
    need(m['new_houses']==188870 and sum(m['new_houses_by_leaf_level'].values())==188870
         and m['updated_existing_streets']==18823+1284==20107 and 6366+1284==7650,'Exact cumulative arithmetic')
    support,api,installer=load_package(PKG,'new_portable_v3_adapter')
    need(installer.MANIFEST_BYTES==(PKG/'manifest.json').stat().st_size
         and installer.MANIFEST_SHA==sha((PKG/'manifest.json').read_bytes()),'Whole manifest hard pin')
    production=api.load_stock_recipe(PKG/'restore-layout.json.gz')
    binding=api.load_restore_binding(PKG/'actual-stock-restore-binding.json',installer.BINDING_SHA)
    need(api.prepare_restore_binding(production,binding['candidate_layout'])==binding,'Portable actual production8K binding connects exact stock recipe')
    guards=[]
    def refuse(name,call,exception=support.Refusal):
        try:call()
        except exception as e:guards.append({'name':name,'refused':True,'exception':type(e).__name__,'message':str(e)})
        else:raise AssertionError('Accepted new refusal control '+name)
    bad=copy.deepcopy(binding);bad['candidate_layout']['candidate_sha256']='0'*64
    refuse('binding_candidate_source_identity',lambda:installer.validate_recipe({'stock':production,'binding':bad},Path('/never-opened-fixture-source'),m['target']))
    bad=copy.deepcopy(binding);bad['MDR_candidate_offsets_by_original_range_index'][3]+=1
    refuse('corrupt_binding_original_range_offset',lambda:installer.validate_recipe({'stock':production,'binding':bad},Path('/never-opened-fixture-source'),m['target']))
    bad=copy.deepcopy(binding);bad['candidate_layout']['tables'][4]['stride']=127
    refuse('unsupported_inverse_lower_width',lambda:installer.validate_recipe({'stock':production,'binding':bad},Path('/never-opened-fixture-source'),m['target']))
    target=copy.deepcopy(m['target']);target['bytes']-=8192
    refuse('mismatched_target_geometry',lambda:installer.validate_recipe({'stock':production,'binding':binding},Path('/never-opened-fixture-source'),target))
    refuse('unexpected_restore_object_type',lambda:installer.validate_recipe(binding,Path('/never-opened-fixture-source'),m['target']))
    with tempfile.TemporaryDirectory(prefix='v3-adapter-focused-') as directory:
        tmp=Path(directory);clone=tmp/'portable';clone.mkdir()
        names=('manifest.json','install_native_house_supplement.py','device_support.py','native_8k_stock_restore.py',
               'restore-layout.json.gz','actual-stock-restore-binding.json')
        for name in names:shutil.copyfile(PKG/name,clone/name)
        cs,ca,ci=load_package(clone,'new_v3_portable_clone_guard')
        def clone_refuse(name,call):
            try:call()
            except cs.Refusal as e:guards.append({'name':name,'refused':True,'exception':type(e).__name__,'message':str(e)})
            else:raise AssertionError('Accepted portable clone '+name)
        # Guards are placed before absent IMG lookup: no real candidate needed.
        for name,file in [('corrupt_portable_binding','actual-stock-restore-binding.json'),
                          ('corrupt_compact_stock_recipe','restore-layout.json.gz'),
                          ('portable_helper_identity_mismatch','native_8k_stock_restore.py')]:
            path=clone/file;raw=path.read_bytes();bad=bytearray(raw);bad[-1]^=1;path.write_bytes(bad)
            clone_refuse(name,lambda:ci.load_manifest(clone));path.write_bytes(raw)
        path=clone/'manifest.json';raw=path.read_bytes();bad=json.loads(raw)
        bad['target']['accepted_predecessors'][-1]['sha256']='0'*64
        path.write_text(json.dumps(bad,ensure_ascii=False,indent=2)+'\n')
        clone_refuse('unknown_prior_manifest_hash_substitution',lambda:ci.load_manifest(clone));path.write_bytes(raw)
        root=tmp/'synthetic-device';(root/'.System').mkdir(parents=True)
        (root/installer.TARGET).write_bytes(b'unknown prior bytes')
        refuse('unrecognized_prior_actual_file_size',lambda:installer.image_state(root,m))
        # Reuse only the sealed fixture byte-generator function. Its historical
        # main/cases are never called; production APIs still reject fixture schema.
        sealraw=(API_SOURCE/'sealed-files.json').read_bytes();seal=json.loads(sealraw)
        need(sha(sealraw)=='7bef13e816951f51c32e75b2f9e00940b9104f971ba67a7f67d3684e5561af04','Pinned fixture source seal')
        row=next(x for x in seal['files'] if Path(x['path']).name=='test_mixed_geometry_restore.py')
        source=ROOT/row['path'];need(sha(source.read_bytes())==row['sha256'],'Fixture byte generator source pin')
        fixture_module=load(source,'sealed_byte_generator_only_for_v3_adapter')
        original_small,_,candidate_small,recipe_raw,d,_,_,_=fixture_module.fixtures()
        # fixture_module uses currently imported clone API; instantiate explicitly
        # through the package API for the adapter under test.
        stock=api.load_synthetic_fixture_recipe(recipe_raw);b=api.prepare_synthetic_fixture_binding(stock,d)
        source_path=tmp/'synthetic-mixed8K.img';source_path.write_bytes(candidate_small)
        refuse('production_image_blocks_rejects_fixture_recipe',lambda:list(installer.image_blocks(source_path,{'stock':stock,'binding':b},'rollback')),ValueError)
        restore_before=installer.restore
        installer.restore=types.SimpleNamespace(restored_stock_blocks=api.restored_synthetic_fixture_blocks)
        try:
            restored=b''.join(installer.image_blocks(source_path,{'stock':stock,'binding':b},'rollback'))
            copied=b''.join(installer.image_blocks(source_path,{'stock':stock,'binding':b},'install'))
        finally:installer.restore=restore_before
        need(restored==original_small and copied==candidate_small,'New image_blocks adapter both modes preserve exact synthetic bytes')
    need(not any((PKG/'candidate').iterdir()) and not any((PKG/'roadmap').iterdir()),'ActualIMG/road hardlinks remain absent')
    proof={'schema':'NEW-portable-v3-8K-binding-focused-controls/v1','started_utc':started,
           'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
           'script_sha256':sha(Path(__file__).read_bytes()),'installer_sha256':sha(current),
           'manifest_bytes':installer.MANIFEST_BYTES,'manifest_sha256':installer.MANIFEST_SHA,
           'unchanged_function_AST_identity':identical,'only_changed_production_functions':sorted(changed),
           'device_support_byte_exact':True,'portable_restore_API_byte_exact':True,
           'authorized_model_unit_USB_protection_Searchv2_manifest_exact':True,'exact_countryv2_predecessor_added':True,
           'cumulative_house_count':188870,'cumulative_street_union':20107,
           'compact_recipe_actual_binding_production_identity_verified_without_IMG':True,
           'guards':guards,'guard_count':len(guards),
           'synthetic_changed_image_blocks_adapter':{'source8K_bytes':len(candidate_small),'stock4K_bytes':len(original_small),
               'stock4K_sha256':sha(restored),'exact_all_bytes_equal':True,'install_source_bytes_equal':True,
               'bridge_exists_only_in_test_code':True,'production_fixture_recipe_refused':True,
               'production_CLI_fixture_mode_added':False,'old_fixture_main_or_cases_executed':False},
           'actual_production_load_manifest_waiting_for_root_hardlinks':True,
           'actual_candidate_or_road_IMG_opened_linked_chmodded':False,
           'transaction_execute_device_preflight_invoked':False,'device_IO':False,'old_closed_suites_replayed':False,
           'header_checksum_or_actual8K_device_acceptance_verified':False,
           'limits':['Small changed-adapter/source-binding controls only; actual bundled load_manifest must run after root hardlinks and review-handle closure.',
                     'Transaction/execute/device_preflight/image_state/main ASTs inherit sealedv2; old closed control suites were not replayed.']}
    (OUT/'portable-v3-focused-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'guard_count':len(guards),'identical_function_count':len(identical),
                     'installer_sha256':sha(current),'proof_sha256':sha((OUT/'portable-v3-focused-proof.json').read_bytes()),
                     'actual_IMG_or_device_IO':False}))


if __name__=='__main__':main()
