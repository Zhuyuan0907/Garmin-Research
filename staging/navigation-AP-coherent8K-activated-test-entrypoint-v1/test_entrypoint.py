#!/usr/bin/env python3
"""NEW bounded catalog/refusal controls; no recipe decoding or real IMG."""
import ast
import copy
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PRE=ROOT/'staging/navigation-AP-coherent8K-installer-integration-preparation-v1'
SHA=lambda b:hashlib.sha256(b).hexdigest()
CASES=[]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m
support=load('device_support','device_support.py')
old=load('native_8k_stock_restore','native_8k_stock_restore.py')
overlay=load('coherent_header_overlay','coherent_header_overlay.py')
adapter=load('native_coherent8k_rollback','native_coherent8k_rollback.py')
inv=load('coherent_bundle_inventory','coherent_bundle_inventory.py')
installer=load('activated_test_installer','install_native_house_supplement.py')


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads((HERE/'manifest.json').read_bytes())
        cls.sb=json.loads((HERE/'entrypoint-source-binding.json').read_bytes())

    def memory_fixture(self):
        bodies={'helper.py':b'H'*512,'control.json':b'C'*256,'recipe.gz':b'NOT-DECODED'*32,
                'virtual.json':b'V'*256,'road.img.disabled':b'R'*768,'candidate.img.disabled':b'N'*1024}
        roles=('portable_helper','coherent_binding','stock_recipe','virtual_old_v3_binding','road','candidate')
        catalog={name:{'bytes':len(raw),'sha256':SHA(raw),'role':role} for (name,raw),role in zip(bodies.items(),roles)}
        self.assertLessEqual(sum(map(len,bodies.values())),8192)
        checked=[]
        def verify(path,size,digest,label):
            name=str(path)
            if name not in bodies:raise ValueError('Synthetic missing file')
            raw=bodies[name]
            if len(raw)!=size or SHA(raw)!=digest:raise ValueError('Synthetic wrong hash/size')
            checked.append(name)
        return bodies,catalog,checked,verify

    def guard_context(self):
        stack=contextlib.ExitStack()
        spies=[stack.enter_context(patch.object(installer,name,side_effect=RuntimeError('Forbidden device operation')))
               for name in ('main','execute','transaction','device_preflight','disk_records','select_disk','run_command')]
        decoder=stack.enter_context(patch.object(old,'load_stock_recipe',side_effect=RuntimeError('Recipe decoding forbidden')))
        opener=support.open_regular
        def small_only(path,*args,**kwargs):
            if str(path).endswith(('.img','.img.disabled')):raise RuntimeError('Real IMG lookup forbidden')
            return opener(path,*args,**kwargs)
        stack.enter_context(patch.object(support,'open_regular',small_only))
        return stack,spies,decoder

    def test01_exact_new_catalog_and_source_binding_metadata(self):
        c=inv.validate_catalog(self.manifest['bundle_input_inventory'],installer.EXPECTED_INPUT_INVENTORY)
        self.assertEqual(len(c),12);self.assertNotIn('integration_preparation_only',self.manifest)
        self.assertEqual(self.manifest['schema'],'garmin-AP-coherent8K-experimental-map-test/v1')
        self.assertEqual(self.sb['entrypoint']['sha256'],SHA((HERE/'install_native_house_supplement.py').read_bytes()))
        self.assertEqual(self.sb['manifest']['sha256'],SHA((HERE/'manifest.json').read_bytes()))
        self.assertEqual(self.sb['bundle_input_inventory'],c)
        self.assertEqual(c['candidate/coherent8K-end-mirror.img.disabled']['sha256'],adapter.COHERENT_SHA)
        self.assertEqual(c['virtual-old-v3-stock-restore-binding.json']['sha256'],adapter.OLD_BINDING_SHA)
        CASES.append({'name':'new_schema_full_catalog_detached_source_binding','passed':True,'input_count':12,
                      'actual_payload_read':False,'complete_real_packet_loaded':False})

    def test02_synthetic_complete_hash_inventory(self):
        bodies,catalog,checked,verify=self.memory_fixture()
        got=inv.verify_catalog(None,catalog,catalog,verify,lambda _,n:PurePosixPath(n))
        self.assertEqual(got,checked);self.assertEqual(got,list(bodies));self.assertEqual(got[-1],'candidate.img.disabled')
        CASES.append({'name':'synthetic_catalog_all_file_hashes_ordered','passed':True,'aggregate_fixture_bytes':sum(map(len,bodies.values())),
                      'production_expected_catalog_substituted':False,'full_production_load_manifest':False})

    def test03_wrong_hash_and_missing_synthetic_inputs_refused(self):
        for kind in ('hash','missing'):
            bodies,catalog,checked,verify=self.memory_fixture()
            if kind=='hash':bodies['recipe.gz']=b'X'*len(bodies['recipe.gz'])
            else:del bodies['virtual.json']
            with self.assertRaises(ValueError) as caught:inv.verify_catalog(None,catalog,catalog,verify,lambda _,n:PurePosixPath(n))
            self.assertNotIn('candidate.img.disabled',checked)
            CASES.append({'name':'synthetic_'+kind+'_inventory_refusal','passed':True,'actual_error':str(caught.exception),
                          'IMG_or_recipe_decoder_invoked':False})

    def test04_symlink_path_fixture_refused_before_verifier(self):
        bodies,catalog,checked,verify=self.memory_fixture()
        def safe(_,name):
            if name=='control.json':raise ValueError('Synthetic symlink path refusal')
            return PurePosixPath(name)
        with self.assertRaisesRegex(ValueError,'symlink'):inv.verify_catalog(None,catalog,catalog,verify,safe)
        self.assertEqual(checked,['helper.py'])
        CASES.append({'name':'synthetic_path_guard_delegation','passed':True,'actual_symlink_created':False,
                      'inherited_safe_path_actual_FS_suite_replayed':False})

    def test05_real_partial_packet_refuses_before_recipe_decode_IMG_device(self):
        stack,spies,decoder=self.guard_context()
        with stack,self.assertRaises(support.Refusal) as caught:installer.load_manifest(HERE)
        self.assertTrue(all(x.call_count==0 for x in spies));self.assertEqual(decoder.call_count,0)
        CASES.append({'name':'actual_missing_packet_source_inventory_refusal','passed':True,'actual_error':str(caught.exception),
                      'recipe_decode_calls':0,'device_calls':0,'real_IMG_open_stat':False})

    def test06_old_preparation_manifest_refused(self):
        original=installer.safe_path
        def old_manifest(bundle,name):
            return PRE/'manifest.json' if name=='manifest.json' else original(bundle,name)
        stack,spies,decoder=self.guard_context()
        with stack,patch.object(installer,'safe_path',old_manifest),self.assertRaises(support.Refusal) as caught:
            installer.load_manifest(HERE)
        self.assertTrue(all(x.call_count==0 for x in spies));self.assertEqual(decoder.call_count,0)
        CASES.append({'name':'old_preparation_manifest_wholepin_refused','passed':True,'actual_error':str(caught.exception),
                      'closed_manifest_modified':False,'real_IMG_or_recipe_read':False})

    def test07_source_manifest_hash_roles_refused(self):
        for kind in ('manifest','entrypoint'):
            bad=copy.deepcopy(self.sb);bad[kind]['sha256']='0'*64
            self.assertLessEqual(len(json.dumps(bad).encode()),8192)
            reader=installer.read_json
            def injected(path,cap):return bad if Path(path).name=='entrypoint-source-binding.json' else reader(path,cap)
            stack,spies,decoder=self.guard_context()
            with stack,patch.object(installer,'read_json',injected),self.assertRaises(support.Refusal) as caught:
                installer.load_manifest(HERE)
            self.assertTrue(all(x.call_count==0 for x in spies));self.assertEqual(decoder.call_count,0)
            CASES.append({'name':'synthetic_detached_'+kind+'_hash_refusal','passed':True,'actual_error':str(caught.exception),
                          'fixture_json_injected_only_in_test':True,'synthetic_metadata_bytes':len(json.dumps(bad).encode()),
                          'source_or_manifest_file_modified':False})

    def test08_wrong_candidate_profile_and_case_alias_refused(self):
        actual=copy.deepcopy(installer.EXPECTED_INPUT_INVENTORY)
        actual['candidate/coherent8K-end-mirror.img.disabled']['sha256']='8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6'
        with self.assertRaises(ValueError):inv.validate_catalog(actual,installer.EXPECTED_INPUT_INVENTORY)
        _,catalog,_,_=self.memory_fixture();catalog['HELPER.py']=dict(catalog['helper.py'])
        with self.assertRaisesRegex(ValueError,'Case-aliased'):inv.validate_catalog(catalog,catalog)
        CASES.append({'name':'expanded4K_identity_and_case_alias_refused','passed':True,'actual_other_control_IMG_opened':False})

    def test09_original_main_transaction_guards_AST_and_binding_lookup(self):
        oldsrc=(PRE/'install_native_house_supplement.py').read_bytes();newsrc=(HERE/'install_native_house_supplement.py').read_bytes()
        oldnodes={n.name:n for n in ast.parse(oldsrc).body if isinstance(n,ast.FunctionDef)}
        newnodes={n.name:n for n in ast.parse(newsrc).body if isinstance(n,ast.FunctionDef)}
        for name in ('main','execute','device_preflight','transaction','image_state','validate_recipe','image_blocks'):
            self.assertEqual(ast.dump(oldnodes[name],include_attributes=False),ast.dump(newnodes[name],include_attributes=False))
        adaptertree=ast.parse((HERE/'native_coherent8k_rollback.py').read_bytes())
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='prepare_fixed_inputs'
                             for n in ast.walk(adaptertree)))
        original=json.loads((PRE/'manifest.json').read_bytes())
        for key in ('device','preserved_stock_files','required_files'):self.assertEqual(self.manifest[key],original[key])
        self.assertEqual(self.manifest['target']['accepted_predecessors'],original['target']['accepted_predecessors'])
        CASES.append({'name':'unchanged_CLI_transaction_model_USB_protection_and_portable_restore_lookup','passed':True,
                      'original_operation_lock_optional_workspace_path_preserved':True,
                      'guest_or_device_preflight_or_atomictransaction_executed':False})


def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    proof={'schema':'coherent8K-activated-entrypoint-host-controls/v1','all_assigned_checks_passed':result.wasSuccessful(),
           'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'cases':CASES,
           'test_sha256':SHA(Path(__file__).read_bytes()),'entrypoint_sha256':SHA((HERE/'install_native_house_supplement.py').read_bytes()),
           'manifest_sha256':SHA((HERE/'manifest.json').read_bytes()),'inventory_helper_sha256':SHA((HERE/'coherent_bundle_inventory.py').read_bytes()),
           'synthetic_max_aggregate_data_bytes':max(r.get('aggregate_fixture_bytes',0) for r in CASES),
           'synthetic_max_injected_metadata_bytes':max(r.get('synthetic_metadata_bytes',0) for r in CASES),
           'recipe_read_bytes':0,'recipe_decoded_bytes':0,'real_IMG_open_stat_read_link_chmod_write':False,
           'full_actual_packet_load_manifest_passed':False,'actual_missing_packet_guard_executed':True,
           'device_preflight_transaction_main_execute_discovery_or_services':False,
           'guest_native_firmware_audio_or_old_suites':False,'installable':False}
    (HERE/'host-control-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':sys.exit(main())
