#!/usr/bin/env python3
"""Finite host transport/guard tests; no real target FS or device preflight."""
import ast
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
OLD=ROOT/'staging/navigation-country-address-package-v3'
SHA=lambda b:hashlib.sha256(b).hexdigest()
CASES=[]
def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m
support=load('device_support','device_support.py')
old=load('native_8k_stock_restore','native_8k_stock_restore.py')
overlay=load('coherent_header_overlay','coherent_header_overlay.py')
adapter=load('native_coherent8k_rollback','native_coherent8k_rollback.py')
installer=load('coherent_test_installer','install_native_house_supplement.py')


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads((HERE/'manifest.json').read_bytes())
        cls.stock=old.load_stock_recipe(OLD/'restore-layout.json.gz')
        cls.binding=old.load_restore_binding(OLD/'actual-stock-restore-binding.json',installer.BINDING_SHA)
        cls.control=json.loads((HERE/'coherent-control-restore-binding.json').read_bytes())
        cls.recipe={'stock':cls.stock,'binding':cls.binding,'control':cls.control}

    def refuse(self,label,recipe,target=None):
        def no_open(_):raise RuntimeError('Refusal guard unexpectedly opened source')
        with patch.object(installer,'open_regular',no_open),self.assertRaises(support.Refusal) as caught:
            installer.validate_recipe(recipe,Path('/never-opened-fixture-source'),target or self.manifest['target'])
        CASES.append({'name':label,'passed':True,'actual_refusal':str(caught.exception),'source_opened':False})

    def test01_recipe_objects_from_same_bundle_without_workspace_loader(self):
        def forbidden():raise RuntimeError('Portable entrypoint called original workspace loader')
        with patch.object(overlay,'prepare_fixed_inputs',forbidden):inputs=adapter.prepare_objects(self.recipe)
        self.assertEqual(inputs.spec.corrected_full_sha,installer.CANDIDATE_SHA)
        self.assertEqual(inputs.spec.inverse_full_sha,adapter.VIRTUAL_V3_SHA)
        self.assertEqual(inputs.old_binding['candidate_layout']['candidate_sha256'],adapter.VIRTUAL_V3_SHA)
        self.assertEqual(inputs.stock.data['original_sha256'],adapter.STOCK_SHA)
        self.assertEqual([i for i,(a,b) in enumerate(zip(inputs.spec.corrected_header,inputs.spec.original_header)) if a!=b],[452])
        CASES.append({'name':'portable_objects_no_ROOT_lookup','passed':True,'original_workspace_loader_called':False,
                      'actual_candidate_or_stock_stream_invoked':False})

    def test02_virtual_old_binding_never_relabelled_coherent(self):
        bad=copy.deepcopy(self.binding);bad['candidate_layout']['candidate_sha256']=installer.CANDIDATE_SHA
        self.refuse('old_binding_relabelled_as_actual_coherent',{'stock':self.stock,'binding':bad,'control':self.control})

    def test03_corrupt_control_header_or_binding_refused(self):
        bad=copy.deepcopy(self.control);bad['inverse_header']['changed_offsets']=[451]
        self.refuse('changed_inverse_header_contract',{'stock':self.stock,'binding':self.binding,'control':bad})
        bad=copy.deepcopy(self.control);bad['candidate']['sha256']=adapter.VIRTUAL_V3_SHA
        self.refuse('coherent_identity_substituted_with_old_v3',{'stock':self.stock,'binding':self.binding,'control':bad})

    def test04_mismatched_target_and_fixture_recipe_refused(self):
        bad=copy.deepcopy(self.manifest['target']);bad['candidate_sha256']=adapter.VIRTUAL_V3_SHA
        self.refuse('target_coherent_hash_mismatch',self.recipe,bad)
        fixture=old.StockRecipe(self.stock.data,self.stock.compressed_sha256,self.stock.compressed_bytes,
                                self.stock.uncompressed_sha256,True)
        self.refuse('production_fixture_recipe_refused',{'stock':fixture,'binding':self.binding,'control':self.control})

    def test05_preparation_load_manifest_refuses_before_IMG_or_device(self):
        with contextlib.ExitStack() as stack:
            spies=[stack.enter_context(patch.object(installer,name,side_effect=RuntimeError('Forbidden device operation')))
                   for name in ('device_preflight','transaction','execute','disk_records','select_disk','run_command')]
            with self.assertRaisesRegex(support.Refusal,'Preparation-only') as caught:installer.load_manifest(HERE)
            self.assertTrue(all(spy.call_count==0 for spy in spies))
        self.assertEqual(list((HERE/'candidate').iterdir()),[])
        CASES.append({'name':'pinned_preparation_manifest_gate','passed':True,'actual_refusal':str(caught.exception),
                      'only_small_manifest_read':True,'device_preflight_or_transaction_or_execute_invoked':False,
                      'actual_candidate_opened_or_statted':False})

    def test06_synthetic_install_and_rollback_transport(self):
        source=bytes.fromhex(self.control['inverse_header']['corrected_header_hex'])+bytes((i*5+9)%256 for i in range(3584))
        stock=b'SYNTHETIC-ROLLBACK-PROTOCOL\0'+bytes(2048-28)
        self.assertLessEqual(len(source),16384);self.assertLessEqual(len(stock),16384)
        opened=[];calls=[]
        def open_memory(_):
            f=io.BytesIO(source);opened.append(f);return f
        def test_only_bridge(stream,recipe):
            self.assertIs(recipe,self.recipe);self.assertEqual(stream.read(),source)
            calls.append('test_only_synthetic_stock_generator')
            yield stock[:1024];yield stock[1024:]
        with patch.object(installer,'open_regular',open_memory):
            installed=b''.join(installer.image_blocks(Path('/memory-source'),self.recipe,'install'))
            with patch.object(adapter,'restored_stock_blocks',test_only_bridge):
                restored=b''.join(installer.image_blocks(Path('/memory-source'),self.recipe,'rollback'))
        self.assertEqual(installed,source);self.assertEqual(restored,stock);self.assertEqual(len(calls),1)
        self.assertTrue(all(f.closed for f in opened))
        CASES.append({'name':'new_image_blocks_synthetic_transport','passed':True,'source_bytes':len(source),
                      'rollback_bytes':len(stock),'install_body_all_bytes_identical':True,'rollback_bridge_test_only':True,
                      'actual_old_stock_generator_executed':False,'atomic_transaction_invoked':False,
                      'real_target_filesystem_or_device_invoked':False,'all_memory_streams_closed':True})

    def test07_rollback_stream_failure_never_reported_as_complete(self):
        memory=io.BytesIO(b'only-synthetic-input');returned=[]
        def failing(stream,recipe):
            yield b'prefix';raise ValueError('synthetic rollback incomplete EOF')
        with patch.object(installer,'open_regular',lambda _:memory),patch.object(adapter,'restored_stock_blocks',failing):
            with self.assertRaisesRegex(ValueError,'incomplete EOF'):
                for b in installer.image_blocks(Path('/memory-source'),self.recipe,'rollback'):returned.append(b)
        self.assertEqual(returned,[b'prefix']);self.assertTrue(memory.closed)
        with self.assertRaises(support.Refusal):list(installer.image_blocks(Path('/never-opened'),'invalid-recipe','unknown'))
        CASES.append({'name':'rollback_EOF_failure_propagates','passed':True,'prefix_bytes':6,
                      'completed_rollback':False,'atomic_commit_or_target_write':False})

    def test08_receipt_sink_supports_append_and_extend(self):
        rows=[{'purpose':'header','bytes':512},{'purpose':'MDR','bytes':772},{'purpose':'DIR','bytes':120}]
        sink=adapter.ReceiptSink();sink.append(rows[0]);sink.extend(rows[1:]);s=sink.summary()
        self.assertEqual(s['append_count'],3);self.assertEqual(s['logical_bytes'],1404)
        raw=b''.join((json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode() for r in rows)
        self.assertEqual(s['canonical_receipt_stream_sha256'],SHA(raw));self.assertFalse(s['retained_per_block_receipt_list'])
        with self.assertRaises(ValueError):sink.append({'purpose':'invalid','bytes':-1})
        CASES.append({'name':'new_sink_append_extend_contract','passed':True,'summary':s,
                      'old_first_missing_extend_failure_not_replayed':True})

    def test09_unchanged_AST_and_exact_unit_protected_fields(self):
        oldsrc=(OLD/'install_native_house_supplement.py').read_bytes()
        self.assertEqual(SHA(oldsrc),'cefe766e9b1c0380a72e588e53da1fbc5fc1037a3510cbb507cb2a1526403374')
        new=(HERE/'install_native_house_supplement.py').read_bytes()
        oldnodes={n.name:n for n in ast.parse(oldsrc).body if isinstance(n,ast.FunctionDef)}
        newnodes={n.name:n for n in ast.parse(new).body if isinstance(n,ast.FunctionDef)}
        for name in ('image_state','device_preflight','transaction','execute','main'):
            self.assertEqual(ast.dump(oldnodes[name],include_attributes=False),ast.dump(newnodes[name],include_attributes=False))
        original=json.loads((OLD/'manifest.json').read_bytes())
        for key in ('device','preserved_stock_files','required_files'):self.assertEqual(original[key],self.manifest[key])
        self.assertEqual(original['target']['accepted_predecessors'],self.manifest['target']['accepted_predecessors'])
        self.assertEqual(self.manifest['required_files'][0]['sha256'],'664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117')
        self.assertEqual(SHA((HERE/'device_support.py').read_bytes()),'8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411')
        self.assertEqual(SHA((HERE/'native_8k_stock_restore.py').read_bytes()),'43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f')
        CASES.append({'name':'preserved_AST_unit_XML_protection_and_predecessors','passed':True,
                      'functions_AST_exact':['image_state','device_preflight','transaction','execute','main'],
                      'device_functions_actually_executed':False})


def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    proof={'schema':'coherent8K-installer-integration-host-controls/v1','all_assigned_checks_passed':result.wasSuccessful(),
           'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'cases':CASES,
           'test_source_sha256':SHA(Path(__file__).read_bytes()),
           'installer_sha256':SHA((HERE/'install_native_house_supplement.py').read_bytes()),
           'native_coherent_adapter_sha256':SHA((HERE/'native_coherent8k_rollback.py').read_bytes()),
           'test_stock_recipe_plain_bytes':1779988,'test_stock_recipe_raw_bytes':879499,
           'test_old_binding_raw_bytes':292144,'total_recipe_plain_bytes_preparation_and_tests':3559976,
           'max_synthetic_map_or_protocol_payload_bytes':4096,'synthetic_transport_bridge_only_in_test':True,
           'real_candidate_or_road_IMG_open_or_stat':False,'real_IMG_read_or_write_bytes':0,
           'production_load_manifest_completed':False,'preparation_manifest_refusal_executed':True,
           'device_discovery_or_preflight_or_transaction_or_execute_invoked':False,
           'device_FS_mount_sysfs_BlueZ_guest_firmware_audio_service':False,'atomictransaction_tests_replayed':False,
           'installer_release_or_package_or_installable':False}
    (HERE/'host-control-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':sys.exit(main())
