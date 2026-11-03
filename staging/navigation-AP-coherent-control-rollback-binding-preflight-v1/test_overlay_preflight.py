#!/usr/bin/env python3
"""Small pure-host preflight; never opens/stats any real IMG."""
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ADAPTER=HERE/'eightk_inverse_header_overlay.py'
spec=importlib.util.spec_from_file_location('ap_inverse_overlay_preflight',ADAPTER)
a=importlib.util.module_from_spec(spec);sys.modules[spec.name]=a;spec.loader.exec_module(a)
SHA=lambda b:hashlib.sha256(b).hexdigest()
CASES=[]


def savecase(name,result):CASES.append({'case':name,**result})


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=a.prepare_fixed_inputs()

    def fixture(self,body=b''):
        body=body or bytes((i*13+7)%256 for i in range(4096-512))
        self.assertLessEqual(512+len(body),8192)
        raw=self.inputs.spec.corrected_header+body
        spec=replace(self.inputs.spec,size=len(raw),corrected_full_sha=SHA(raw),
                     inverse_full_sha=SHA(self.inputs.spec.original_header+body))
        return raw,spec

    def test01_inverse_read_identity_and_unchanged_body(self):
        raw,spec=self.fixture()
        with tempfile.TemporaryDirectory(prefix='ap-inverse-synthetic-') as d:
            p=Path(d)/'fixture.bin';p.write_bytes(raw)
            with p.open('rb') as f:
                before=a._identity(f);view=a._verify_inverse_overlay(f,spec)
                self.assertEqual(self.inputs.helper.identity(view),self.inputs.helper.identity(f))
                self.assertEqual(view.mode,'rb');self.assertFalse(hasattr(view,'write'));self.assertFalse(hasattr(view,'close'))
                expected=spec.original_header+raw[512:]
                for start,length in ((0,512),(400,200),(512,512),(3700,396)):
                    self.assertEqual(self.inputs.helper._read(view,start,length),expected[start:start+length])
                view.seek(0,2);self.assertEqual(view.tell(),len(raw));view.seek(0)
                self.assertEqual(view.read(len(raw)),expected)
                with self.assertRaises(ValueError):view.read(-1)
                with self.assertRaises(ValueError):view.seek(len(raw)+1)
                self.assertEqual(a._identity(f),before);self.assertFalse(f.closed)
                savecase('synthetic_actual_fd_inverse_reads_via_unchanged_helper',
                         {'passed':True,'receipt':dict(view.receipt),'fixture_bytes':len(raw),
                          'old_helper_functions_executed':['identity','_read'],
                          'full_parse_or_stock_restore_executed':False,'source_handle_closed_by_caller':True})
            self.assertEqual(p.read_bytes(),raw)

    def rejection(self,name,raw,spec,mode='rb'):
        with tempfile.TemporaryDirectory(prefix='ap-inverse-synthetic-') as d:
            p=Path(d)/'fixture.bin';p.write_bytes(raw)
            with p.open(mode) as f:
                with self.assertRaises(ValueError) as caught:a._verify_inverse_overlay(f,spec)
                self.assertFalse(f.closed)
            self.assertEqual(p.read_bytes(),raw)
            savecase(name,{'passed':True,'actual_error':str(caught.exception),'fixture_bytes':len(raw),
                           'returned_overlay':False,'physical_source_write_bytes':0,'source_handle_closed_by_caller':True})

    def test02_wrong_actual_corrected_header(self):
        raw,spec=self.fixture();bad=bytearray(raw);bad[452]=208
        self.rejection('wrong_actual_corrected_header',bytes(bad),spec)

    def test03_wrong_corrected_full_digest(self):
        raw,spec=self.fixture();self.rejection('wrong_corrected_fullSHA',raw,replace(spec,corrected_full_sha='0'*64))

    def test04_wrong_inverse_full_digest(self):
        raw,spec=self.fixture();self.rejection('wrong_inverse_fullSHA',raw,replace(spec,inverse_full_sha='0'*64))

    def test05_readwrite_source_refused(self):
        raw,spec=self.fixture();self.rejection('readwrite_descriptor_refused',raw,spec,'r+b')

    def test06_source_mutation_after_verification(self):
        raw,spec=self.fixture()
        with tempfile.TemporaryDirectory(prefix='ap-inverse-synthetic-') as d:
            p=Path(d)/'fixture.bin';p.write_bytes(raw)
            with p.open('rb') as f:
                view=a._verify_inverse_overlay(f,spec);s=p.stat();os.utime(p,ns=(s.st_atime_ns,s.st_mtime_ns+1000000))
                with self.assertRaises(ValueError) as caught:view.read(512)
                self.assertFalse(f.closed)
            savecase('post_verification_source_stat_mutation',{'passed':True,'actual_error':str(caught.exception),
                     'fixture_bytes':len(raw),'source_handle_closed_by_caller':True,'no_physical_body_transform':True})

    def test07_declared_old_guard_failures_remain(self):
        h=self.inputs.helper;stock=self.inputs.stock
        old=h._expected_header(bytes.fromhex(stock.data['original_prefix_hex'])[:4096],8192)
        fake=self.inputs.spec.corrected_header+old[512:]+bytes(4096)
        self.assertEqual(len(fake),8192)
        # Deliberately synthetic buffer with production declared length: prove only this header guard.
        with self.assertRaisesRegex(ValueError,'Header differs') as caught:
            h.parse_layout(io.BytesIO(fake),a.V3_BYTES,8192,old)
        savecase('unchanged_old_helper_rejects_direct_corrected_header',
                 {'passed':True,'actual_error':str(caught.exception),'fixture_bytes':len(fake),
                  'declared_size_is_synthetic_guard_input':True,'full_candidate_parse':False})
        with self.assertRaisesRegex(ValueError,'Invalid aligned AP byte length') as caught:
            h.parse_layout(io.BytesIO(bytes(4096)),a.EXPANDED4_BYTES,4096)
        savecase('unchanged_old_helper_rejects_expanded4K_declared_size',
                 {'passed':True,'actual_error':str(caught.exception),'fixture_bytes':4096,'actual_IMG_read':False})
        with self.assertRaisesRegex(ValueError,'not supported') as caught:
            a.verified_eightk_overlay(None,self.inputs,'expanded_fourK_geometry')
        savecase('adapter_expanded4K_refused_before_stream_access',{'passed':True,'actual_error':str(caught.exception),
                                                                 'candidate_stream_accessed':False})

    def test08_fixed_recipe_binding_and_inverse_header(self):
        i=self.inputs;h=i.helper
        self.assertEqual(i.old_binding,h.prepare_restore_binding(i.stock,i.old_binding['candidate_layout']))
        self.assertEqual(i.stock.data['original_bytes'],96739328)
        self.assertEqual(i.stock.data['original_sha256'],a.STOCK_SHA)
        old=h._expected_header(bytes.fromhex(i.stock.data['original_prefix_hex'])[:4096],8192)
        self.assertEqual(old[:512],i.spec.original_header)
        self.assertEqual([k for k,(x,y) in enumerate(zip(i.spec.original_header,i.spec.corrected_header)) if x!=y],[452])
        savecase('fixed_real_small_recipe_binding_static_preflight',
                 {'passed':True,'stock_bytes':96739328,'stock_sha256':a.STOCK_SHA,
                  'old_helper_prepare_binding_executed':True,'candidate_read':False,
                  'decompressed_recipe_bytes':h.RECIPE_PLAIN_BYTES})


def main():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    inputs=getattr(Tests,'inputs',None)
    proof={'schema':'coherent-control-rollback-synthetic-preflight/v1','all_assigned_checks_passed':result.wasSuccessful(),
           'unittest_methods':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),
           'cases':CASES,'real_IMG_open_or_stat':False,'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,
           'production_candidate_verification_invoked':False,'actual_stock_reconstruction_executed':False,
           'fixture_max_bytes':max((r.get('fixture_bytes',0) for r in CASES),default=0),
           'adapter_sha256':SHA(ADAPTER.read_bytes()),'test_sha256':SHA(Path(__file__).read_bytes()),
           'installable':False,'checksum_UI_renderer_rootcause_verified':False}
    if inputs is not None:
        proof.update(input_receipts=list(inputs.receipts),input_raw_bytes=sum(r['bytes'] for r in inputs.receipts),
                     input_decompressed_bytes=inputs.helper.RECIPE_PLAIN_BYTES,design=inputs.design)
    (HERE/'synthetic-preflight-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':sys.exit(main())
