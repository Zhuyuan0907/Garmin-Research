#!/usr/bin/env python3
"""Finite ordinary-host tests. All IMG bodies are synthetic and <=4096 bytes."""
from __future__ import annotations
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/materialize_ap_header_control_v1.py'
spec=importlib.util.spec_from_file_location('ap_header_control_materializer',SOURCE)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
SHA=lambda b:hashlib.sha256(b).hexdigest()
RECEIPTS=[]
FIXTURE_BYTES=4096


@contextlib.contextmanager
def fixture(base):
    with tempfile.TemporaryDirectory(prefix='ap-header-synthetic-') as temp:
        stage=Path(temp)/'staging';stage.mkdir()
        source=stage/'synthetic-source.img';body=bytes((i*17+31)%256 for i in range(FIXTURE_BYTES-512))
        raw=base.original_header+body;source.write_bytes(raw);source.chmod(0o444)
        c=dataclasses.replace(base,source=source,size=len(raw),source_stat=m._pin5(source.stat()),
                              source_sha256=SHA(raw),virtual_sha256=SHA(base.corrected_header+body))
        yield c,stage,stage/'synthetic-output.img.disabled',raw


def record(label,state):
    RECEIPTS.append({'case':label,'receipt':state})


def optimized_probe():
    old=bytearray(512);old[452]=208;new=bytearray(old);new[452]=224
    base=m._Control('eightK_end_mirror',Path('/unopened'),512,'0'*64,'0'*64,(0,0,512,0,0),
                    bytes(old),bytes(new),SHA(new),(452,))
    with fixture(base) as (c,stage,out,raw):
        c=dataclasses.replace(c,source_sha256='0'*64)
        try:m._materialize_control(c,out,staging_root=stage)
        except m.ControlError as exc:
            if out.exists() or exc.receipt.get('published') or not exc.receipt.get('all_handles_closed'):
                raise RuntimeError('Optimized rejection published output or leaked handle')
            if list(stage.glob('*.partial')):raise RuntimeError('Optimized rejection leaked partial')
            print(json.dumps({'optimized_python':not __debug__,'rejected':True,'receipt':exc.receipt}))
            return 0
        raise RuntimeError('Explicit SHA guard disappeared under -O')


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls,cls.catalog_receipts=m.load_catalog()

    def rejected(self,label,c,stage,out,*,published=False):
        with self.assertRaises(m.ControlError) as caught:m._materialize_control(c,out,staging_root=stage)
        r=caught.exception.receipt;record(label,r)
        self.assertEqual(r['published'],published);self.assertTrue(r['all_handles_closed'])
        if not published and not out.is_symlink():self.assertFalse(out.exists())
        return r

    def test_01_both_control_hashes_and_body(self):
        for name,base in self.controls.items():
            with self.subTest(control=name),fixture(base) as (c,stage,out,raw):
                r=m._materialize_control(c,out,staging_root=stage);record('success_'+name,r)
                saved=out.read_bytes()
                self.assertEqual(saved,c.corrected_header+raw[512:]);self.assertEqual(saved[512:],raw[512:])
                self.assertEqual(r['source_actual_full_sha256'],SHA(raw))
                self.assertEqual(r['generated_computed_full_sha256'],c.virtual_sha256)
                self.assertEqual(r['actual_saved_output_sha256'],SHA(saved));self.assertEqual(SHA(saved),c.virtual_sha256)
                self.assertEqual(r['saved_output_bytes_read'],c.size);self.assertTrue(r['published'])
                self.assertTrue(r['full_hashes_and_length_verified']);self.assertTrue(r['all_handles_closed'])
                self.assertTrue(r['source_unchanged']);self.assertEqual(m._pin5(c.source.stat()),c.source_stat)
                self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o444);self.assertEqual(list(stage.glob('*.partial')),[])

    def test_02_wrong_header_before_partial(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            bad=bytearray(raw);bad[0]^=1;c.source.chmod(0o600);c.source.write_bytes(bad);c.source.chmod(0o444)
            c=dataclasses.replace(c,source_stat=m._pin5(c.source.stat()),source_sha256=SHA(bad))
            r=self.rejected('wrong_source_header',c,stage,out)
            self.assertFalse(r['partial_created']);self.assertEqual(r['source_bytes_read'],512)

    def test_03_wrong_full_source_sha(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            r=self.rejected('wrong_original_full_sha',dataclasses.replace(c,source_sha256='0'*64),stage,out)
            self.assertEqual(r['partial_cleanup'],'owned_partial_removed');self.assertTrue(r['source_unchanged'])

    def test_04_wrong_virtual_sha(self):
        with fixture(self.controls['expanded_fourK_geometry']) as (c,stage,out,raw):
            r=self.rejected('wrong_expected_virtual_sha',dataclasses.replace(c,virtual_sha256='0'*64),stage,out)
            self.assertEqual(r['partial_cleanup'],'owned_partial_removed')

    def test_05_existing_output_preserved(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            sentinel=b'existing';out.write_bytes(sentinel)
            with self.assertRaises(m.ControlError) as caught:m._materialize_control(c,out,staging_root=stage)
            r=caught.exception.receipt;record('existing_output_no_overwrite',r)
            self.assertEqual(out.read_bytes(),sentinel);self.assertEqual(r['source_bytes_read'],0)
            self.assertFalse(r['partial_created']);self.assertTrue(r['all_handles_closed'])

    def test_06_symlink_output_and_parent(self):
        for kind in ('final','parent'):
            with self.subTest(kind=kind),fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
                if kind=='final':out.symlink_to(stage/'absent')
                else:
                    (stage/'link').symlink_to(stage,target_is_directory=True);out=stage/'link'/'other.img.disabled'
                r=self.rejected('symlink_'+kind,c,stage,out)
                self.assertEqual(r['source_bytes_read'],0);self.assertFalse(r['partial_created'])
                if kind=='final':self.assertTrue(out.is_symlink())

    def test_07_source_symlink_and_pin(self):
        for kind in ('symlink','stat'):
            with self.subTest(kind=kind),fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
                if kind=='symlink':
                    link=stage/'source-link.img';link.symlink_to(c.source);c=dataclasses.replace(c,source=link)
                else:c=dataclasses.replace(c,source_stat=tuple([c.source_stat[0],c.source_stat[1]+1,*c.source_stat[2:]]))
                r=self.rejected('source_'+kind,c,stage,out);self.assertEqual(r['source_bytes_read'],0)

    def test_08_atomic_foreign_output_race(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            link=m.os.link
            def race(src,dst,**kw):
                out.write_bytes(b'foreign-racing-output');return link(src,dst,**kw)
            with patch.object(m.os,'link',race):
                with self.assertRaises(m.ControlError) as caught:m._materialize_control(c,out,staging_root=stage)
            r=caught.exception.receipt;record('atomic_destination_race',r)
            self.assertFalse(r['published']);self.assertEqual(out.read_bytes(),b'foreign-racing-output')
            self.assertEqual(r['partial_cleanup'],'owned_partial_removed');self.assertTrue(r['all_handles_closed'])

    def test_09_write_failure_cleanup(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            write=m._write_all;calls=0
            def fail(fd,data):
                nonlocal calls;calls+=1
                if calls==2:raise OSError('synthetic body-write failure')
                return write(fd,data)
            with patch.object(m,'_write_all',fail):r=self.rejected('write_failure',c,stage,out)
            self.assertEqual(r['partial_cleanup'],'owned_partial_removed');self.assertEqual(list(stage.glob('*.partial')),[])

    def test_10_fsync_failure_before_publish(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            sync=m.os.fsync;calls=0
            def fail(fd):
                nonlocal calls;calls+=1
                if calls==1:raise OSError('synthetic partial-fsync failure')
                return sync(fd)
            with patch.object(m.os,'fsync',fail):r=self.rejected('partial_fsync_failure',c,stage,out)
            self.assertEqual(r['partial_cleanup'],'owned_partial_removed')

    def test_11_corrupt_saved_partial_readback(self):
        with fixture(self.controls['expanded_fourK_geometry']) as (c,stage,out,raw):
            readback=m._readback_owned_partial
            def corrupt(parentfd,name,identity,size,state):
                fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW,dir_fd=parentfd)
                try:
                    os.fchmod(fd,0o600);os.pwrite(fd,b'X',777);os.fchmod(fd,0o444);os.fsync(fd)
                finally:os.close(fd)
                return readback(parentfd,name,identity,size,state)
            with patch.object(m,'_readback_owned_partial',corrupt):r=self.rejected('corrupt_saved_partial_before_readback',c,stage,out)
            self.assertEqual(r['generated_computed_full_sha256'],c.virtual_sha256)
            self.assertNotEqual(r['actual_saved_output_sha256'],c.virtual_sha256)
            self.assertEqual(r['saved_output_bytes_read'],c.size);self.assertEqual(r['partial_cleanup'],'owned_partial_removed')
            self.assertTrue(r['readback_handle_closed']);self.assertTrue(r['source_unchanged'])

    def test_12_post_link_fsync_failure_preserves_verified_output(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            sync=m.os.fsync;calls=0
            def fail(fd):
                nonlocal calls;calls+=1
                if calls==2:raise OSError('synthetic post-link directory-fsync failure')
                return sync(fd)
            with patch.object(m.os,'fsync',fail):r=self.rejected('post_link_fsync_failure',c,stage,out,published=True)
            self.assertTrue(out.is_file());self.assertEqual(SHA(out.read_bytes()),c.virtual_sha256)
            self.assertTrue(r['actual_saved_output_fullhash_verified']);self.assertEqual(r['partial_cleanup'],'owned_partial_removed')

    def test_13_unknown_partial_inode_preserved(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            publish=m._publish_owned_no_replace;foreign=None
            def replace(parentfd,name,output,identity):
                nonlocal foreign
                os.unlink(name,dir_fd=parentfd)
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parentfd)
                try:os.write(fd,b'foreign-partial')
                finally:os.close(fd)
                foreign=stage/name;return publish(parentfd,name,output,identity)
            with patch.object(m,'_publish_owned_no_replace',replace):r=self.rejected('partial_inode_replaced',c,stage,out)
            self.assertEqual(r['partial_cleanup'],'not_removed_ownership_or_cleanup_error')
            self.assertEqual(foreign.read_bytes(),b'foreign-partial')

    def test_14_source_changes_during_readback(self):
        with fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
            readback=m._readback_owned_partial
            def change(*args):
                result=readback(*args);s=c.source.stat();os.utime(c.source,ns=(s.st_atime_ns,s.st_mtime_ns+1000000));return result
            with patch.object(m,'_readback_owned_partial',change):r=self.rejected('source_stat_changes_during_readback',c,stage,out)
            self.assertFalse(r['source_unchanged']);self.assertEqual(r['partial_cleanup'],'owned_partial_removed')

    def test_15_metadata_cli_never_opens_or_stats_source_IMG(self):
        sourcepaths={os.fspath(c.source) for c in self.controls.values()};open0=m.os.open;lstat0=Path.lstat
        def watched_open(path,*args,**kw):
            if os.fspath(path) in sourcepaths:raise RuntimeError('Metadata CLI opened real source IMG')
            return open0(path,*args,**kw)
        def watched_lstat(path,*args,**kw):
            if os.fspath(path) in sourcepaths:raise RuntimeError('Metadata CLI statted real source IMG')
            return lstat0(path,*args,**kw)
        for argv in ([],['--list']):
            with self.subTest(argv=argv),patch.object(m.os,'open',watched_open),patch.object(Path,'lstat',watched_lstat):
                buffer=io.StringIO()
                with contextlib.redirect_stdout(buffer):self.assertEqual(m.main(argv),0)
                data=json.loads(buffer.getvalue());record('metadata_'+('default' if not argv else 'list'),data)
                self.assertFalse(data['source_IMG_opened_or_statted']);self.assertEqual(len(data['controls']),2)

    def test_16_explicit_guards_survive_optimized_python(self):
        run=subprocess.run([sys.executable,'-O',str(Path(__file__)),'--optimized-probe'],capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr);data=json.loads(run.stdout);record('python_O_rejection',data)
        self.assertTrue(data['optimized_python']);self.assertTrue(data['rejected'])

    def test_17_output_path_and_length_guards(self):
        for kind in ('suffix','outside','truncated','extra'):
            with self.subTest(kind=kind),fixture(self.controls['eightK_end_mirror']) as (c,stage,out,raw):
                if kind=='suffix':out=stage/'invalid.img'
                elif kind=='outside':out=stage.parent/'outside.img.disabled'
                else:
                    payload=raw[:-1] if kind=='truncated' else raw+b'X'
                    c.source.chmod(0o600);c.source.write_bytes(payload);c.source.chmod(0o444)
                    # Retain pinned size/identity, only refresh timestamps: source-size guard must reject.
                    s=c.source.stat();c=dataclasses.replace(c,source_stat=(s.st_dev,s.st_ino,c.size,s.st_mtime_ns,s.st_ctime_ns))
                r=self.rejected('output_or_size_'+kind,c,stage,out)
                self.assertEqual(r['source_bytes_read'],0)


def main():
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    proof={'schema':'AP-header-control-materializer-synthetic-tests/v1','all_assigned_checks_passed':result.wasSuccessful(),
           'unittest_methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
           'synthetic_receipt_cases':len(RECEIPTS),'fixture_max_bytes':FIXTURE_BYTES,
           'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,'real_materialization_executed':False,
           'small_catalog_reads_bytes':sum(r['bytes'] for r in Tests.catalog_receipts)+
                 sum(sum(v['bytes'] for v in r['receipt'].get('small_catalog_input_receipts',[])) for r in RECEIPTS),
           'catalog_input_receipts':Tests.catalog_receipts,'receipts':RECEIPTS,
           'source_sha256':SHA(SOURCE.read_bytes()),'test_source_sha256':SHA(Path(__file__).read_bytes()),
           'installable':False,'actual_device_UI_renderer_or_checksum_policy_verified':False}
    (HERE/'synthetic-test-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    (HERE/'catalog-manifest.json').write_text(json.dumps(m.catalog_metadata(Tests.controls,Tests.catalog_receipts),ensure_ascii=False,indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    sys.exit(optimized_probe() if sys.argv[1:]==['--optimized-probe'] else main())
