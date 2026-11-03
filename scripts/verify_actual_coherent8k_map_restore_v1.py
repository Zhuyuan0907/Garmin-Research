"""One local disabled map output and exact streamed stock-restore verification.

Pure host map-data tools only. No device discovery, firmware execution, native
emulator, Bluetooth, service changes, archive or second full backup.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-AP-coherent8k-actual-materialization-rollback-v1'
CANDIDATE = OUT/'coherent8K-end-mirror.img.disabled'
MAT = 'scripts/materialize_ap_header_control_v1.py'
ADAPTER = 'staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py'
INPUT_PINS = {
    MAT:'dfbf182f4d1b40fc4315c5568a7e92c521c35d1c764bc1946e53269f7f958142',
    ADAPTER:'284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc',
    'staging/navigation-AP-header-control-materializer-v1/proof.json':
        'c9b7b59d962f262b3c89f089eab04aeed5cfbdcc29657705703515cc0d128d7e',
    'staging/navigation-AP-header-control-materializer-v1/sealed-files.json':
        '442653f6ea55b5792f40048aa391c2c3a19b11cf0c7ed0af1a592d13df48197d',
    'staging/navigation-AP-header-control-materializer-independent-review-v1/proof.json':
        '9fa96cf0f4596b90a1c25c753347261fe74390a8721684268db71c948236b5c3',
    'staging/navigation-AP-header-control-materializer-independent-review-v1/sealed-files.json':
        'f8c6dc5e29df1d3ece2722426e14d4c4a786086ce01199218753c4f26d3e7008',
    'staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/proof.json':
        'a6418ca226e22f4bcbfae273abec4daf8ab8725c3d83ce5dc8e09e5f9d155198',
    'staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/sealed-files.json':
        'b68b33e3e6d8af2126c1da1e2667a40ea73a081c3e906d5accd73fcc9f9abc30',
}
MAX_CURRENT_MEMORY_KIB = 98304
RESTORE_ACTUAL_READ_CAP = 260000000
TOTAL_IMG_READ_CAP = 600000000
SMALL_INPUT_CAP = 3145728


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(s):
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_mode]


def memory():
    data = Path('/proc/self/status').read_text()
    fields = {line.split(':',1)[0]:int(line.split()[1]) for line in data.splitlines()
              if line.startswith(('VmRSS:', 'VmHWM:'))}
    require(max(fields.values()) <= MAX_CURRENT_MEMORY_KIB, 'Current process RSS/HWM budget')
    return fields


def save(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    require(len(raw) <= 65536, 'Small own artifact output bound')
    path = OUT/name
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o444)
    return dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=digest(raw))


def load_small():
    result = {}; receipts = []
    for path,pin in INPUT_PINS.items():
        p = ROOT/path; before=p.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 65536, 'Small fixed regular prerequisite')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            require(snapshot(os.fstat(f.fileno())) == snapshot(before), 'Opened prerequisite inode pin')
            raw=f.read(65537);require(f.read(1)==b'', 'Prerequisite EOF')
        require(len(raw)==before.st_size and digest(raw)==pin and snapshot(p.lstat())==snapshot(before),
                'Prerequisite full hash and stable source')
        receipts.append(dict(path=path,bytes=len(raw),sha256=pin))
        result[path]=raw
    require(sum(r['bytes'] for r in receipts) < SMALL_INPUT_CAP, 'Small prerequisite raw budget')
    return result,receipts


def module(name, path, raw):
    result=types.ModuleType(name);result.__file__=str(ROOT/path)
    sys.modules[name]=result
    exec(compile(raw,result.__file__,'exec'),result.__dict__)
    return result


class CountedReadOnly:
    mode='rb'
    def __init__(self, base):
        self.base=base;self.bytes_read=0;self.read_calls=0;self.seek_calls=0
    def fileno(self):return self.base.fileno()
    def tell(self):return self.base.tell()
    def seek(self,offset,whence=0):
        self.seek_calls+=1;return self.base.seek(offset,whence)
    def read(self,count):
        require(type(count) is int and 0 <= count <= 1048576, 'Bounded actual source read')
        require(self.bytes_read+count <= RESTORE_ACTUAL_READ_CAP, 'Actual verification/restoration read cap')
        raw=self.base.read(count);self.bytes_read+=len(raw);self.read_calls+=1
        return raw


class ReceiptSink:
    def __init__(self):
        self.count=0;self.bytes=0;self.purposes={};self.samples=[];self.hash=hashlib.sha256()
    def append(self, value):
        self.count+=1;self.bytes+=value['bytes']
        purpose=value['purpose'];self.purposes[purpose]=self.purposes.get(purpose,0)+value['bytes']
        self.hash.update((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
        if len(self.samples)<12:self.samples.append(value)
    def summary(self):
        return dict(append_count=self.count,logical_bytes=self.bytes,purposes=self.purposes,
                    canonical_receipt_stream_sha256=self.hash.hexdigest(),first_samples=self.samples,
                    retained_per_block_receipt_list=False)


def main():
    require(not OUT.exists(), 'Single-use output namespace must be absent')
    OUT.mkdir(mode=0o700)
    phase='prerequisites';fd=None;base=None;state={}
    try:
        raw,small_receipts=load_small()
        matproof=json.loads(raw['staging/navigation-AP-header-control-materializer-v1/proof.json'])
        reviewed=json.loads(raw['staging/navigation-AP-header-control-materializer-independent-review-v1/proof.json'])
        rollbackproof=json.loads(raw['staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/proof.json'])
        require(matproof['all_assigned_checks_passed'] and matproof['tests']['methods']==17 and
                reviewed['all_assigned_checks_completed'] and rollbackproof['all_assigned_checks_passed'] and
                rollbackproof['actual_run']['actual_exit_code']==0, 'Closed production prerequisites')
        materializer=module('_root_closed_materializer_v1',MAT,raw[MAT])
        adapter=module('_root_closed_inverse_header_v1',ADAPTER,raw[ADAPTER])
        controls,catalog_receipts=materializer.load_catalog()
        control=controls['eightK_end_mirror']
        inputs=adapter.prepare_fixed_inputs()
        small_bytes=sum(x['bytes'] for x in small_receipts+catalog_receipts+list(inputs.receipts))
        require(small_bytes <= SMALL_INPUT_CAP, 'Aggregate actual fixed small artifact reads')
        require(control.size==153346048 and control.virtual_sha256==adapter.COHERENT8_SHA,
                'Exact fixed coherent8K production control')
        free=os.statvfs(OUT)
        require(free.f_bavail*free.f_frsize > control.size*3, 'Space for exactly one new candidate and routine reserve')
        save('execution-preflight.json',dict(schema='actual-coherent8K-local-preflight/v1',prerequisite_pins=INPUT_PINS,
            current_memory=memory(),small_input_bytes=small_bytes,small_input_read_cap=SMALL_INPUT_CAP,
            new_IMG_output_count=1,new_IMG_output_bytes=control.size,streamed_stock_output_saved=False,
            restore_actual_read_cap=RESTORE_ACTUAL_READ_CAP,total_IMG_read_cap=TOTAL_IMG_READ_CAP,
            native_guest=False,firmware=False,device_IO=False,audio=False,services=False))
        print(json.dumps(dict(phase='materializing_one_disabled_local_candidate',IMG_bytes=control.size)),flush=True)
        phase='materialization'
        state=materializer._materialize_control(control,CANDIDATE)
        require(state['all_handles_closed'] and state['published'] and state['actual_saved_output_fullhash_verified'],
                'Actual materializer output and saved readback completed')
        save('actual-materialization-receipt.json',state)
        candidate_before=CANDIDATE.lstat()
        require(stat.S_ISREG(candidate_before.st_mode) and stat.S_IMODE(candidate_before.st_mode)==0o444 and
                candidate_before.st_size==control.size and candidate_before.st_nlink==1,
                'Final regular readonly single-link actual output')
        save('actual-control-output-descriptor.json',dict(schema='actual-coherent8K-materialized-output/v1',
            path=str(CANDIDATE.relative_to(ROOT)),bytes=control.size,sha256=state['actual_saved_output_sha256'],
            final_stat=snapshot(candidate_before),changed_byte_offsets=[452],all_nonheader_bytes_unchanged=True,
            source_SHA=state['source_actual_full_sha256'],source_unchanged=state['source_unchanged'],
            all_source_handles_closed=True,device_installed=False,installable=False))
        print(json.dumps(dict(phase='fresh_actual_candidate_and_streamed_stock_verification',saved_SHA=state['actual_saved_output_sha256'])),flush=True)
        phase='fresh_candidate_and_stock_restore'
        fd=os.open(CANDIDATE,os.O_RDONLY|os.O_NOFOLLOW)
        base=os.fdopen(fd,'rb',buffering=0);fd=None
        require(snapshot(os.fstat(base.fileno()))==snapshot(candidate_before),'Actual output inode/stat binding')
        reader=CountedReadOnly(base)
        view=adapter.verified_eightk_overlay(reader,inputs)
        require(view.receipt['actual_corrected_full_sha256']==control.virtual_sha256 and
                view.receipt['computed_inverse_full_sha256']==control.source_sha256,
                'Fresh candidate full SHA and declared inverse full SHA')
        sink=ReceiptSink();stockhash=hashlib.sha256();stock_bytes=0;stock_blocks=0
        for block in inputs.helper.restored_stock_blocks(view,inputs.stock,inputs.old_binding,sink):
            stock_bytes+=len(block);stock_blocks+=1
            require(len(block)==4096 and stock_bytes<=adapter.STOCK_BYTES,'Exact streamed stock block/length')
            stockhash.update(block)
        require(stock_bytes==adapter.STOCK_BYTES and stockhash.hexdigest()==adapter.STOCK_SHA,
                'Fresh exact complete stock reconstruction SHA')
        view._stable();view.receipt['stock_hash_verified']=True
        require(snapshot(os.fstat(base.fileno()))==snapshot(CANDIDATE.lstat())==snapshot(candidate_before),
                'Materialized candidate unchanged during full restore')
        actual_restore_read_bytes=reader.bytes_read
        base.close();base=None
        total_IMG_reads=state['source_bytes_read']+state['saved_output_bytes_read']+actual_restore_read_bytes
        require(total_IMG_reads<=TOTAL_IMG_READ_CAP,'Total actual IMG read cap')
        proof=dict(schema='actual-coherent8K-materialization-and-exact-stock-restore/v1',
            all_assigned_checks_passed=True,completed_utc=datetime.now(timezone.utc).isoformat(),
            prerequisite_pins=INPUT_PINS,actual_new_IMG_file=str(CANDIDATE.relative_to(ROOT)),
            actual_candidate_bytes=control.size,actual_candidate_sha256=control.virtual_sha256,
            original_source_actual_sha256=state['source_actual_full_sha256'],
            saved_output_actual_readback_sha256=state['actual_saved_output_sha256'],
            fresh_second_candidate_full_sha256=view.receipt['actual_corrected_full_sha256'],
            fresh_inverse_full_sha256=view.receipt['computed_inverse_full_sha256'],
            exact_stock_reconstruction_bytes=stock_bytes,exact_stock_reconstruction_blocks=stock_blocks,
            exact_stock_reconstruction_sha256=stockhash.hexdigest(),streamed_stock_IMG_saved=False,
            inverse_overlay=view.receipt,unchanged_strict_old_helper=True,source_and_candidate_unchanged=True,
            candidate_final_stat=snapshot(CANDIDATE.lstat()),actual_restore_logical_read_receipts=sink.summary(),
            actual_read_counters=dict(materializer_original_IMG=state['source_bytes_read'],
                materializer_saved_output_IMG=state['saved_output_bytes_read'],
                fresh_candidate_verify_and_stock_restore=actual_restore_read_bytes,
                total_IMG=total_IMG_reads,IMG_read_cap=TOTAL_IMG_READ_CAP,small_artifacts=small_bytes),
            real_IMG_bytes_written=state['generated_bytes_written'],all_handles_closed=True,
            current_memory=memory(),physical_source_write_bytes=0,second_full_backup_created=False,
            device_IO=False,native_guest=False,firmware_execution=False,audio=False,service_changes=False,
            experimental_candidate_only=True,all_188870_supplements_content_unchanged_inherited_from_exact_body_identity=True,
            all_188870_records_UI_validated=False,installer_binding_and_package_completed=False,
            checksum_policy_verified=False,Garmin_acceptance_verified=False,renderer_rootcause_proven=False,
            full_Taiwan_update_complete=False,installable=False,full_goal_complete=False)
        proof_binding=save('proof.json',proof)
        print(json.dumps(dict(all_passed=True,proof=proof_binding,candidate_sha256=control.virtual_sha256,
            streamed_stock_sha256=stockhash.hexdigest(),total_actual_IMG_read_bytes=total_IMG_reads,
            device_IO=False,installable=False)),flush=True)
    except BaseException as exc:
        save('failure.json',dict(phase=phase,error_type=type(exc).__name__,error=str(exc),
            materializer_receipt=getattr(exc,'receipt',state),candidate_retained_if_published=True,
            no_automatic_retry=True,device_IO=False,installable=False))
        raise
    finally:
        if base is not None:base.close()
        if fd is not None:os.close(fd)


if __name__=='__main__':
    main()
