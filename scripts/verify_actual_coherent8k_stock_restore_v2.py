"""Verify the existing disabled coherent8K output; no IMG output or retry of v1."""
import hashlib
import json
import os
from pathlib import Path
import stat
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-AP-coherent8k-actual-stock-verification-v2'
PREVIOUS='staging/navigation-AP-coherent8k-actual-materialization-rollback-v1/'
CANDIDATE=ROOT/(PREVIOUS+'coherent8K-end-mirror.img.disabled')
DRIVER='scripts/verify_actual_coherent8k_map_restore_v1.py'
ADAPTER='staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py'
PINS={
    DRIVER:'8ca8d42acacfb4e5680495949639c380ca7df9992bb0b0785c969478aa169f70',
    ADAPTER:'284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc',
    PREVIOUS+'actual-control-output-descriptor.json':'1e533fd854c7c026ad7f9434133c6e6f51f69eaec23d039e7edd8569ac91f14b',
    PREVIOUS+'actual-materialization-receipt.json':'6e55a9faf020f8e18f306720abbc4f326a5b93da3cc8c87ebb13041be8564214',
    PREVIOUS+'failure-closure.json':'f2a1fd1d787ebd723443074c650333864aacb72088e208b7f15ec4cb45d4746e',
}


def require(ok,message):
    if not ok:raise ValueError(message)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def snapshot(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_mode]


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    require(len(raw)<=65536,'Small output artifact cap')
    p=OUT/name
    with p.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    p.chmod(0o444)
    return {'path':str(p.relative_to(ROOT)),'bytes':len(raw),'sha256':digest(raw)}


def load():
    result={};receipts=[]
    for path,pin in PINS.items():
        p=ROOT/path;before=p.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size<=65536,'Bounded regular prerequisite')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            require(snapshot(os.fstat(f.fileno()))==snapshot(before),'Opened prerequisite exact inode/stat')
            raw=f.read(65537);require(f.read(1)==b'','Prerequisite EOF')
        require(len(raw)==before.st_size and digest(raw)==pin and snapshot(p.lstat())==snapshot(before),
                'Pinned prerequisite full hash and stable stat')
        result[path]=raw;receipts.append({'path':path,'bytes':len(raw),'sha256':pin})
    return result,receipts


def main():
    require(not OUT.exists(),'Single-use verification namespace')
    OUT.mkdir(mode=0o700)
    base=None;fd=None;view=None;reader=None;phase='preparation'
    try:
        raw,receipts=load()
        import sys,types
        driver=types.ModuleType('_root_closed_failed_driver_utilities_v2')
        driver.__file__=str(ROOT/DRIVER);sys.modules[driver.__name__]=driver
        exec(compile(raw[DRIVER],driver.__file__,'exec'),driver.__dict__)
        # Import shared bounded utilities only; its main/writer is never called.
        adapter=driver.module('_root_coherent8K_adapter_actual_v2',ADAPTER,raw[ADAPTER])
        inputs=adapter.prepare_fixed_inputs()
        descriptor=json.loads(raw[PREVIOUS+'actual-control-output-descriptor.json'])
        materialized=json.loads(raw[PREVIOUS+'actual-materialization-receipt.json'])
        previous_failure=json.loads(raw[PREVIOUS+'failure-closure.json'])
        require(descriptor['path']==str(CANDIDATE.relative_to(ROOT)) and
                descriptor['bytes']==adapter.V3_BYTES and descriptor['sha256']==adapter.COHERENT8_SHA and
                materialized['actual_saved_output_fullhash_verified'] and previous_failure['streamed_stock_blocks_yielded']==0,
                'Bind the one already materialized candidate and preserve failed attempt')
        small_bytes=sum(x['bytes'] for x in receipts+list(inputs.receipts))
        require(small_bytes<=driver.SMALL_INPUT_CAP,'Aggregate small input bound')

        class CompleteReceiptSink(driver.ReceiptSink):
            def extend(self,values):
                for value in values:self.append(value)

        # Check the missing protocol operation before opening the actual IMG.
        protocol=CompleteReceiptSink();protocol.extend([{'purpose':'protocol_check','bytes':0}])
        require(protocol.count==1 and protocol.bytes==0,'append/extend recorder protocol preflight')
        save('execution-preflight.json',dict(schema='actual-coherent8K-stock-verification-only/v2',
            prerequisite_pins=PINS,small_input_bytes=small_bytes,current_memory=driver.memory(),
            actual_IMG_read_cap=driver.RESTORE_ACTUAL_READ_CAP,new_IMG_files=0,
            old_failed_source_unchanged=True,only_glue_extend_added=True,old_parser_guards_unchanged=True,
            native_guest=False,firmware=False,device_IO=False,audio=False))
        phase='actual_candidate_full_verify_and_stock_generator'
        print(json.dumps({'phase':phase,'existing_disabled_candidate':str(CANDIDATE.relative_to(ROOT))}),flush=True)
        before=CANDIDATE.lstat()
        require(snapshot(before)==descriptor['final_stat'] and stat.S_ISREG(before.st_mode),
                'Exact materialized candidate final stat pin')
        fd=os.open(CANDIDATE,os.O_RDONLY|os.O_NOFOLLOW)
        base=os.fdopen(fd,'rb',buffering=0);fd=None
        require(snapshot(os.fstat(base.fileno()))==descriptor['final_stat'],'Opened actual candidate inode/stat pin')
        reader=driver.CountedReadOnly(base)
        view=adapter.verified_eightk_overlay(reader,inputs)
        require(view.receipt['actual_corrected_full_sha256']==adapter.COHERENT8_SHA and
                view.receipt['computed_inverse_full_sha256']==adapter.V3_SHA,'Fresh candidate/inverse full hashes')
        sink=CompleteReceiptSink();stock_hash=hashlib.sha256();stock_bytes=0;stock_blocks=0
        for block in inputs.helper.restored_stock_blocks(view,inputs.stock,inputs.old_binding,sink):
            require(len(block)==4096 and stock_bytes+len(block)<=adapter.STOCK_BYTES,'Exact complete stock blocks')
            stock_hash.update(block);stock_bytes+=len(block);stock_blocks+=1
        require(stock_bytes==adapter.STOCK_BYTES and stock_hash.hexdigest()==adapter.STOCK_SHA,
                'Fresh streamed complete stock SHA and length')
        view._stable();view.receipt['stock_hash_verified']=True
        require(snapshot(os.fstat(base.fileno()))==snapshot(CANDIDATE.lstat())==descriptor['final_stat'],
                'Actual source unchanged through complete stock-generator EOF')
        actual_reads=reader.bytes_read;read_calls=reader.read_calls;seek_calls=reader.seek_calls
        base.close();base=None
        require(actual_reads<=driver.RESTORE_ACTUAL_READ_CAP,'Actual verification-only read bound')
        proof=dict(schema='actual-coherent8K-streamed-stock-verification/v2',all_assigned_checks_passed=True,
            completed_utc=datetime.now(timezone.utc).isoformat(),prerequisite_pins=PINS,
            candidate_path=str(CANDIDATE.relative_to(ROOT)),candidate_bytes=adapter.V3_BYTES,
            candidate_full_sha256=view.receipt['actual_corrected_full_sha256'],
            computed_inverse_original_v3_sha256=view.receipt['computed_inverse_full_sha256'],
            exact_stock_reconstruction_sha256=stock_hash.hexdigest(),exact_stock_bytes=stock_bytes,
            exact_stock_blocks=stock_blocks,actual_candidate_read_bytes=actual_reads,
            read_calls=read_calls,seek_calls=seek_calls,actual_read_cap=driver.RESTORE_ACTUAL_READ_CAP,
            final_source_stat=snapshot(CANDIDATE.lstat()),all_handles_closed=True,source_unchanged=True,
            inverse_view_receipt=view.receipt,stock_read_receipts=sink.summary(),
            original_materialization_readback_inherited=materialized['actual_saved_output_sha256'],
            first_failed_actual_restore_read_counter_not_saved=True,
            cumulative_IMG_reads_all_attempts_conservative_upper_bound=
                previous_failure['first_total_IMG_read_conservative_upper_bound']+actual_reads,
            whole_pipeline_one_attempt=False,old_helper_unchanged=True,old_strict_guards_unchanged=True,
            real_IMG_write_bytes=0,new_IMG_files=0,streamed_stock_image_saved=False,
            second_full_backup_created=False,current_memory=driver.memory(),device_IO=False,
            native_guest=False,firmware_execution=False,audio=False,service_changes=False,
            full_Taiwan_update_complete=False,checksum_policy_verified=False,
            Garmin_UI_renderer_verified=False,road_loss_rootcause_proven=False,
            installer_binding_and_package_completed=False,installable=False,full_goal_complete=False)
        binding=save('proof.json',proof)
        print(json.dumps({'all_passed':True,'proof':binding,'stock_bytes':stock_bytes,
            'stock_sha256':stock_hash.hexdigest(),'actual_candidate_read_bytes':actual_reads,
            'new_IMG_files':0,'device_IO':False}),flush=True)
    except BaseException as exc:
        save('failure.json',{'phase':phase,'error_type':type(exc).__name__,'error':str(exc),
            'actual_IMG_read_bytes':None if reader is None else reader.bytes_read,
            'inverse_view_receipt':None if view is None else view.receipt,'new_IMG_files':0,
            'old_attempts_retained':True,'no_automatic_retry':True,'device_IO':False})
        raise
    finally:
        if base is not None:base.close()
        if fd is not None:os.close(fd)


if __name__=='__main__':main()
