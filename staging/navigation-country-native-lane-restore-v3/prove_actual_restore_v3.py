#!/usr/bin/env python3
"""NEW actual8K -> exact stock4K streamed proof; no IMG output or full hash."""
from collections import Counter
from datetime import datetime,timezone
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
CANDIDATE_DIR=ROOT/'staging/navigation-country-native-lane-candidate-v3'
API_DIR=ROOT/'staging/navigation-native-8k-layout-restore-api-v1'
API_SHA='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
API_SEAL_SHA='7bef13e816951f51c32e75b2f9e00940b9104f971ba67a7f67d3684e5561af04'
RECIPE_PATH=ROOT/'staging/navigation-country-layout-restore-v2/restore-layout.json.gz'
EXPECTED_BYTES=153346048
EXPECTED_COUNTS={4:4896236,5:3077845,6:2062771}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]


class TracedReader:
    """Records only actual bounded reads; never opens or writes another IMG."""
    def __init__(self,stream,api):
        self.stream=stream;self.api=api;self.mode=stream.mode
        self.log=[];self.bytes=0;self.rolling=hashlib.sha256();self.progress_at=8*1024*1024
    def fileno(self):return self.stream.fileno()
    def seek(self,*args):return self.stream.seek(*args)
    def tell(self):return self.stream.tell()
    def read(self,length):
        need(type(length) is int and 0<=length<=1024*1024,'Every actual candidate read is explicitly bounded')
        offset=self.stream.tell();raw=self.stream.read(length)
        need(len(raw)==length,'Actual candidate read truncated')
        self.bytes+=len(raw);self.rolling.update(raw)
        self.log.append({'physical_offset':offset,'bytes':len(raw),'sha256':sha(raw)})
        if self.bytes>=self.progress_at:
            print(json.dumps({'actual_candidate_partial_bytes_read':self.bytes,
                              'actual_bounded_read_calls':len(self.log),
                              'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}),flush=True)
            self.progress_at+=8*1024*1024
        return raw


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root-seal-sha256',required=True)
    parser.add_argument('--root-proof-sha256',required=True)
    parser.add_argument('--descriptor-sha256',required=True)
    parser.add_argument('--candidate-sha256',required=True)
    parser.add_argument('--candidate-stat5',required=True,help='Explicit frozen parent dev,ino,size,mtime_ns,ctime_ns comma-separated')
    args=parser.parse_args();started=datetime.now(timezone.utc).isoformat();t0=time.monotonic()
    need(not(HERE/'proof.json').exists(),'Refuse overwrite terminal NEW actual proof')
    pins=[]
    def read(path,expected,maximum):
        before=identity(path);need(before[2]<=maximum and path.stat().st_mode&0o222==0,'Only bounded immutable sealed input '+str(path))
        raw=path.read_bytes();need(sha(raw)==expected and identity(path)==before,'Bound input content/stat mismatch '+str(path))
        pins.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':expected,'stat_before':before,'stat_after':identity(path)})
        return raw
    seal=json.loads(read(CANDIDATE_DIR/'sealed-files.json',args.root_seal_sha256,1024*1024))
    need(seal['all_assigned_checks_passed'],'Root terminal seal all checks passed')
    rows={Path(r['path']).name:r for r in seal['files']}
    need(len(rows)==len(seal['files']),'Root seal basename identities unique')
    def sealed(name,expected,maximum):
        item=rows[name];path=ROOT/item['path'];need(path==CANDIDATE_DIR/name,'Root actual artifact namespace')
        need(item['sha256']==expected and path.stat().st_size==item['bytes'],'Root seal pins exact actual input')
        return read(path,expected,maximum)
    rootproof=json.loads(sealed('proof.json',args.root_proof_sha256,2*1024*1024))
    need(rootproof['all_assigned_checks_passed'] and rootproof['candidate_bytes']==EXPECTED_BYTES
         and rootproof['candidate_sha256']==args.candidate_sha256,'Final full root candidate proof pin')
    need(rootproof['lower_widths_expanded'] is False and rootproof['unknown_prefix_and_L2_L1_preserved'] is True
         and rootproof['all_47870_L3_actual_bytes_verified'] is True,'Root current-profile COW prerequisites')
    descriptor_raw=sealed('actual-output-layout.json',args.descriptor_sha256,1024*1024)
    descriptor=json.loads(descriptor_raw)
    need(descriptor['candidate_bytes']==EXPECTED_BYTES and descriptor['candidate_sha256']==args.candidate_sha256,
         'Actual normalized descriptor binding to complete root readback')
    api_seal=json.loads(read(API_DIR/'sealed-files.json',API_SEAL_SHA,65536))
    need(api_seal['all_assigned_checks_passed'],'Sealed restore API focused proof is complete')
    api_row=next(x for x in api_seal['files'] if Path(x['path']).name=='native_8k_stock_restore.py')
    api_raw=read(API_DIR/'native_8k_stock_restore.py',API_SHA,65536)
    need(api_row['sha256']==API_SHA and api_row['bytes']==len(api_raw),'Exact sealed API source')
    spec=importlib.util.spec_from_file_location('sealed_v3_actual_stock_restore',API_DIR/'native_8k_stock_restore.py')
    api=importlib.util.module_from_spec(spec);sys.modules[spec.name]=api;spec.loader.exec_module(api)
    recipe_before=identity(RECIPE_PATH);stock=api.load_stock_recipe(RECIPE_PATH)
    need(identity(RECIPE_PATH)==recipe_before and RECIPE_PATH.stat().st_mode&0o222==0,'Closed compact stock recipe immutable')
    pins.append({'path':str(RECIPE_PATH.relative_to(ROOT)),'bytes':stock.compressed_bytes,'sha256':stock.compressed_sha256,
                 'uncompressed_sha256':stock.uncompressed_sha256,'stat_before':recipe_before,'stat_after':identity(RECIPE_PATH),
                 'content_passes':1,'gzip_EOF_and_fixed_production_binding_checked':True})
    binding=api.prepare_restore_binding(stock,descriptor)
    need({x['level']:x['count'] for x in descriptor['tables'] if x['level'] in EXPECTED_COUNTS}==EXPECTED_COUNTS,
         'Exact actual future lower counts')
    binding_raw=api.canonical(binding);binding_path=HERE/'actual-stock-restore-binding.json'
    binding_path.write_bytes(binding_raw)
    candidate_path=ROOT/rows['gmapprom1.img']['path']
    need(candidate_path==CANDIDATE_DIR/'gmapprom1.img' and rootproof['candidate_path']==str(candidate_path.relative_to(ROOT)),
         'Actual candidate filename is explicitly pinned')
    before=identity(candidate_path);expected_stat=[int(x) for x in args.candidate_stat5.split(',')]
    need(len(expected_stat)==5 and before[:5]==expected_stat and before[2]==EXPECTED_BYTES
         and candidate_path.stat().st_mode&0o222==0,'Parent frozen actual candidate stat/readonly')
    need(rows['gmapprom1.img']['sha256']==args.candidate_sha256 and rows['gmapprom1.img']['bytes']==EXPECTED_BYTES,
         'Candidate full hash inherited from actual sealed root producer')
    logical=[];out_hash=hashlib.sha256();output_bytes=0;blocks=0
    with candidate_path.open('rb') as f:
        trace=TracedReader(f,api)
        for block in api.restored_stock_blocks(trace,stock,binding,logical):
            need(len(block)==4096,'Actual reconstruction block remains original4K')
            out_hash.update(block);output_bytes+=len(block);blocks+=1
        need(output_bytes==stock.data['original_bytes']==96739328 and blocks==23618
             and out_hash.hexdigest()==api.STOCK_SHA,'Complete exact original STOCK hash/bytes/blocks')
        need(trace.bytes<EXPECTED_BYTES and len(trace.log)<100000,'Only needed partial candidate slices consumed')
    need(identity(candidate_path)==before,'Actual candidate immutable after handle close')
    for pin in pins:need(identity(ROOT/pin['path'])==pin['stat_before']==pin['stat_after'],'Sealed source changed during reconstruction')
    receipt_path=HERE/'actual-candidate-bounded-reads.jsonl.gz';plain=hashlib.sha256();rows_written=0
    with receipt_path.open('xb') as rawfile:
        with gzip.GzipFile(fileobj=rawfile,mode='wb',mtime=0) as g:
            for sequence,r in enumerate(trace.log):
                line=api.canonical({'read_sequence':sequence,**r});g.write(line);plain.update(line);rows_written+=1
    receipt_bytes=receipt_path.stat().st_size;receipt_sha=sha(receipt_path.read_bytes())
    purposes=Counter();logical_bytes=Counter()
    for row in logical:
        purposes[row['purpose']]+=1;logical_bytes[row['purpose']]+=row['bytes']
    original_ranges=stock.data['MDR_ranges']
    range_counts=Counter();range_bytes=Counter()
    for row in logical:
        if 'range_index' in row:range_counts[row['range_index']]+=1;range_bytes[row['range_index']]+=row['bytes']
    for index in (1,2,3,4,6):need(range_bytes[index]==original_ranges[index]['length'],'Each original-length candidate MDR range consumed exactly once')
    proof={'schema':'actual-explicit8K-candidate-to-exact-stock4K-streamed-proof/v3',
        'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t0,
        'all_assigned_checks_passed':True,'script_sha256':sha(Path(__file__).read_bytes()),
        'candidate':{'path':str(candidate_path.relative_to(ROOT)),'bytes':EXPECTED_BYTES,'block_bytes':8192,
            'inherited_root_complete_readback_sha256':args.candidate_sha256,'whole_candidate_hash_repeated':False,
            'stat_before':before,'stat_after':identity(candidate_path),'immutable_stat_and_linkcount':True},
        'original':{'bytes':output_bytes,'blocks':blocks,'block_bytes':4096,
                    'exact_reconstructed_sha256':out_hash.hexdigest(),'expected_stock_sha256':api.STOCK_SHA,
                    'exact_hash_passed':True,'complete_generator_EOF_consumed':True,'IMG_file_written':False},
        'actual_binding':{'path':str(binding_path.relative_to(ROOT)),'bytes':len(binding_raw),'sha256':sha(binding_raw),
                          'no_compact_recipe_data_duplicated':True},
        'actual_input_pins':pins,'actual_future_counts':EXPECTED_COUNTS,
        'actual_header_FAT_MDR_directory_checked':True,'all_six_actual_components_matched_descriptor':True,
        'original_header_FAT_small111_L3_padding_and_unused_blocks_from_closed_recipe':True,
        'original_lower4_5_6_byte_prefixes_read_from_each_actual_future_table_start':True,
        'current_v2_L5_two_padding_bits_not_treated_as_stock_prefix':True,'lower_widths_inverse_transform_performed':False,
        'actual_candidate_bytes_read':trace.bytes,'actual_bounded_physical_read_calls':len(trace.log),
        'max_actual_physical_read_bytes':max(r['bytes'] for r in trace.log),
        'partial_read_concatenation_sha256':trace.rolling.hexdigest(),
        'partial_read_hash_scope':'Actual bounded reads in call order; not whole candidate hash.',
        'actual_read_receipts':{'path':str(receipt_path.relative_to(ROOT)),'bytes':receipt_bytes,'sha256':receipt_sha,
                              'plain_jsonl_sha256':plain.hexdigest(),'rows':rows_written,'gzip_writer_completed':True},
        'API_logical_read_summary':{'calls_by_purpose':dict(purposes),'bytes_by_purpose':dict(logical_bytes),
            'original_MDR_range_calls':dict(range_counts),'original_MDR_range_bytes':dict(range_bytes),
            'metadata_and_directory_witnesses':[r for r in logical if r['purpose'] in ('actual8K_header_FAT','actual_MDR_header','actual_MDR_directory')]},
        'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'full_backup_copied':False,'full_restored_IMG_written':False,'source_PBF_groups_ready_or_old_suite_opened':False,
        'USB_ZIP_canonical_installer_changes':False,'device_IO':False,'native_CPU_or_search_UI_route_tested':False,
        'header_checksum_rule_known':False,'actual8K_device_acceptance_verified':False,'full_Taiwan_address_update_complete':False,
        'limits':['Actual read-only exact stock reconstruction hash proof; no atomic transaction or physical rollback.',
                  'Candidate payloads beyond original stock ranges inherit root complete actual readback; this scope does not repeat that hash.',
                  'Native UI/search/route and physical explicit8K acceptance/checksum remain unverified.']}
    (HERE/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    (HERE/'execution-receipt.json').write_text(json.dumps({'actual_script_completed_exit_status':0,
        'started_utc':started,'finished_utc':proof['finished_utc'],'elapsed_seconds':proof['elapsed_seconds'],
        'script_sha256':proof['script_sha256'],'proof_sha256':sha((HERE/'proof.json').read_bytes()),
        'actual_candidate_bytes_read':trace.bytes,'exact_stock_reconstructed_SHA':out_hash.hexdigest(),
        'full_backup_or_restored_IMG_written':False,'device_IO':False},indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'exact_original_sha256':out_hash.hexdigest(),
        'actual_candidate_bytes_read':trace.bytes,'actual_read_calls':len(trace.log),
        'binding_bytes':len(binding_raw),'binding_sha256':sha(binding_raw),'read_receipt_gzip_bytes':receipt_bytes,
        'proof_sha256':sha((HERE/'proof.json').read_bytes()),'max_RSS_KiB':proof['max_RSS_KiB'],
        'device_IO':False,'restored_IMG_written':False}),flush=True)


if __name__=='__main__':main()
