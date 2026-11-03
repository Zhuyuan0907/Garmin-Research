#!/usr/bin/env python3
"""Independent saved-output bit/label audit, small summary and hash seal only."""
import hashlib
import json
import math
import struct
from decimal import Decimal
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(name, d):
    (OUT/name).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')


def bitloop(raw, start, width):
    value = 0
    for bit in range(width):
        value |= ((raw[(start+bit)//8] >> ((start+bit)%8)) & 1) << bit
    return value


def main():
    assert not (OUT/'SEAL.json').exists()
    p = json.loads((OUT/'proof.json').read_text())
    assert p['status'] == 'bounded_diagnostic_completed' and p['exception'] is None
    assert p['actual_IMG_read_bytes'] == sum(r['bytes'] for r in p['actual_FILE_read_journal']) == 253674
    assert p['actual_IMG_read_operations'] == len(p['actual_FILE_read_journal']) == 1411
    assert all(x['readonly_source_handle_closed'] and x['unchanged'] for x in p['source_handles'])
    labels = ['昌平路二段','50之6巷','2弄','39號']
    audited_records, audited_spans, leaves, rawflag_paths = 0, [], {}, {}
    for tag in ['v2','v3']:
        result = p['results'][tag]
        assert result['status'] == 'existing_exact_terminal_leaf_found'
        assert result['exact_path_labels_reached'] == labels
        assert all(s['status']=='exact_unique' for s in result['steps'])
        assert [s['group']['exact_match_count'] for s in result['steps']] == [1,1,1]
        directory = (OUT/(tag+'-actual120-directory.bin')).read_bytes()
        assert len(directory)==120 and sha(directory)==result['actual_directory']['SHA256']
        tables = {}
        for level in range(1,7):
            a,b,stride,w,x = struct.unpack_from('<5I',directory,(level-1)*20)
            tables[level] = {'stride':stride,'widths':[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63],
                             'refs':[w>>30&1,w>>31&1]}
        assert (tables[3]['widths'][0],tables[3]['stride'])==(23,112)
        rows = [json.loads(x) for x in (OUT/('observed-records-'+tag+'.jsonl')).read_text().splitlines()]
        assert len(rows)==1+594+26+117==738
        by_record = {r['record']:r for r in rows}
        assert len(by_record)==len(rows)
        cache = {r['ref']:r for r in result['label_cache']}
        for row in rows:
            value = bitloop(bytes.fromhex(row['raw_record_hex']),row['initial_bit_shift'],row['record_bit_length'])
            assert value==row['raw_record_value']
            assert int.from_bytes(bytes.fromhex(row['significant_rawbit_hex']),'little')==value
            ref = row['primary_ref']
            assert row['actual_primary_label']==(cache[ref]['actual_primary_label'] if ref is not None else None)
            if ref is not None:
                assert bytes.fromhex(cache[ref]['CP950_hex']).decode('cp950')==row['actual_primary_label']
                assert row['actual_primary_label'].encode('cp950').hex()==cache[ref]['CP950_hex']
            t = tables[row['level']]
            w,r = t['widths'],t['refs']
            fields=[('mapordinal',w[4],True,False),('secondary_ref',w[3],bool(r[1]),True),
                    ('primary_ref',w[3],bool(r[0]),True),('first_child',w[0],bool(w[0]),False),
                    ('child_count',w[5],bool(w[5]),False),('raw_flags',w[1],bool(w[1]),False),
                    ('raw_location_a',w[2],bool(w[2]),False),('raw_location_b',w[2],bool(w[2]),False)]
            cursor=0
            for name,width,on,isref in fields:
                v=bitloop(bytes.fromhex(row['significant_rawbit_hex']),cursor,width) if on else None if isref else 0
                expected=None if on and isref and v==(1<<width)-1 else v
                assert row[name]==expected
                cursor+=width if on else 0
            assert cursor==row['record_bit_length'] and row['next_level']==row['raw_flags']&7
            audited_records+=1
        for g in p['selected_groups'][tag]:
            raw=(OUT/g['raw_span_artifact']).read_bytes()
            assert len(raw)==g['raw_span_bytes'] and sha(raw)==g['raw_span_SHA256']
            level=g['actual_childlevel']
            assert tables[level]['stride']==g['child_stride_bits']
            for ordinal in range(g['count']):
                record=level<<28|(g['first']+ordinal)
                row=by_record[record]
                value=bitloop(raw,g['initial_wholegroup_bit_shift']+ordinal*g['child_stride_bits'],g['child_stride_bits'])
                assert value==row['raw_record_value'] and row['child_ordinal_under_selected_parent']==ordinal
                assert row['selected_parent_record']==g['parent_record']
            audited_spans.append({'source':tag,'level':level,'count':g['count'],
                                  'initial_wholegroup_bit_shift':g['initial_wholegroup_bit_shift'],
                                  'all_significant_record_bits_equal_saved_span':True})
        path=result['path_records_with_full_rawbits']
        for r in path:
            assert r==by_record[r['record']]
        leaf=path[-1]
        assert leaf['next_level']==0 and leaf['child_count']==0
        leaves[tag]={'leaf_record':leaf['record'],'leaf_ID':leaf['ID'],'raw24':[leaf['raw_location_a'],leaf['raw_location_b']],
                     'actual_primary_label_ref':leaf['primary_ref'],'full_raw_flags':leaf['raw_flags']}
        rawflag_paths[tag]=[r['raw_flags'] for r in path]
    assert audited_records==1476
    assert leaves['v2']['leaf_record']==leaves['v3']['leaf_record']==1611333657
    assert leaves['v2']['raw24']==leaves['v3']['raw24']==[1127428,5624276]
    assert p['source_summary']['native24']==[1127428,5624288]
    assert all(not x for x in p['flags'].values())
    originals=list(map(Decimal,p['source_summary']['sourcepoint']))
    leaf_degrees=list(map(Decimal,p['results']['v2']['exact39_rawpoint_comparison']['leaf_degree_strings']))
    original_degree_delta=[leaf_degrees[i]-originals[i] for i in range(2)]
    mean=math.radians(float((leaf_degrees[0]+originals[0])/2))
    dlat,dlon=map(lambda x:math.radians(float(x)),original_degree_delta)
    original_metres=math.hypot(dlat,dlon*math.cos(mean))*6371008.8
    audit={'schema':'independent_new_saved_span_bitloop_label_audit/v1','all_assigned_checks_passed':True,
        'records_full_significant_bits_and_actual_fields_checked':audited_records,'selected_group_spans':audited_spans,
        'unique_exact_labels_at_every_path_stage':True,'existing_leaf_identity_both_images':leaves,
        'full_rawflags_along_selected_paths':rawflag_paths,
        'comparison_to_original_decimal_source_only':{'leaf_degree_strings':list(map(str,leaf_degrees)),
            'source_original_decimal_strings':p['source_summary']['sourcepoint'],
            'leaf_minus_original_decimal_degrees':list(map(str,original_degree_delta)),
            'approx_metres':original_metres,'no_nearest_matching_or_source_acceptance':True},
        'new_IMG_or_source_reads_in_this_audit':0,'native_CPU_or_compile':False}
    write('output-bit-label-audit.json',audit)
    receipts=[
        {'command':'python3 staging/navigation-country-v2-v3-address-path-diagnostic-v1/prepare_reader_source_v1.py',
         'actual_tool':'exec_command','terminal_chunk_id':'941921','exit_code':0,'wall_time_seconds':0.000022278,
         'executed_source_SHA256':sha((OUT/'prepare_reader_source_v1.py').read_bytes()),'actual_IMG_bytes':0},
        {'command':'python3 staging/navigation-country-v2-v3-address-path-diagnostic-v1/diagnose_exact_path_v1.py',
         'actual_tool':'exec_command','terminal_chunk_id':'c85380','exit_code':0,'wall_time_seconds':0.091407427,
         'executed_source_SHA256':sha((OUT/'diagnose_exact_path_v1.py').read_bytes()),
         'actual_IMG_bytes':253674,'actual_FILE_read_operations':1411,
         'observed_status':'both existing exact terminal39 leaves found; all source handles closed; source floor hold unchanged',
         'groups_per_image':[{'level':4,'count':594,'shift':0,'exact_matches':1},
                             {'level':5,'count':26,'shift':2,'exact_matches':1},
                             {'level':6,'count':117,'shift':0,'exact_matches':1}]}]
    write('actual-tool-receipts.json',{'receipts':receipts,'audit_and_seal_actual_terminal_receipt':'post-seal-tool-receipt.json'})
    summary={'schema':'small_existing_address_path_diagnostic_summary/v1','status':'both_existing_exact39_leaves_found_coordinates_differ_from_source',
        'exact4labels':labels,'unique_matches_each_image_each_step':[1,1,1],
        'paths':{tag:{'records':p['results'][tag]['actual_path_records'],'leaf':leaves[tag],
            'children_inspected':[594,26,117],'wholegroup_initial_shifts':[0,2,0],'raw_flags':rawflag_paths[tag]} for tag in ['v2','v3']},
        'two_existing_leaf_raw24_identical':True,
        'source_group':172188,'sourcepoint_original':p['source_summary']['sourcepoint'],'source_raw24':[1127428,5624288],
        'leaf_minus_source_raw24':[0,-12],
        'approx_metres_from_quantized_source':p['results']['v2']['exact39_rawpoint_comparison']['approx_metres_from_quantized_source'],
        'approx_metres_from_original_decimal_source':original_metres,
        'point_distance_method':'Local equirectangular approximation; comparison after exact label lookup, never nearest selection.',
        'actual_IMG_bytes':253674,'actual_FILE_reads':1411,'actual_IMG_limit_bytes':2097152,
        'actual_tool_receipts':[{'chunk':'941921','exit':0},{'chunk':'c85380','exit':0}],
        'source_handles_all_closed_stats_unchanged':True,'native_CPU_instructions':0,'compile_commands':0,
        'source21_nodes_PBF_groups_capture_gzip_fulltree_or_fullGMP_read':False,
        'holds':['Existing source floor/unit/official/formal/install holds remain.','Exact existing39 label is present; source point does not equal its stored raw24.'],
        'interpretation':'This exact address path already exists in both countryv2/v3. L4 record relocation leads to the same L5/L6 records and same leaf point; no new address, search UI, route or physical success is proved.',
        'flags':p['flags'],'private_engineering_proof':'proof.json','private_record_observations':['observed-records-v2.jsonl','observed-records-v3.jsonl'],
        'private_rawgroup_spans_and_labelcache':'Selected bounded group .bin artifacts and full proof.json; no public bundle created.',
        'seal_after_completion':True}
    raw=(json.dumps(summary,ensure_ascii=False,indent=2)+'\n').encode()
    assert len(raw)<=8192
    (OUT/'scope-summary.json').write_bytes(raw)
    handoff=f'''# navigation-country-v2-v3-address-path-diagnostic-v1 HANDOFF

兩圖既有精確path都存在：昌平路二段 → 50之6巷 → 2弄 → 39號；每一步均unique exact primary CP950 label，未使用secondary ref、suffix alias、nearest或假missing-child。Actual c85380 EXIT0，共253674 IMG bytes／1411 FILE reads（全局上限2097152），每圖594 L4＋26 L5＋117 L6。Actual L5 group初始bit shift2／stride126，L6 stride68；完整raw spans及1476 observed records保留。

v2 path records805319491／1076295446／1342980390／1611333657；v3為805319491／1077917669／1342980390／1611333657。只L4 clone record ID不同，後段同原L5/L6。兩圖leaf ID{leaves['v2']['leaf_ID']}／record1611333657，raw24同[1127428,5624276]；source摘要[1127428,5624288]差[0,-12]。Approx quantized-source距離26.11732968738901m；與原decimal source24.19197/120.6841351約{original_metres}m。這是lookup後兩個已指定點的比較，未用距離選門牌。

所以不能把172188的39號當missing新增，也沒有same-source-coordinate match。來源floor/unit、官方alias、正式門牌／路由／install holds全部保持。Root另agent的21node floor partition研究與此普通existing-tree診斷分開；此scope沒有重讀source capture、PBF、groups／fullnodeledger或whole-v3 tree/house ledger，沒有nativeCPU、writer、firmware compile、IMG/DB修改／安裝／裝置／音訊。

普通reader從上一scope已pin的readonly AP code抽出到新namespace，唯一class差異是登记readonly handle供finally清理；原sealed source未import/執行或修改。兩圖header/FAT／120-byte DIR與parent按各實際4K/8K descriptor讀取。所有raw flags保持原bits，只以已證低3bits作childlevel；不修改unknownflags。所有source handles真closed、stats前後一致，destination只有新scope證據檔案。WholeIMG SHA繼承oldpins不重算。

新output independent bitloop audit核對全部1476記錄 significant bits、descriptor fields、CP950 label/ref對應、6個actual saved group spans與exact path一致。Source/record/label cache完整工程proof保留私密文件；供root報告的小scope-summary.json為{len(raw)}B，≤8KiB。

Evidence：proof.json含full FILE journal／source stats／所有path rawfields／labelcache；observed-records-v2/v3.jsonl；6個selected child .bin rawspans；output-bit-label-audit.json；actual receipts、readonly reader source／dependency manifest／diff。所有claim flagsfalse，scope完成後hash-size-stat seal並停止。不叫搜尋UI／正式路由／v3道路修復／新街加入或install成功。
'''
    (OUT/'HANDOFF.md').write_text(handoff)
    files=[]
    for f in sorted(OUT.rglob('*')):
        if not f.is_file() or f.name in ['SEAL.json','post-seal-tool-receipt.json']:
            continue
        b=f.read_bytes();s=f.stat()
        files.append({'path':str(f.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b),'actual_mode_octal':oct(s.st_mode&0o777),
                      'device':s.st_dev,'inode':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns})
    seal={'schema':'hash-size-observed-stat-seal/v1','files':files,'old_sources_seals_or_IMG_modified':False,
        'chmod_performed':False,'native_compile_or_CPU_execution':False,'readonly_handles_closed':True,
        'actual_IMG_budget_respected':True,'small_summary_max8192_respected':True,
        'self_and_post_actual_terminal_receipt_excluded':True,'seal_then_stop':True}
    b=(json.dumps(seal,ensure_ascii=False,indent=2)+'\n').encode();(OUT/'SEAL.json').write_bytes(b)
    print(json.dumps({'status':'existing_exact_path_diagnostic_and_output_bit_audit_sealed','files':len(files),
        'records_independently_bit_checked':1476,'summary_bytes':len(raw),'summary_SHA256':sha(raw),
        'proof_SHA256':sha((OUT/'proof.json').read_bytes()),'seal_SHA256':sha(b),
        'IMG_bytes':253674,'source_hold_released':False,'stop_after_seal':True},ensure_ascii=False))


if __name__=='__main__':
    main()
