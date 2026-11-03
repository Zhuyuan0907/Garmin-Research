#!/usr/bin/env python3
"""Two bounded existing trees, exact primary CP950 labels; floor hold unchanged."""
import hashlib
import json
import math
import struct
import traceback
from decimal import Decimal
from pathlib import Path

import bounded_ap_reader_v1 as reader

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
OLD = ROOT / 'staging/navigation-v2-one-family-lane-delta-plan-v1'
TOKENS = ['50之6巷', '2弄', '39號']
IMAGES = []
RESULTS = {}
OBSERVATIONS = {'v2': [], 'v3': []}
GROUPS = {'v2': [], 'v3': []}
NORMAL_PINS = []


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def load_pin(path, pin):
    before = reader.stat(path)
    raw = path.read_bytes()
    reader.need(sha(raw) == pin and reader.stat(path) == before, 'Normal input SHA/stat changed')
    NORMAL_PINS.append({'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'SHA256': pin,
                        'stat_before': before, 'stat_after': reader.stat(path)})
    return json.loads(raw)


def compare_point(record, source):
    raw = [record['raw_location_a'], record['raw_location_b']]
    signed = [x if x < 1 << 23 else x - (1 << 24) for x in raw]
    degrees = [Decimal(x) * Decimal(360) / Decimal(1 << 24) for x in signed]
    src_raw = source['native24']
    src_degrees = [Decimal(x) * Decimal(360) / Decimal(1 << 24) for x in src_raw]
    delta = [signed[i] - src_raw[i] for i in range(2)]
    dlat, dlon = [math.radians(float(degrees[i] - src_degrees[i])) for i in range(2)]
    mean_lat = math.radians(float((degrees[0] + src_degrees[0]) / 2))
    metres = math.hypot(dlat, dlon * math.cos(mean_lat)) * 6371008.8
    return {'leaf_native24': raw, 'leaf_signed24': signed, 'leaf_degree_strings': list(map(str, degrees)),
        'sourcepoint_original_decimal_strings': source['sourcepoint'], 'source_native24': src_raw,
        'leaf_minus_source_native24': delta, 'same_source_raw24': signed == src_raw,
        'approx_metres_from_quantized_source': metres,
        'comparison_only_not_nearest_selection_or_formal_address_acceptance': True}


class Tree:
    def __init__(self, tag, previous):
        self.tag, self.label_cache = tag, {}
        path = ROOT / previous['path']
        current = reader.stat(path)
        reader.need(current[:4] == previous['source_stat_after'][:4], 'Same inherited IMG dev/inode/size/mtime')
        self.image = reader.Image(tag, path, previous['block_bytes'])
        IMAGES.append(self.image)
        h = self.image.logical('00004171.MDR', 0, 772, 'actual MDR header')
        reader.need(h[2:12] == b'GARMIN MDR' and struct.unpack_from('<H', h)[0] == 772, 'MDR header')
        start, size, item, flag = struct.unpack_from('<4I', h, 600)
        reader.need((size, item, flag) == (120,20,1) and start + size == self.image.components['00004171.MDR']['size'], 'Actual six DIR EOF')
        d = self.image.logical('00004171.MDR', start, size, 'actual MDR directory')
        reader.need(sha(d) == previous['DIR_SHA256'] and d.hex() == previous['DIR_hex'], 'Actual directory pin')
        self.tables = {}
        for level in range(1, 7):
            a,b,stride,w,x = struct.unpack_from('<5I', d, (level-1)*20)
            widths = [w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63]
            refs = [w>>30&1,w>>31&1]
            count = b*8//stride
            self.tables[level] = {'level':level,'start':a,'bytes':b,'stride':stride,'count':count,
                'widths':widths,'refs':refs,'directory_hex':d[(level-1)*20:level*20].hex()}
            reader.need(self.tables[level] == previous['actual_tables'][str(level)], 'Decode actual descriptor exactly as prior pin')
        g = self.image.logical('I053061A.GMP',0,57,'actual GMP header')
        reader.need(g[2:12] == b'GARMIN GMP' and struct.unpack_from('<H',g)[0] == 57,'GMP header')
        lbl_at = struct.unpack_from('<7I',g,25)[2]
        lbl = self.image.logical('I053061A.GMP',lbl_at,661,'actual LBL descriptor')
        reader.need(lbl[2:12] == b'GARMIN LBL' and struct.unpack_from('<H',lbl)[0] == 661,'LBL header')
        self.pool_start,self.pool_size = struct.unpack_from('<II',lbl,21)
        self.label_shift = lbl[29]
        reader.need((self.pool_start,self.pool_size,self.label_shift,lbl[30],struct.unpack_from('<H',lbl,170)[0]) == (6566,3805432,3,10,950),'Exact CP950 pool')
        (OUT/(tag+'-actual120-directory.bin')).write_bytes(d)
        self.directory = {'logical_offset':start,'bytes':120,'SHA256':sha(d),'hex':d.hex()}

    def label(self, ref):
        if ref is None:
            return None
        if ref not in self.label_cache:
            reader.need(type(ref) is int and 0 <= ref < (1<<19)-1,'Actual non-sentinel primary labelref')
            offset = ref << self.label_shift
            reader.need(offset < self.pool_size,'Actual labelref within pool')
            b = self.image.logical('I053061A.GMP',self.pool_start+offset,min(64,self.pool_size-offset),'actual primary CP950 labelref '+str(ref))
            end = b.find(b'\0')
            reader.need(end >= 0,'No NUL within bounded64 label bytes; stop without truncation')
            text = b[:end].decode('cp950',errors='strict')
            self.label_cache[ref] = {'ref':ref,'actual_primary_label':text,'CP950_hex':b[:end].hex(),
                'actual_label_window_SHA256':sha(b),'logical_label_offset':self.pool_start+offset,
                'bounded_window_bytes':len(b)}
        return self.label_cache[ref]['actual_primary_label']

    def unpack(self, value, table, ID, raw_window, shift, purpose):
        # Reuse the pinned full descriptor decode; no field or raw flag normalization.
        r = reader.decode_parent(raw_window,shift,table)
        reader.need(r['raw_record_value'] == value,'Complete record significant bits')
        reader.need(r['mapordinal'] == 1,'Only actual one-map ordinal1 supported; no guessed GMP selection')
        r.update({'level':table['level'],'ID':ID,'record':table['level']<<28|ID,
            'actual_primary_label':self.label(r['primary_ref']),'purpose':purpose,
            'significant_rawbit_hex':value.to_bytes((table['stride']+7)//8,'little').hex(),
            'record_bit_length':table['stride'],'source_bit_shift':shift,
            'secondary_ref_kept_raw_not_used_as_alias':r['secondary_ref']})
        OBSERVATIONS[self.tag].append(r)
        return r

    def record(self, encoded, purpose):
        level,ID = encoded>>28,encoded&0xfffffff
        reader.need(level in self.tables and 1 <= ID <= self.tables[level]['count'],'Record bounds')
        t = self.tables[level]
        bit = (ID-1)*t['stride']
        byte,shift = divmod(bit,8)
        b = self.image.logical('00004171.MDR',t['start']+byte,(shift+t['stride']+7)//8,purpose)
        value = int.from_bytes(b,'little')>>shift&((1<<t['stride'])-1)
        return self.unpack(value,t,ID,b,shift,purpose)

    def exact_child(self, parent, token, maximum, stage):
        level,count,first = parent['next_level'],parent['child_count'],parent['first_child']
        if level == 0:
            return {'status':'finite_negative_terminal_parent','expected_exact_label':token,
                'parent_record':parent['record'],'actual_next_level':0,'children_read':0,'matching_records':[]}
        if not parent['level'] < level <= 6:
            return {'status':'gap_nonforward_or_unsupported_actual_childlevel','parent_record':parent['record'],
                    'raw_flags':parent['raw_flags'],'actual_next_level':level,'expected_exact_label':token}
        t = self.tables[level]
        reader.need(type(count) is int and 0 <= count <= maximum,'Selected child count exceeds declared per-stage bound')
        if not count:
            return {'status':'finite_negative_empty_child_range','expected_exact_label':token,
                'parent_record':parent['record'],'actual_next_level':level,'children_read':0,'matching_records':[]}
        reader.need(1 <= first <= first+count-1 <= t['count'],'Actual parent pointer/count range')
        bit = (first-1)*t['stride']
        byte,shift = divmod(bit,8)
        b = self.image.logical('00004171.MDR',t['start']+byte,(shift+count*t['stride']+7)//8,
            'actual selected child group stage'+str(stage)+' parent'+str(parent['record']))
        rawname = self.tag+'-stage'+str(stage)+'-selected-child-rawbits.bin'
        (OUT/rawname).write_bytes(b)
        whole = int.from_bytes(b,'little')
        matches = []
        before = len(OBSERVATIONS[self.tag])
        for ordinal in range(count):
            rbit = shift+ordinal*t['stride']
            at,s = divmod(rbit,8)
            n = (s+t['stride']+7)//8
            window = b[at:at+n]
            value = whole>>rbit&((1<<t['stride'])-1)
            r = self.unpack(value,t,first+ordinal,window,s,'exact primary-label child lookup stage'+str(stage))
            r['child_ordinal_under_selected_parent'] = ordinal
            r['selected_parent_record'] = parent['record']
            if r['actual_primary_label'] == token:
                matches.append(r)
        reader.need(len(OBSERVATIONS[self.tag])-before == count,'Every bounded child decoded and primary label inspected')
        group = {'stage':stage,'parent_record':parent['record'],'parent_full_raw_flags':parent['raw_flags'],
            'expected_exact_primary_label':token,'actual_childlevel':level,'first':first,'count':count,
            'last':first+count-1,'child_stride_bits':t['stride'],'initial_wholegroup_bit_shift':shift,
            'raw_span_bytes':len(b),'raw_span_SHA256':sha(b),'raw_span_artifact':rawname,
            'children_read':count,'all_primary_labels_inspected':True,
            'exact_match_count':len(matches),'exact_match_records':[r['record'] for r in matches],
            'suffix_normalization_alias_secondary_or_nearest_used':False}
        GROUPS[self.tag].append(group)
        return {'status':'exact_unique' if len(matches)==1 else 'finite_negative_no_exact_primary_label' if not matches else 'gap_multiple_exact_primary_labels',
            'group':group,'matching_records':matches,'expected_exact_label':token}


def diagnose(tag, previous, source):
    tree = Tree(tag,previous)
    parent = tree.record(805319491,'actual exact L3 ID13123 parent')
    reader.need(parent['actual_primary_label'] == '昌平路二段' and parent['next_level']==4 and parent['child_count']==594,'Actual exact street root594')
    steps, path = [], [parent]
    for stage,token in enumerate(TOKENS,1):
        got = tree.exact_child(parent,token,594 if stage==1 else 1023,stage)
        steps.append(got)
        if got['status'] != 'exact_unique':
            return {'status':got['status'],'exact_path_labels_reached':[r['actual_primary_label'] for r in path],
                'stopped_expected_exact_label':token,'actual_path_records':[r['record'] for r in path],
                'path_records_with_full_rawbits':path,'steps':steps,'actual_directory':tree.directory,
                'matching_final_or_ambiguous_records':got.get('matching_records',[]),
                'label_cache':list(tree.label_cache.values()),'source_floor_hold_unchanged':True,
                'negative_scope':'Only this exact street record, selected parent ranges and exact primary labels in this image; no whole-Taiwan absence claim.'}
        parent = got['matching_records'][0]
        path.append(parent)
    terminal = parent['next_level']==0 and parent['child_count']==0
    return {'status':'existing_exact_terminal_leaf_found' if terminal else 'gap_exact39_label_not_terminal_under_actual_flags',
        'exact_path_labels_reached':[r['actual_primary_label'] for r in path],
        'actual_path_records':[r['record'] for r in path],'path_records_with_full_rawbits':path,
        'steps':steps,'actual_directory':tree.directory,'label_cache':list(tree.label_cache.values()),
        'exact39_rawpoint_comparison':compare_point(parent,source),
        'source_floor_hold_unchanged':True,'existing_leaf_only_not_new_address_or_formal_route_success':True}


def save_progress(status, source, exception=None):
    for tag in ['v2','v3']:
        (OUT/('observed-records-'+tag+'.jsonl')).write_text(''.join(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n' for x in OBSERVATIONS[tag]))
    closure = []
    for im in IMAGES:
        closure.append({'path':str(im.path.relative_to(ROOT)),'readonly_source_handle_closed':im.f.closed,
            'stat_before':im.before,'stat_after':reader.stat(im.path),'unchanged':im.before==reader.stat(im.path)})
    proof = {'schema':'bounded_existing_country_v2_v3_exact_address_path_diagnostic/v1','status':status,
        'results':RESULTS,'source_summary':source,'source_floor_unit_hold_released':False,
        'normal_input_pins':NORMAL_PINS,'actual_IMG_read_bytes':sum(x['bytes'] for x in reader.READS),
        'actual_IMG_read_operations':len(reader.READS),'global_IMG_limit':reader.LIMIT,
        'actual_FILE_read_journal':reader.READS,'selected_groups':GROUPS,'source_handles':closure,
        'destination_handles':'Path.write_text/write_bytes close every newly scoped output; no IMG or device destination handle is opened.',
        'old_IMG_complete_hash_not_recomputed':True,'native_CPU_instructions':0,'compile_commands':0,
        'source21_nodes_PBF_groups_gzip_fulltree_or_fullGMP_not_read':True,
        'new_IMG_DB_labelref_recordID_or_install_created':False,
        'source_floor_hold_and_formal_address_route_alias_validation_not_changed':True,
        'flags':{k:False for k in ['source_released','formal_address_accepted','v3_road_bug_fixed','fullTaiwan_complete',
            'installable','device_verified','App_complete','native_backend_owner','STOP_DONE','phone_A2DP','speaker']},
        'exception':exception,'seal_after_completion_or_budget_frontier':True}
    if all(r.get('status')=='existing_exact_terminal_leaf_found' for r in RESULTS.values()) and len(RESULTS)==2:
        a = RESULTS['v2']['exact39_rawpoint_comparison']['leaf_native24']
        b = RESULTS['v3']['exact39_rawpoint_comparison']['leaf_native24']
        proof['two_existing_exact39_leaves_comparison'] = {'v2_native24':a,'v3_native24':b,
            'same_raw24':a==b,'v3_minus_v2_raw24':[b[i]-a[i] for i in range(2)],
            'existing_tree_diagnostic_only':True}
    write('proof.json',proof)
    return proof


def main():
    manifest = json.loads((OUT/'reader-dependency-manifest.json').read_text())
    reader.need(sha((OUT/'bounded_ap_reader_v1.py').read_bytes())==manifest['new_reader_SHA256'],'New isolated reader hash')
    prior = load_pin(OLD/'actual-profile-parent-proof.json','267fc5401fd0193800f249a7f9b814f29d5c8209a92c4559d3daafc7d46a4b7e')
    summary = load_pin(OLD/'scope-proof.json','c923d38221233491179edbe7ba2e524f6f507b86414bb2a445bbc6fd309cd6b0')
    source = {'source_group':172188,'sourcepoint':summary['sourcepoint'],'native24':summary['native24'],
        'separate_floor_unit_nodes':summary['separate_floor_unit_nodes'],'source_metadata_hold':True,
        'summary_only_no21node_source_or_capture_reopened':True}
    exception = None
    try:
        for tag in ['v2','v3']:
            RESULTS[tag] = diagnose(tag,prior['results'][tag],source)
    except Exception as exc:
        exception = {'error':str(exc),'traceback':traceback.format_exc()}
    finally:
        for f in reader.OPEN_HANDLES:
            if not f.closed:
                f.close()
    for im in IMAGES:
        reader.need(im.before==reader.stat(im.path),'Source IMG changed')
    proof = save_progress('bounded_diagnostic_completed' if exception is None else 'bounded_diagnostic_gap_saved',source,exception)
    print(json.dumps({'status':proof['status'],'per_image':{k:{'status':v['status'],'path_labels':v['exact_path_labels_reached'],
            'record_path':v['actual_path_records'],'stopped_label':v.get('stopped_expected_exact_label'),
            'point':v.get('exact39_rawpoint_comparison')} for k,v in RESULTS.items()},
        'actual_IMG_bytes':proof['actual_IMG_read_bytes'],'read_operations':len(reader.READS),
        'groups':{k:[{'level':g['actual_childlevel'],'count':g['count'],'shift':g['initial_wholegroup_bit_shift'],'matches':g['exact_match_count']} for g in v] for k,v in GROUPS.items()},
        'all_source_handles_closed':all(f.closed for f in reader.OPEN_HANDLES),'native_CPU_instructions':0,
        'source_floor_hold_unchanged':True,'exception':exception and exception['error']},ensure_ascii=False))
    if exception:
        raise SystemExit(1)


if __name__=='__main__':
    main()
