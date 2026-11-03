#!/usr/bin/env python3
"""Only bounded actual v2 source profile + explicit8K capacity binding.

No append supplier, complete MDR/IMG, source ledger or device operation.
"""
import datetime
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0,str(HERE))
import current_profile_cow_writer as w


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    output = HERE/'actual-current-source-bounded-proof.json'
    w.need(not output.exists(),'Refuse overwrite current source proof')
    planner = ROOT/'staging/navigation-native-lane-tree-overlay-plan-v1'
    seal_raw = (planner/'seal.json').read_bytes();seal = json.loads(seal_raw)
    plan_raw = (planner/'capacity-and-width-plan.json').read_bytes()
    pin = next(row for row in seal['files'] if row['path'] == str((planner/'capacity-and-width-plan.json').relative_to(ROOT)))
    w.need(len(plan_raw) == pin['bytes'] and sha(plan_raw) == pin['sha256'],'Frozen planner capacity source differs')
    planning = json.loads(plan_raw)
    w.need(planning['base_candidate_sha256'] == w.V2_SHA and planning['base_candidate_bytes'] == w.V2_BYTES,
           'Planner current image identity differs')
    supplier_calls = []
    def forbidden_supplier():
        supplier_calls.append('called')
        raise AssertionError('This source-profile scope may not consume actual append suppliers')
    appends = {}
    for level in (4,5,6):
        count = planning['clone_counts'][str(level)]+planning['new_leaf_counts'][str(level)]
        appends[level] = w.PackedAppend(level,count,count*w.STRIDES[level],forbidden_supplier)
    with (w.V2/'gmapprom1.img').open('rb') as stream:
        before = w.stat_tuple(stream);image = w.eight().Source4K(stream)
        adapter = w.Explicit8KAdapter.from_container(image)
        plan = w.plan_current_mdr(adapter.source,appends=appends)
        bound = plan.bind_container(adapter)
        after = w.stat_tuple(stream)
        w.need(before == after and adapter.source.unchanged() is True,'Actual source changed during bounded check')
        w.need(not supplier_calls,'Append supplier was consumed')
        w.need({str(i+1):t['count'] for i,t in enumerate(plan.new_tables)} == planning['proposed_table_counts'],
               'Planner final counts differ from actual current source plan')
        expected = planning['capacity_variants'][0]
        w.need(plan.size == expected['MDR_component_bytes'] and plan.new_directory_start == expected['MDR_directory_start'],
               'Actual-source MDR capacity arithmetic differs from planner')
        w.need(bound.capacity_plan['image_bytes'] == expected['explicit8K_estimated_bytes'],
               'Actual AP8K allocation differs from estimate')
        for i,t in enumerate(plan.old_tables,1):
            p = planning['current_tables'][str(i)]
            w.need(all(t[k] == p[k] for k in ('start','bytes','stride','count','widths')),
                   'Actual current descriptor differs from sealed planner level'+str(i))
        components = [{'name':name,'size':image.components[name].size,'blocks':list(image.components[name].blocks),
                       'parts':[{'part':i,'allocation_blocks':len(w.eight()._base.StreamIMG._blocks(image,row)),
                                 'nonallocation_metadata_sha256':sha(w.eight().nonallocation_metadata(row))}
                                for i,row in enumerate(image.components[name].rows)]} for name in image.order]
        source_layout = {'schema':'garmin-native-current-ap4k-source-layout/v1','block_bytes':4096,
                         'source_v2':{'path':str((w.V2/'gmapprom1.img').relative_to(ROOT)),'bytes':w.V2_BYTES,'sha256':w.V2_SHA,
                                      'whole_SHA_inherited_from_completed_v2_readback':True},
                         'metadata_bytes':image.directory_end,'directory_start':image.directory_start,
                         'header_hex':image.header.hex(),'prefix_0_to_dirStart_sha256':sha(image.prefix),
                         'components':components,'tables':[dict(level=i+1,**t) for i,t in enumerate(plan.old_tables)]}
        with (HERE/'actual-current-source-layout.json').open('x') as out:
            json.dump(source_layout,out,indent=2,sort_keys=True);out.write('\n')
        with (HERE/'actual-current-source-read-receipts.json').open('x') as out:
            json.dump(image.read_log,out,indent=2,sort_keys=True);out.write('\n')
        compact_capacity = {k:v for k,v in bound.capacity_plan.items() if k != 'allocations'}
        proof = {'schema':'actual-current-profile-bounded-source-and-explicit8K-binding/v1',
                 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'all_assigned_checks_passed':True,
                 'writer_sha256':sha((HERE/'current_profile_cow_writer.py').read_bytes()),
                 'planner_seal_sha256':sha(seal_raw),'planner_capacity_sha256':sha(plan_raw),
                 'source_seal_sha256':w.V2_SEAL_SHA,'source_image_sha256':w.V2_SHA,
                 'source_stat_before':before,'source_stat_after':after,'source_stats_unchanged':True,
                 'whole_source_hash_recomputed':False,'actual_physical_reads':len(image.read_log),
                 'actual_physical_bytes_read':sum(r['bytes'] for r in image.read_log),
                 'maximum_physical_read_bytes':max(r['bytes'] for r in image.read_log),
                 'actual_current_L3_sha256':plan.report['original_L3_sha256'],
                 'actual_current_lower_table_final_unused_bits':{str(level):(-t['count']*t['stride'])%8
                                                              for level,t in ((4,plan.old_tables[3]),(5,plan.old_tables[4]),(6,plan.old_tables[5]))},
                 'current_112bit_L3_and_23bit_first_verified':True,'no_L3_width_expansion':True,
                 'actual_selected_L3_ranges_supplied_in_this_scope':0,
                 'producer_required_root_count':7650,'prior_v2_selected_subset_count':6366,
                 'plan':plan.report,'explicit8K_capacity_plan':compact_capacity,'actual_append_suppliers_consumed':False,
                 'large_append_or_MDR_or_IMG_output_produced':False,'source_ledger_or_PBF_read':False,
                 'native_CPU_executed':False,'device_IO':False,'checksum_rule_or_device_acceptance_verified':False,
                 'limitations':['Bounded descriptor/L3/profile and capacity check, not all current table content or new closure payload validation.',
                                'Actual full output component/tree preservation remains a future separate integration readback.',
                                'Checksum byte15 zero follows the sealed adapter; actual AP checksum rule and device acceptance unknown.']}
    with output.open('x') as out:
        json.dump(proof,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'all_assigned_checks_passed':True,'reads':proof['actual_physical_reads'],
                      'bytes_read':proof['actual_physical_bytes_read'],'MDR_bytes':plan.size,
                      'explicit8K_IMG_bytes':bound.capacity_plan['image_bytes'],'supplier_consumed':bool(supplier_calls)}))


if __name__ == '__main__':
    main()
