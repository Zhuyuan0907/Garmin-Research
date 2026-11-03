"""Fresh integer capacity calculation; no producer imports or scanner/image I/O."""
from pathlib import Path
import hashlib,json

HERE=Path(__file__).resolve().parent
CAPTURE=HERE/'captured-inputs'
COUNTS={4:3781594,5:3074293,6:2062771}
STRIDE={4:128,5:126,6:68}
BASE=4870967
BLOCK=4096
CAPACITY=134217728
OLD_METADATA=73728

def up(n,d):
    assert isinstance(n,int) and n>=0 and isinstance(d,int) and d>0
    q,r=divmod(n,d)
    return q+bool(r)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(name):return json.loads((CAPTURE/name).read_text())
def save(name,data):
    p=HERE/name;p.write_text(json.dumps(data,indent=2)+'\n');return sha(p.read_bytes())

def geometry(saving,original_components):
    assert isinstance(saving,int) and 0<=saving<=COUNTS[5]
    counts=dict(COUNTS);counts[5]-=saving
    packed={level:up(counts[level]*STRIDE[level],8) for level in counts}
    mdr=BASE+sum(packed.values())
    sizes=dict(original_components);sizes['00004171.MDR']=mdr
    blocks={name:up(size,BLOCK) for name,size in sizes.items()}
    parts={name:up(count,240) for name,count in blocks.items()}
    fat_rows=1+sum(parts.values())
    metadata_min=up(BLOCK+fat_rows*512,BLOCK)*BLOCK
    metadata=max(OLD_METADATA,metadata_min)
    image=metadata+sum(blocks.values())*BLOCK
    return dict(L5_rows_saved=saving,retained_counts=counts,lower_packed_bytes=packed,
        lower_padding_bits={i:(-counts[i]*STRIDE[i])%8 for i in counts},
        MDR_bytes=mdr,component_logical_bytes=sizes,component_blocks=blocks,
        component_FAT_parts=parts,FAT_rows=fat_rows,minimal_metadata_bytes=metadata_min,
        metadata_bytes=metadata,IMG_bytes=image,capacity_bytes=CAPACITY,
        capacity_margin_bytes=CAPACITY-image,fits=image<=CAPACITY)

def main():
    summary=read('L4reuse-scope-summary.json')
    reported=read('L4reuse-capacity-arithmetic.json')
    prior=read('prior-capacity-math.json')
    checklist=read('prior-capacity-checklist.json')
    receipts=json.loads((HERE/'input-read-receipts.json').read_text())
    assert {int(k):v for k,v in summary['retained_counts_after_reuse'].items()}==COUNTS
    assert {int(k):v for k,v in reported['retained_lower_counts_after_reuse'].items()}==COUNTS
    assert prior['MDR_nonlower_base_bytes']==BASE
    originals=prior['current_component_logical_bytes']
    assert len(originals)==6
    baseline=geometry(0,originals)
    expected_components=dict(originals);expected_components['00004171.MDR']=baseline['MDR_bytes']
    assert baseline['component_logical_bytes']==expected_components==reported['component_sizes']
    assert baseline['MDR_bytes']==reported['MDR_bytes_after']==131330140
    assert baseline['IMG_bytes']==reported['projected_4K_IMG_bytes']==135438336
    assert baseline['metadata_bytes']==reported['4K_metadata_bytes']==77824
    assert baseline['FAT_rows']==reported['root_plus_component_FAT_rows']==143
    assert baseline['capacity_margin_bytes']==reported['capacity_margin']==-1220608
    assert baseline['component_blocks']==reported['component_4K_blocks']
    assert baseline['component_FAT_parts']==reported['component_FAT_parts']
    assert baseline['lower_packed_bytes']=={int(k):v for k,v in reported['lower_table_bytes_after'].items()}
    assert baseline['fits'] is False
    assert checklist['full_graph_record_bits_or_transitive_external_ABIs_independently_proved'] is False
    assert summary['falseflags']['IMG_constructed'] is False
    low,high=0,COUNTS[5]
    assert geometry(high,originals)['fits']
    steps=0
    while low<high:
        mid=(low+high)//2;steps+=1
        if geometry(mid,originals)['fits']:high=mid
        else:low=mid+1
    n=low
    previous=geometry(n-1,originals);fitting=geometry(n,originals)
    assert not previous['fits'] and fitting['fits']
    other_blocks=sum(v for name,v in fitting['component_blocks'].items() if name!='00004171.MDR')
    allowed_MDR_blocks=(CAPACITY-fitting['metadata_bytes'])//BLOCK-other_blocks
    allowed_MDR_bytes=allowed_MDR_blocks*BLOCK
    fixed_bytes=BASE+fitting['lower_packed_bytes'][4]+fitting['lower_packed_bytes'][6]
    allowed_L5_bytes=allowed_MDR_bytes-fixed_bytes
    max_L5_count=allowed_L5_bytes*8//STRIDE[5]
    closed_form=COUNTS[5]-max_L5_count
    assert n==closed_form==77245
    assert previous['retained_counts'][5]==2997049
    assert previous['MDR_bytes']==130113547 and previous['IMG_bytes']==134221824
    assert fitting['retained_counts'][5]==2997048
    assert fitting['MDR_bytes']==130113531 and fitting['IMG_bytes']==134217728
    assert fitting['component_blocks']['00004171.MDR']==31766
    assert previous['component_blocks']['00004171.MDR']==31767
    assert fitting['component_FAT_parts']['00004171.MDR']==previous['component_FAT_parts']['00004171.MDR']==133
    assert fitting['FAT_rows']==previous['FAT_rows']==142
    assert fitting['metadata_bytes']==previous['metadata_bytes']==baseline['metadata_bytes']==77824
    assert fitting['retained_counts'][4]==previous['retained_counts'][4]==COUNTS[4]
    assert fitting['retained_counts'][6]==previous['retained_counts'][6]==COUNTS[6]
    math=dict(schema='garmin-stock-L5-capacity-threshold-math/v1',
        method='Exact integer ceilings with monotone search and independent floor closed-form',
        bits_per_record=STRIDE,MDR_nonlower_base_bytes=BASE,
        all_five_original_component_logical_bytes={k:v for k,v in originals.items() if k!='00004171.MDR'},
        baseline=baseline,threshold_minus_one=previous,threshold=fitting,
        minimum_additional_L5_rows_saved=n,binary_search_steps=steps,
        independent_closed_form=dict(non_MDR_blocks=other_blocks,
            allowed_MDR_blocks=allowed_MDR_blocks,allowed_MDR_logical_bytes=allowed_MDR_bytes,
            fixed_L4_L6_and_base_bytes=fixed_bytes,allowed_L5_packed_bytes=allowed_L5_bytes,
            maximum_L5_count_floor8bytes_over126=max_L5_count,
            rows_saved=closed_form),
        L5_significant_packed_bytes_saved=baseline['lower_packed_bytes'][5]-fitting['lower_packed_bytes'][5],
        MDR_allocated_blocks_saved=baseline['component_blocks']['00004171.MDR']-fitting['component_blocks']['00004171.MDR'],
        metadata_allocated_bytes_saved=0,
        exact_capacity_margin_at_threshold=0,
        L4_and_L6_retention_counts_unchanged=True,
        safe_record_reuse_or_address_deletion_proved=False)
    mathsha=save('math.json',math)
    proof=dict(schema='garmin-stock-L5-capacity-threshold-independent-review/v1',
        all_assigned_checks_passed=True,review_kind='NUMERIC DATA only',
        source_summary_sha256=sha((CAPTURE/'L4reuse-scope-summary.json').read_bytes()),
        prior_capacity_math_sha256=sha((CAPTURE/'prior-capacity-math.json').read_bytes()),
        all_input_pins_and_stats_passed=True,retained_baseline_counts=COUNTS,
        packed_bits_to_bytes_ceil_recomputed=True,
        all_six_components_4K_block_ceil_and_FAT240parts_recomputed=True,
        root_plus_FATrow_metadata_ceil_and_max73728_applied=True,
        capacity_bytes=CAPACITY,baseline_MDR_bytes=131330140,
        baseline_IMG_bytes=135438336,baseline_excess_bytes=1220608,
        exact_minimum_additional_L5_rows_saved=77245,
        threshold_minus_one_L5_rows_saved=77244,
        threshold_minus_one_MDR_bytes=130113547,
        threshold_minus_one_MDR_blocks=31767,
        threshold_minus_one_IMG_bytes=134221824,
        threshold_L5_rows_remaining=2997048,
        threshold_MDR_bytes=130113531,threshold_MDR_blocks=31766,
        threshold_MDR_FAT_parts=133,threshold_FAT_rows=142,
        threshold_metadata_bytes=77824,threshold_IMG_bytes=134217728,
        metadata_bytes_unchanged_after_L5_savings=True,
        all_L4_and_L6_counts_and_five_other_components_unchanged=True,
        exact_minimality_checked_by_adjacent_cases_and_closed_form=True,
        safe_L5_reuse_deletion_addresses_graph_ABIs_not_proved=True,
        source_summary_actual_reuse_record_checks_inherited_not_rerun=True,
        original_capacity_not_platform_maximum=True,
        IMG_constructed_scanner_renderer_UI_route_install_or_v3_fix=False,
        external_artifact_bytes=receipts['external_artifact_bytes'],
        external_artifact_limit_bytes=98304,
        own_scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        shared_closed_scopes_sources_modes_report_or_device_mutations=0,
        all_handles_closed=True,math_sha256=mathsha)
    proofsha=save('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,
        exact_minimum_L5_rows_saved=n,threshold_minus_one_IMG_bytes=previous['IMG_bytes'],
        threshold_IMG_bytes=fitting['IMG_bytes'],threshold_MDR_bytes=fitting['MDR_bytes'],
        threshold_metadata_bytes=fitting['metadata_bytes'],
        proof_sha256=proofsha,external_artifact_bytes=receipts['external_artifact_bytes'],
        scanner_IMG_MAIN_PBF_CPU_guest_device=0)))

if __name__=='__main__':main()
