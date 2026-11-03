"""Integer-only capacity arithmetic; no scanner/image or firmware access."""

CAPACITY=134217728
OLD_METADATA=73728
BLOCK=4096
BLOCKS_PER_PART=240
STRIDES={4:128,5:126,6:68}

def ceildiv(value,unit):
    assert isinstance(value,int) and value>=0 and isinstance(unit,int) and unit>0
    return (value+unit-1)//unit

def packed_bytes(count,stride):
    return ceildiv(count*stride,8)

def plan(counts,current_lower_bytes,current_MDR_bytes,component_sizes):
    assert set(counts)==set(STRIDES)==set(current_lower_bytes)
    assert len(component_sizes)==6 and '00004171.MDR' in component_sizes
    base=current_MDR_bytes-sum(current_lower_bytes.values())
    assert base>=0 and component_sizes['00004171.MDR']==current_MDR_bytes
    lower={i:packed_bytes(counts[i],STRIDES[i]) for i in STRIDES}
    newmdr=base+sum(lower.values())
    sizes=dict(component_sizes);sizes['00004171.MDR']=newmdr
    blocks={name:ceildiv(size,BLOCK) for name,size in sizes.items()}
    parts={name:ceildiv(number,BLOCKS_PER_PART) for name,number in blocks.items()}
    rows=1+sum(parts.values())
    metamin=ceildiv(BLOCK+rows*512,BLOCK)*BLOCK
    metadata=max(OLD_METADATA,metamin)
    image=metadata+sum(blocks.values())*BLOCK
    return dict(lower_table_bytes_after=lower,MDR_nonlower_base_bytes=base,
                MDR_bytes_after=newmdr,MDR_bytes_removed=current_MDR_bytes-newmdr,
                component_4K_block_counts=blocks,FAT_component_part_counts=parts,
                root_plus_component_FAT_rows=rows,minimal_4K_metadata_bytes=metamin,
                conservative_4K_metadata_bytes=metadata,
                projected_minimum_4K_IMG_bytes=metamin+sum(blocks.values())*BLOCK,
                projected_conservative_4K_IMG_bytes=image,
                declared_original_4K_capacity=CAPACITY,
                capacity_margin_conservative=CAPACITY-image,
                fits_4K_capacity_arithmetic=image<=CAPACITY)

def minimum_L4_row_savings(counts,current_lower_bytes,current_MDR_bytes,components):
    # Ceil packing/block/FAT/metadata terms all monotonically decrease as
    # positive128-bit L4 rows are removed. Binary search finds the exact first
    # fitting count, then adjacent arithmetic witnesses establish minimality.
    def after(savings):
        changed=dict(counts);changed[4]-=savings
        return plan(changed,current_lower_bytes,current_MDR_bytes,components)
    initial=after(0)
    assert not initial['fits_4K_capacity_arithmetic']
    assert after(counts[4])['fits_4K_capacity_arithmetic']
    low,high=0,counts[4]
    while low<high:
        mid=(low+high)//2
        if after(mid)['fits_4K_capacity_arithmetic']:high=mid
        else:low=mid+1
    answer=low
    previous=after(answer-1)
    fitting=after(answer)
    assert not previous['fits_4K_capacity_arithmetic']
    assert fitting['fits_4K_capacity_arithmetic']
    return dict(exact_minimum_L4_rows_saved=answer,L4_significant_bytes_saved=answer*16,
                previous_rows_saved=answer-1,previous_plan=previous,fitting_plan=fitting,
                initial_plan=initial,
                metadata_saving_bytes=initial['conservative_4K_metadata_bytes']-
                                      fitting['conservative_4K_metadata_bytes'],
                MDR_allocated_blocks_saved=initial['component_4K_block_counts']['00004171.MDR']-
                                          fitting['component_4K_block_counts']['00004171.MDR'],
                assumption='Only128-bit L4 row count decreases; other retained counts/component bytes/widths unchanged',
                record_deletion_eligibility_or_native_reference_safety_proved=False)
