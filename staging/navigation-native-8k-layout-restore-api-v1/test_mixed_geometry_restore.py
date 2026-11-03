#!/usr/bin/env python3
"""NEW small independent six-component fixtures; no previous suite or IMG."""
import copy
from datetime import datetime,timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode=True
import native_8k_stock_restore as api

HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def check(ok,message):
    if not ok:raise AssertionError(message)


def pattern(length,seed):return bytes((i*37+seed+(i>>5))&255 for i in range(length))


def header():
    raw=bytearray(pattern(4096,21));raw[0]=0;raw[16:23]=b'DSKIMG\0'
    raw[64]=8;raw[97]=9;raw[98]=3
    struct.pack_into('<H',raw,0x18,16);struct.pack_into('<H',raw,0x5f,16)
    struct.pack_into('<H',raw,0x63,32768);struct.pack_into('<I',raw,0x1ca,262144)
    return bytes(raw)


def encode_container(components,block,stock_header,fragmented=False,unused=False):
    """Independent fixture encoder; no writer or API parser generates bytes."""
    counts={n:(len(x)+block-1)//block for n,x in components.items()}
    row_count=1+sum((n+239)//240 for n in counts.values())
    metadata=((4096+row_count*512+block-1)//block)*block
    block_ids=list(range(metadata//block,metadata//block+sum(counts.values())))
    if fragmented:block_ids=block_ids[::2]+block_ids[1::2]
    cursor=0;items={}
    for n in api.NAMES:
        c=counts[n];items[n]={'size':len(components[n]),'blocks':block_ids[cursor:cursor+c],'parts':(c+239)//240};cursor+=c
    size=(metadata//block+sum(counts.values())+int(unused))*block
    raw=bytearray([0xE7]*size);h=bytearray(stock_header)
    if block==8192:
        h[15]=0;h[98]=4
        struct.pack_into('<H',h,0x18,32);struct.pack_into('<H',h,0x5f,32)
        struct.pack_into('<I',h,0x1ca,524288)
    raw[:4096]=h;raw[4096:metadata]=bytes(metadata-4096)
    def row(at,name,size,blocks,root=False,part=0):
        r=bytearray(512);r[0]=1
        r[1:12]=b' '*11 if root else name.split('.')[0].encode().ljust(8,b' ')+name.split('.')[1].encode().ljust(3,b' ')
        struct.pack_into('<I',r,12,size);r[16]=3 if root else 0;struct.pack_into('<H',r,17,part)
        r[19:32]=b'fixture-meta!'
        struct.pack_into('<240H',r,32,*(blocks+[65535]*(240-len(blocks))))
        raw[at:at+512]=r
    row(4096,'.',metadata,list(range(metadata//block)),True)
    at=4608
    for i,n in enumerate(api.NAMES):
        item=items[n]
        for part,start in enumerate(range(0,len(item['blocks']),240)):
            row(at,n,item['size'] if part==0 else 0,item['blocks'][start:start+240],part=part);at+=512
        content=components[n]
        for index,b in enumerate(item['blocks']):
            part=content[index*block:(index+1)*block];raw[b*block:b*block+len(part)]=part
            # Distinct source4K tails versus future8K tails test exact padding.
            if len(part)<block:raw[b*block+len(part):(b+1)*block]=bytes([0xA0+i if block==4096 else 0xE7])*(block-len(part))
    if unused:raw[-block:]=pattern(block,199)
    return bytes(raw),items,metadata


def bit_records(count,stride,seed):
    # Give each record leading11 so a COW append consumes old zero padding.
    mask=(1<<stride)-1;value=0
    for i in range(count):
        record=(((seed+i*31)*0x123456789ABCDEF)|3)&mask
        value|=record<<(i*stride)
    return value.to_bytes((count*stride+7)//8,'little')


def table_bytes_and_mdr(counts,stock=False):
    tables=[None]*6;parts={};cursor=824
    for level in (6,5,4,3,2,1):
        stride=api.LOWER_STRIDES.get(level,111 if stock and level==3 else 112 if level==3 else 122)
        body=bit_records(counts[level],stride,level*83)
        widths=api.WIDTHS[level].copy()
        if stock and level==3:widths[0]=22
        t={'start':cursor,'bytes':len(body),'count':counts[level],'stride':stride,'widths':widths,'flags':api.FLAGS[level].copy()}
        tables[level-1]=t;parts[level]=body;cursor+=len(body)
    h=bytearray(pattern(772,77));struct.pack_into('<H',h,0,772);h[2:12]=b'GARMIN MDR'
    struct.pack_into('<4I',h,600,cursor,120,20,1)
    directory=bytearray()
    for t in tables:
        w=t['widths'];flags=t['flags']
        a=w[4]|w[3]<<6|w[2]<<12|w[0]<<18|w[1]<<24|flags[0]<<30|flags[1]<<31
        b=w[5]|w[6]<<11|w[7]<<17
        directory+=struct.pack('<5I',t['start'],t['bytes'],t['stride'],a,b)
    mdr=bytes(h)+pattern(52,31)+b''.join(parts[level] for level in (6,5,4,3,2,1))+bytes(directory)
    check(len(mdr)==cursor+120,'Independent fixture native directory layout')
    return mdr,tables,parts,cursor


def fixtures(continuations=False):
    old_counts={1:2,2:4,3:4,4:8,5:4,6:4}
    v2_counts={1:2,2:4,3:4,4:11,5:5,6:6}
    new_counts={1:2,2:4,3:4,4:17,5:9,6:9}
    old_mdr,old_tables,old_parts,old_dir=table_bytes_and_mdr(old_counts,True)
    v2_mdr,v2_tables,v2_parts,v2_dir=table_bytes_and_mdr(v2_counts)
    new_mdr,tables,new_parts,new_dir=table_bytes_and_mdr(new_counts)
    unchanged={'00004171.MD2':pattern(240,3),'00004171.SRT':pattern(9001,11),
        'I053061A.GMP':pattern(9007,25),'I053061A.SRT':pattern(8203,71),'MAPSOURC.MPS':pattern(138,94)}
    if continuations:unchanged['00004171.SRT']=pattern(240*8192+37,11)
    old_components={n:old_mdr if n==api.MDR else unchanged[n] for n in api.NAMES}
    v2_components={n:v2_mdr if n==api.MDR else unchanged[n] for n in api.NAMES}
    new_components={n:new_mdr if n==api.MDR else unchanged[n] for n in api.NAMES}
    h=header();original,old_fat,old_meta=encode_container(old_components,4096,h,True,True)
    v2,v2_fat,v2_meta=encode_container(v2_components,4096,h,False,False)
    candidate,new_fat,new_meta=encode_container(new_components,8192,h,True,False)
    tails={};unused={}
    for name,item in old_fat.items():
        remainder=item['size']%4096
        if remainder:tails[name]=original[item['blocks'][-1]*4096+remainder:(item['blocks'][-1]+1)*4096].hex()
    used=set(range(old_meta//4096))|{b for item in old_fat.values() for b in item['blocks']}
    for b in set(range(len(original)//4096))-used:unused[str(b)]=original[b*4096:(b+1)*4096].hex()
    ranges=[{'original_hex':old_mdr[:772].hex(),'length':772},{'candidate_offset':772,'length':52}]
    for level in (6,5,4):ranges.append({'candidate_offset':v2_tables[level-1]['start'],'length':len(old_parts[level])})
    ranges.extend([{'original_hex':old_parts[3].hex(),'length':len(old_parts[3])},
        {'candidate_offset':v2_tables[1]['start'],'length':len(old_parts[2])+len(old_parts[1])},
        {'original_hex':old_mdr[old_dir:old_dir+120].hex(),'length':120}])
    recipe={'schema':'garmin-native-layout-restore/synthetic-mixed-v1','fixture_profile':api.FIXTURE_PROFILE,
        'original_bytes':len(original),'original_sha256':sha(original),'candidate_bytes':len(v2),'candidate_sha256':sha(v2),
        'original_metadata_bytes':old_meta,'original_prefix_hex':original[:old_meta].hex(),
        'original_components':old_fat,'candidate_components':v2_fat,'MDR_ranges':ranges,
        'original_tail_hex':tails,'original_unused_blocks_hex':unused}
    recipe_raw=gzip.compress((json.dumps(recipe,ensure_ascii=False,separators=(',',':'))+'\n').encode(),mtime=0)
    declared_components=[]
    at=4608
    for name in api.NAMES:
        x=new_fat[name]
        parts=[]
        for part,start in enumerate(range(0,len(x['blocks']),240)):
            parts.append({'part':part,'size':x['size'] if part==0 else 0,'blocks':x['blocks'][start:start+240],
                'row_hex':candidate[at:at+512].hex()});at+=512
        declared_components.append({'name':name,'size':x['size'],'blocks':x['blocks'],
            'parts':parts})
    for i,t in enumerate(tables,1):t['level']=i
    descriptor={'schema':api.DESCRIPTOR_SCHEMA,'profile':api.CONTAINER_PROFILE,'block_bytes':8192,
        'candidate_bytes':len(candidate),'candidate_sha256':sha(candidate),'metadata_bytes':new_meta,
        'metadata_prefix_sha256':sha(candidate[:new_meta]),'source_v2':{'bytes':len(v2),'sha256':sha(v2)},
        'components':declared_components,'tables':tables}
    return original,v2,candidate,recipe_raw,descriptor,old_parts,v2_parts,new_parts


def main():
    check(not(HERE/'focused-proof.json').exists(),'Refuse overwrite NEW focused proof')
    started=datetime.now(timezone.utc).isoformat();t0=time.monotonic()
    original,v2,candidate,recipe_raw,descriptor,old_parts,v2_parts,new_parts=fixtures()
    stock=api.load_synthetic_fixture_recipe(recipe_raw);binding=api.prepare_synthetic_fixture_binding(stock,descriptor)
    receipts=[];blocks=list(api.restored_synthetic_fixture_blocks(io.BytesIO(candidate),stock,binding,receipts))
    restored=b''.join(blocks)
    check(restored==original and sha(restored)==sha(original),'Exact physical original4K bytes including all padding and unused blocks')
    check(len(restored)==len(original) and all(len(x)==4096 for x in blocks),'No surviving extra8K tail or changed block stride')
    check(candidate[:4096]!=original[:4096] and restored[:4096]==original[:4096],'Original header/checksum restored exactly')
    check(restored[:8192]==original[:8192],'Original FAT restored exactly')
    check(v2_parts[5][-1]!=new_parts[5][len(v2_parts[5])-1],'Real fixture uses both previously unused currentL5 tail bits')
    check(int.from_bytes(new_parts[5],'little')&((1<<(5*126))-1)==int.from_bytes(v2_parts[5],'little'),
          'CurrentL5 significant prefix preserved despite changed last byte')
    for level in (4,5,6):check(new_parts[level][:len(old_parts[level])]==old_parts[level],'Each original stock lower table remains a byte prefix')
    check(9*68%8==4 and new_parts[6][-1]>>4==0,'FutureL6 final4 unused bits stay zero')
    # All component8K tails may vary; they must not contaminate stock4K tails.
    altered=bytearray(candidate)
    for item in descriptor['components']:
        remainder=item['size']%8192
        if remainder:altered[item['blocks'][-1]*8192+remainder:(item['blocks'][-1]+1)*8192]=b'\xCC'*(8192-remainder)
    altered_blocks=list(api.restored_synthetic_fixture_blocks(io.BytesIO(altered),stock,binding))
    check(b''.join(altered_blocks)==original,'Candidate8K tail bytes never replace original4K stored padding')
    guards=[]
    def reject(name,call):
        try:call()
        except (ValueError,KeyError,ZeroDivisionError) as e:guards.append({'name':name,'rejected':True,'exception':type(e).__name__,'message':str(e)})
        else:raise AssertionError('Guard accepted '+name)
    def changed_descriptor(key,value):
        d=copy.deepcopy(descriptor);d[key]=value;return api.prepare_synthetic_fixture_binding(stock,d)
    for key,value in [('schema','unknown'),('profile',api.PROFILE),('block_bytes',4096),
        ('source_v2',{'bytes':len(v2),'sha256':'1'*64}),('candidate_bytes',len(candidate)-1)]:
        reject('descriptor_'+key,lambda k=key,v=value:changed_descriptor(k,v))
    reject('fixture_rejected_by_production_binding',lambda:api.prepare_restore_binding(stock,descriptor))
    reject('fixture_rejected_by_production_generator',lambda:list(api.restored_stock_blocks(io.BytesIO(candidate),stock,binding)))
    bad=copy.deepcopy(binding);bad['stock_recipe_sha256']='0'*64
    reject('closed_recipe_binding_tamper',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(candidate),stock,bad)))
    bad=copy.deepcopy(binding);bad['MDR_candidate_offsets_by_original_range_index'][3]+=1
    reject('binding_offset_tamper',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(candidate),stock,bad)))
    bad=copy.deepcopy(descriptor);bad['components'][0]['blocks'][0]=bad['components'][1]['blocks'][0]
    reject('descriptor_block_alias',lambda:api.prepare_synthetic_fixture_binding(stock,bad))
    bad=copy.deepcopy(descriptor);bad['tables'][4]['stride']=127
    reject('lower_width_change_not_inverse_transformed',lambda:api.prepare_synthetic_fixture_binding(stock,bad))
    bad=copy.deepcopy(descriptor);bad['metadata_prefix_sha256']='0'*64;b=api.prepare_synthetic_fixture_binding(stock,bad)
    reject('actual_metadata_SHA_mismatch',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(candidate),stock,b)))
    for name,offset,value in [('actual4K_exponent',98,3),('unsupported_header_byte',100,candidate[100]^1),
        ('invalid_checksum_transformation',15,1),('root_allocation_alias',4096+32,1),
        ('nonzero_inactive_FAT',4608+6*512+20,1)]:
        raw=bytearray(candidate);raw[offset]=value
        reject(name,lambda x=raw:list(api.restored_synthetic_fixture_blocks(io.BytesIO(x),stock,binding)))
    reject('truncated8K_candidate',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(candidate[:-1]),stock,binding)))
    raw=bytearray(candidate);mdr=descriptor['components'][1];at=mdr['blocks'][0]*8192+descriptor['tables'][0]['start']+descriptor['tables'][0]['bytes']+4*20+8
    struct.pack_into('<I',raw,at,127)
    reject('actual_directory_stride_tamper',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(raw),stock,binding)))
    # Content corruption is detected by original digest comparison, not by an
    # invented claim that bounded metadata proves unchanged component bytes.
    raw=bytearray(candidate);at=descriptor['components'][3]['blocks'][0]*8192+42;raw[at]^=1
    reject('component_corruption_fails_exact_original_SHA_at_EOF',lambda:list(api.restored_synthetic_fixture_blocks(io.BytesIO(raw),stock,binding)))
    production_path=ROOT/'staging/navigation-country-layout-restore-v2/restore-layout.json.gz'
    before=production_path.stat();production=api.load_stock_recipe(production_path)
    check(production_path.stat()==before and not production.fixture,'Pinned closed production recipe metadata loaded, no fullIMG')
    source=ROOT/'scripts/native_address_layout_restore_v1.py';raw=source.read_bytes()
    check(sha(raw)=='1f9d85290426cf7d696dd6a79a5e152100fd8eec17a73a803f65f0c56ba54695','Closed production helper source pin')
    closed_proof_path=ROOT/'staging/navigation-country-layout-restore-v2/proof.json';closed_raw=closed_proof_path.read_bytes();closed=json.loads(closed_raw)
    check(closed['all_assigned_checks_passed'] and closed['recipe_sha256']==api.RECIPE_SHA
          and closed['exact_original_hash_reconstructed']==api.STOCK_SHA,'Inherited closed production proof, never replayed')
    mutation=copy.deepcopy(production);mutation.data['MDR_ranges'][3]['length']-=1
    reject('loaded_production_recipe_mutation',lambda:api.prepare_restore_binding(mutation,descriptor))
    # A second finite fixture exercises actual two-part8K and three-part4K
    # component allocations; metadata and all component bytes remain small.
    o2,v2_2,c2,r2,d2,_,_,_=fixtures(True)
    s2=api.load_synthetic_fixture_recipe(r2);b2=api.prepare_synthetic_fixture_binding(s2,d2)
    restored2=b''.join(api.restored_synthetic_fixture_blocks(io.BytesIO(c2),s2,b2))
    check(restored2==o2 and s2.data['original_components']['00004171.SRT']['parts']==3
          and len(d2['components'][2]['parts'])==2,'Exact multibody4K/8K FAT continuation fixture')
    bad=copy.deepcopy(d2);bad['components'][2]['parts'][1]['part']=2
    reject('FAT_continuation_index_gap',lambda:api.prepare_synthetic_fixture_binding(s2,bad))
    bad=copy.deepcopy(d2);part=bad['components'][2]['parts'][1];row=bytearray.fromhex(part['row_hex']);row[19]^=1;part['row_hex']=row.hex()
    reject('distinct_continuation_nonallocation_metadata',lambda:api.prepare_synthetic_fixture_binding(s2,bad))
    bad=copy.deepcopy(d2);bad['components'][2]['parts'][1]['blocks'][0]=65535
    reject('reserved_continuation_block',lambda:api.prepare_synthetic_fixture_binding(s2,bad))
    descriptor_path=HERE/'fixture-descriptor.json';descriptor_path.write_bytes(api.canonical(descriptor))
    binding_path=HERE/'fixture-binding.json';binding_path.write_bytes(api.canonical(binding))
    check(api.load_output_descriptor(descriptor_path,sha(descriptor_path.read_bytes()))==descriptor,'Small externally pinned descriptor loader')
    check(api.load_restore_binding(binding_path,sha(binding_path.read_bytes()))==binding,'Small externally pinned restore binding loader')
    reject('sealed_descriptor_wrong_SHA',lambda:api.load_output_descriptor(descriptor_path,'0'*64))
    reject('sealed_binding_wrong_SHA',lambda:api.load_restore_binding(binding_path,'0'*64))
    proof={'schema':'new-mixed4K8K-exact-stock-restore-API-focused-proof/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t0,
        'all_assigned_checks_passed':True,'test_script_sha256':sha(Path(__file__).read_bytes()),
        'helper_sha256':sha((HERE/'native_8k_stock_restore.py').read_bytes()),
        'synthetic_fixture':{'original4K_bytes':len(original),'current4K_v2_bytes':len(v2),'future8K_bytes':len(candidate),
            'original4K_sha256':sha(original),'current4K_v2_sha256':sha(v2),'future8K_sha256':sha(candidate),
            'exact_restored4K_sha256':sha(restored),'exact_all_original_bytes_equal':True,
            'original_block_count':len(blocks),'emitted_block_bytes':4096,'candidate_block_bytes':8192,
            'six_components':list(api.NAMES),'fragmented_allocations':True,'original_unused_blocks':1,
            'all_original_component_padding_retained':True,'candidate8K_tails_varied_without_affecting_restore':True,
            'no_extra8K_tail_survived':True,'originalL3_restored_from_recipe':True,
            'currentL5_final2padding_bits_consumed':True,'currentL5_significant_prefix_preserved':True,
            'stockL4L5L6_prefixes_byte_exact':True,'futureL6_final4padding_bits_zero':True,
            'candidate_content_corruption_does_not_pass_original_digest':True,
            'recipe_compressed_bytes':len(recipe_raw),'recipe_sha256':sha(recipe_raw),
            'descriptor_canonical_sha256':sha(api.canonical(descriptor)),'binding_canonical_sha256':sha(api.canonical(binding)),
            'read_receipts':receipts},
        'guard_count':len(guards),'guards':guards,
        'second_continuation_fixture':{'original4K_bytes':len(o2),'future8K_bytes':len(c2),
            'original4K_SHA':sha(o2),'restored4K_SHA':sha(restored2),'all_bytes_equal':True,
            'component_original4K_parts':3,'component_future8K_parts':2,
            'original_metadata_bytes':s2.data['original_metadata_bytes'],'future_metadata_bytes':d2['metadata_bytes'],
            'same_explicit_block_geometry_schema':True},
        'closed_production_inputs':[
            {'path':str(production_path.relative_to(ROOT)),'bytes':before.st_size,'sha256':production.compressed_sha256,
             'uncompressed_sha256':production.uncompressed_sha256,'source_stat_unchanged':True},
            {'path':str(source.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw)},
            {'path':str(closed_proof_path.relative_to(ROOT)),'bytes':len(closed_raw),'sha256':sha(closed_raw)}],
        'closed_original_reconstruction_proof_inherited':True,'closed_old_suite_replayed':False,
        'full_original_or_candidate_IMG_opened':False,'future_actual8K_candidate_exists_or_acceptance_claimed':False,
        'full_backup_copied':False,'full_restored_IMG_written':False,'device_IO':False,
        'USB_ZIP_canonical_installer_modified':False,'header_checksum_rule_known':False,'device8K_acceptance_verified':False,
        'limits':['Small synthetic six-component exact-byte controls only; production stock recipe/schema pin checked without actual IMG reads.',
            'Future actual8K descriptor/metadata and reconstructed stock hash must be bound and executed after an actual candidate exists.',
            'No inverse lower bit-width transformation supported; any width/stride change is rejected.']}
    (HERE/'focused-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    (HERE/'fixture-descriptor.json').write_bytes(api.canonical(descriptor))
    (HERE/'fixture-binding.json').write_bytes(api.canonical(binding))
    print(json.dumps({'all_assigned_checks_passed':True,'guard_count':len(guards),'fixture_original4K_bytes':len(original),
        'fixture_future8K_bytes':len(candidate),'exact_original_sha256':sha(restored),
        'proof_sha256':sha((HERE/'focused-proof.json').read_bytes()),'fullIMG_or_device_IO':False}))


if __name__=='__main__':main()
