#!/usr/bin/env python3
"""Strict read-only explicit AP8K -> exact STOCK4K reconstruction API.

The production recipe loader accepts only the already sealed stock/v2 recipe.
A new small candidate descriptor binds one future explicit8K COW layout. No
file output, installation, checksum correction, bit-width conversion or CLI.
"""
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct

BLOCK4 = 4096
BLOCK8 = 8192
MDR = '00004171.MDR'
NAMES = ('00004171.MD2', MDR, '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')
RECIPE_SHA = '6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'
RECIPE_BYTES = 879499
RECIPE_PLAIN_BYTES = 1779988
STOCK_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
STOCK_BYTES = 96739328
V2_SHA = '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
V2_BYTES = 128356352
PROFILE = 'stock-1352-8.00-v2-COW-explicit8K/v1'
FIXTURE_PROFILE = 'synthetic-six-component-mixed4K8K/v1'
DESCRIPTOR_SCHEMA = 'garmin-native-ap-explicit8k-cow-layout/v1'
CONTAINER_PROFILE = 'AP8K-9+4-32768blocks-524288sectors'
BINDING_SCHEMA = 'garmin-native-8k-stock-layout-restore/v1'
LOWER_STRIDES = {4:128, 5:126, 6:68}
STOCK_COUNTS = {4:2133948, 5:2341096, 6:1973316}
FUTURE_COUNTS = {4:4896236, 5:3077845, 6:2062771}
WIDTHS = {1:[16,9,24,19,1,10,0,0], 2:[16,9,24,19,1,10,0,0],
          3:[23,9,24,19,1,12,0,0], 4:[22,9,24,19,1,10,0,0],
          5:[21,9,24,19,1,9,0,0], 6:[0,0,24,19,1,0,0,0]}
FLAGS = {1:[1,1], 2:[1,1], 3:[1,0], 4:[1,1], 5:[1,1], 6:[1,0]}


def require(ok, message):
    if not ok: raise ValueError(message)


def integer(value, message, low=0, high=0xffffffff):
    require(type(value) is int and low <= value <= high, message)
    return value


def digest(raw): return hashlib.sha256(raw).hexdigest()


def digest_field(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None, 'Invalid SHA256 field')
    return value


def canonical(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()


def identity(stream):
    try:
        s=os.fstat(stream.fileno())
        return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
    except (AttributeError,OSError,io.UnsupportedOperation): return None


def _read(stream, at, count):
    integer(at,'Invalid physical read offset');integer(count,'Invalid physical read length',0,1024*1024)
    stream.seek(at);raw=stream.read(count)
    require(len(raw)==count,'Truncated bounded physical read')
    return raw


def _expected_header(stock_header, block):
    require(len(stock_header)==4096,'Stored stock header shape')
    if block==BLOCK4:return stock_header
    h=bytearray(stock_header)
    h[15]=0
    struct.pack_into('<H',h,0x18,32);struct.pack_into('<H',h,0x5f,32)
    h[0x62]=4;struct.pack_into('<I',h,0x1ca,524288)
    return bytes(h)


def parse_layout(stream, file_size, block_bytes, expected_header=None):
    """Bounded strict six-component AP metadata parser; no generic IMG fallback."""
    require(block_bytes in (BLOCK4,BLOCK8),'Unsupported allocation geometry')
    integer(file_size,'Invalid aligned AP byte length',block_bytes,32768*block_bytes)
    require(file_size%block_bytes==0,'Partial physical final block')
    header=_read(stream,0,4096)
    require(header[0]==0 and header[16:23]==b'DSKIMG\0','Unsupported IMG signature/XOR')
    require((header[97],header[98],header[64])==(9,3 if block_bytes==BLOCK4 else 4,8),
            'Unexpected exact AP block exponent/directory sector')
    require(struct.unpack_from('<H',header,0x18)[0]==(16 if block_bytes==BLOCK4 else 32)
            and struct.unpack_from('<H',header,0x5f)[0]==(16 if block_bytes==BLOCK4 else 32)
            and struct.unpack_from('<H',header,0x63)[0]==32768
            and struct.unpack_from('<I',header,0x1ca)[0]==(262144 if block_bytes==BLOCK4 else 524288),
            'Unsupported AP declared geometry profile')
    if expected_header is not None:require(header==expected_header,'Header differs from explicitly supported transformation')
    root=_read(stream,4096,512)
    require(root[0]==1 and root[1:12]==b' '*11 and root[16]==3
            and struct.unpack_from('<H',root,17)[0]==0,'Unsupported root FAT record')
    end=struct.unpack_from('<I',root,12)[0]
    require(4608<=end<=1024*1024 and end%block_bytes==0 and end<=file_size,'Invalid bounded metadata span')
    prefix=header+root+_read(stream,4608,end-4608)
    root_slots=struct.unpack_from('<240H',root,32)
    metadata_blocks=end//block_bytes
    require(metadata_blocks<=240 and list(root_slots)==list(range(metadata_blocks))+[65535]*(240-metadata_blocks),
            'Root FAT must allocate exactly the metadata blocks')
    components={};fat_parts={};used=set(range(metadata_blocks));order=[];seen_empty=False;previous=None
    for at in range(4608,end,512):
        row=prefix[at:at+512]
        if row[0]==0:
            require(row==bytes(512),'Unsupported nonzero inactive FAT row')
            seen_empty=True;continue
        require(not seen_empty and row[0]==1 and row[16]!=3,'Unexpected/gapped FAT record')
        try:name=row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
        except UnicodeDecodeError:raise ValueError('Non-ASCII FAT component name')
        require(name in NAMES,'Unexpected AP component')
        part=struct.unpack_from('<H',row,17)[0];length=struct.unpack_from('<I',row,12)[0]
        if name not in components:
            require(part==0 and length>0,'Invalid first FAT part')
            require(name==NAMES[len(order)],'Unexpected six-component order')
            order.append(name);components[name]={'size':length,'blocks':[],'parts':0};fat_parts[name]=[]
        item=components[name]
        require(previous in (None,name) or part==0,'Noncontiguous component continuation')
        require(part==item['parts'] and (part==0 or length==0),'FAT continuation number/size mismatch')
        item['parts']+=1;previous=name
        slots=struct.unpack_from('<240H',row,32);trailing=False;actual=0
        for b in slots:
            if b==65535:trailing=True;continue
            require(not trailing and b not in used and (b+1)*block_bytes<=file_size,
                    'FAT alias, reserved gap or allocation out of file')
            used.add(b);item['blocks'].append(b);actual+=1
        require(actual>0 and (part==0 or len(item['blocks'])>240),'Empty or unnecessary continuation')
        nonallocation=row[:12]+row[16:17]+row[19:32]
        if fat_parts[name]:require(nonallocation==bytes.fromhex(fat_parts[name][0]['row_hex'])[:12]
                +bytes.fromhex(fat_parts[name][0]['row_hex'])[16:17]
                +bytes.fromhex(fat_parts[name][0]['row_hex'])[19:32],
                'Distinct continuation metadata unsupported by explicit8K writer contract')
        fat_parts[name].append({'part':part,'size':length,'blocks':list(slots[:actual]),'row_hex':row.hex()})
    require(tuple(order)==NAMES,'Incomplete six AP components')
    for item in components.values():
        require(len(item['blocks'])==(item['size']+block_bytes-1)//block_bytes,'Component allocation count mismatch')
        require(item['parts']==(len(item['blocks'])+239)//240,'Component part count mismatch')
    return {'prefix':prefix,'metadata_bytes':end,'components':components,'FAT_parts':fat_parts,'block_bytes':block_bytes,
            'unused_blocks':sorted(set(range(file_size//block_bytes))-used)}


def logical_read(stream, component, block_bytes, offset, length):
    integer(offset,'Invalid logical offset');integer(length,'Invalid bounded logical length',0,65536)
    require(offset+length<=component['size'],'Logical read outside component')
    out=[]
    while length:
        index,inside=divmod(offset,block_bytes);count=min(length,block_bytes-inside)
        out.append(_read(stream,component['blocks'][index]*block_bytes+inside,count))
        offset+=count;length-=count
    return b''.join(out)


@dataclass(frozen=True)
class StockRecipe:
    data: dict
    compressed_sha256: str
    compressed_bytes: int
    uncompressed_sha256: str
    fixture: bool


def _decode_recipe(raw, fixture):
    require(len(raw)<=1024*1024,'Compact compressed recipe exceeds bound')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as f:plain=f.read(2*1024*1024+1)
    require(len(plain)<=2*1024*1024,'Compact recipe JSON exceeds bound')
    r=json.loads(plain)
    require(r['schema']==('garmin-native-layout-restore/synthetic-mixed-v1' if fixture else 'garmin-native-layout-restore/v1'),
            'Unsupported stock recipe schema')
    if not fixture:
        require(len(raw)==RECIPE_BYTES and digest(raw)==RECIPE_SHA and len(plain)==RECIPE_PLAIN_BYTES,
                'Production supports only the pinned closed v2 STOCK recipe')
        require(r['original_bytes']==STOCK_BYTES and r['original_sha256']==STOCK_SHA
                and r['candidate_bytes']==V2_BYTES and r['candidate_sha256']==V2_SHA,
                'Recipe original/current-v2 identity mismatch')
    else:
        require(r.get('fixture_profile')==FIXTURE_PROFILE and r['original_bytes']<=8*1024*1024,
                'Only explicitly named small synthetic recipe supported')
    prefix=bytes.fromhex(r['original_prefix_hex'])
    parsed=parse_layout(io.BytesIO(prefix),r['original_bytes'],BLOCK4)
    require(len(prefix)==r['original_metadata_bytes']==parsed['metadata_bytes']
            and parsed['components']==r['original_components'],'Stored STOCK header/FAT binding')
    ranges=r['MDR_ranges'];require(len(ranges)==8,'Expected exact eight-part stock MDR recipe')
    require(sum(integer(x['length'],'Invalid original range length',1) for x in ranges)==r['original_components'][MDR]['size'],
            'Original MDR range coverage mismatch')
    for i,x in enumerate(ranges):
        require(set(x)==({'length','original_hex'} if i in (0,5,7) else {'length','candidate_offset'}),
                'Unknown or shifted original MDR range role')
        if 'original_hex' in x:require(len(bytes.fromhex(x['original_hex']))==x['length'],'Stored original bytes length mismatch')
    require(ranges[0]['length']==772 and ranges[7]['length']==120,'Stock header/directory recipe shape')
    for name,item in r['original_components'].items():
        rem=item['size']%BLOCK4
        require((name in r['original_tail_hex'])==bool(rem),'Original component tail coverage')
        if rem:require(len(bytes.fromhex(r['original_tail_hex'][name]))==BLOCK4-rem,'Original padding length mismatch')
    require(set(r['original_unused_blocks_hex'])==set(map(str,parsed['unused_blocks'])),'Original unused physical blocks coverage')
    return StockRecipe(r,digest(raw),len(raw),digest(plain),fixture)


def load_stock_recipe(path):
    """Load only the pinned879,499-byte production recipe; never a full image."""
    path=Path(path);before=path.stat();require(before.st_size==RECIPE_BYTES,'Closed recipe file size mismatch')
    raw=path.read_bytes();require(path.stat()==before,'Recipe changed while read')
    return _decode_recipe(raw,False)


def load_synthetic_fixture_recipe(raw):
    """Distinct test-only named schema, never accepted by production API."""
    return _decode_recipe(raw,True)


def _descriptor(stock, descriptor):
    require(type(stock) is StockRecipe,'Expected loaded pinned stock recipe object')
    r=stock.data;d=descriptor
    if not stock.fixture:
        require(stock.compressed_sha256==RECIPE_SHA and stock.compressed_bytes==RECIPE_BYTES
                and r['original_bytes']==STOCK_BYTES and r['original_sha256']==STOCK_SHA
                and r['candidate_bytes']==V2_BYTES and r['candidate_sha256']==V2_SHA,
                'Production recipe object must retain exact closed STOCK/v2 identity')
    fields={'schema','profile','block_bytes','candidate_bytes','candidate_sha256','metadata_bytes',
            'metadata_prefix_sha256','source_v2','components','tables'}
    require(type(d) is dict and set(d)==fields,'Unsupported explicit8K descriptor fields')
    require(d['schema']==DESCRIPTOR_SCHEMA and d['profile']==CONTAINER_PROFILE,
            'Unsupported explicit8K restore descriptor profile/schema')
    require(d['block_bytes']==BLOCK8,'Block geometry mismatch')
    require(type(d['source_v2']) is dict and set(d['source_v2'])=={'bytes','sha256'}
            and d['source_v2']['bytes']==r['candidate_bytes'] and d['source_v2']['sha256']==r['candidate_sha256'],
            'Future candidate does not derive from pinned current v2 source')
    digest_field(d['candidate_sha256']);digest_field(d['metadata_prefix_sha256'])
    integer(d['candidate_bytes'],'Invalid explicit8K physical size',BLOCK8,32768*BLOCK8)
    require(d['candidate_bytes']%BLOCK8==0,'Explicit8K candidate physical size misaligned')
    integer(d['metadata_bytes'],'Invalid explicit8K metadata span',BLOCK8,1024*1024)
    require(d['metadata_bytes']%BLOCK8==0 and d['metadata_bytes']<=d['candidate_bytes'],'Explicit8K metadata alignment/bounds')
    require(type(d['components']) is list and len(d['components'])==6
            and tuple(x.get('name') for x in d['components'])==NAMES,'Descriptor six components must retain exact order')
    owners=set(range(d['metadata_bytes']//BLOCK8))
    for item in d['components']:
        require(type(item) is dict and set(item)=={'name','size','blocks','parts'},'Unsupported component descriptor')
        name=item['name']
        integer(item['size'],'Invalid component bytes',1)
        require(type(item['blocks']) is list and len(item['blocks'])==(item['size']+BLOCK8-1)//BLOCK8,
                'Descriptor allocated count mismatch')
        require(type(item['parts']) is list and len(item['parts'])==(len(item['blocks'])+239)//240,'Descriptor part count mismatch')
        concatenated=[];metadata=None
        for index,part in enumerate(item['parts']):
            require(type(part) is dict and set(part)=={'part','size','blocks','row_hex'},'Unsupported FAT part descriptor')
            require(part['part']==index and part['size']==(item['size'] if index==0 else 0)
                    and type(part['blocks']) is list and 1<=len(part['blocks'])<=240,
                    'Declared FAT part index/size/allocation mismatch')
            require(index==len(item['parts'])-1 or len(part['blocks'])==240,'Short nonfinal FAT continuation')
            require(type(part['row_hex']) is str and re.fullmatch('[0-9a-f]{1024}',part['row_hex']) is not None,
                    'Invalid exact FAT row hex')
            row=bytes.fromhex(part['row_hex'])
            expected_name=name.split('.')[0].encode().ljust(8,b' ')+name.split('.')[1].encode().ljust(3,b' ')
            require(row[0]==1 and row[1:12]==expected_name and row[16]!=3
                    and struct.unpack_from('<I',row,12)[0]==part['size'] and struct.unpack_from('<H',row,17)[0]==index
                    and list(struct.unpack_from('<240H',row,32))==part['blocks']+[65535]*(240-len(part['blocks'])),
                    'Declared exact FAT row disagrees with name/part/size/blocks')
            observed=row[:12]+row[16:17]+row[19:32]
            require(metadata is None or metadata==observed,'Distinct nonallocation continuation metadata unsupported')
            metadata=observed;concatenated.extend(part['blocks'])
        require(concatenated==item['blocks'],'Descriptor component allocation is not exact concatenation of parts')
        for block in item['blocks']:
            integer(block,'Invalid explicit8K allocation block',0,65534)
            require(block not in owners and (block+1)*BLOCK8<=d['candidate_bytes'],'Descriptor allocation alias/bounds')
            owners.add(block)
        if name!=MDR:require(item['size']==r['original_components'][name]['size'],'Other five component size changed')
    require(owners==set(range(d['candidate_bytes']//BLOCK8)),'Unexpected unbound physical8K tails/unused blocks')
    tables=d['tables'];require(type(tables) is list and len(tables)==6,'Expected six native tables')
    cursor=r['MDR_ranges'][0]['length']+r['MDR_ranges'][1]['length']
    for level in (6,5,4,3,2,1):
        t=tables[level-1]
        require(type(t) is dict and set(t)=={'level','start','bytes','count','stride','widths','flags'}
                and t['level']==level,'Unsupported native table descriptor/order')
        stride=LOWER_STRIDES.get(level,112 if level==3 else 122)
        integer(t['count'],'Invalid table count',1,8388607)
        require(t['stride']==stride and t['bytes']==(t['count']*stride+7)//8
                and t['widths']==WIDTHS[level] and t['flags']==FLAGS[level],'Unsupported width/stride/flags or byte count')
        require(t['start']==cursor,'Noncontiguous supported native table order')
        cursor+=t['bytes']
        if level in LOWER_STRIDES:
            oldlength=r['MDR_ranges'][{6:2,5:3,4:4}[level]]['length']
            require(oldlength<=t['bytes'],'Future table cannot hold complete STOCK byte prefix')
            if not stock.fixture:
                require(t['count']==FUTURE_COUNTS[level] and oldlength*8==STOCK_COUNTS[level]*stride,
                        'Only explicit current future count/profile and bytealigned original prefix supported')
    require(cursor+120==d['components'][1]['size'],'Directory must follow L1 and end exact MDR component')
    if not stock.fixture:
        require([tables[i]['count'] for i in (0,1,2)]==[22,343,47870],'Stock admin/street ID table shape must remain')
        require(tables[1]['bytes']+tables[0]['bytes']==r['MDR_ranges'][6]['length'],'Original L1/L2 byte shape changed')
    require(tables[1]['bytes']+tables[0]['bytes']==r['MDR_ranges'][6]['length'],'L1/L2 exact rollback span changed')
    return d


def _binding(stock, descriptor):
    require(digest((json.dumps(stock.data,ensure_ascii=False,separators=(',',':'))+'\n').encode())==stock.uncompressed_sha256,
            'Loaded stock recipe data changed after verified read')
    d=_descriptor(stock,descriptor)
    offsets=[None,772,d['tables'][5]['start'],d['tables'][4]['start'],d['tables'][3]['start'],None,d['tables'][1]['start'],None]
    return {'schema':BINDING_SCHEMA,'profile':FIXTURE_PROFILE if stock.fixture else PROFILE,'stock_recipe_sha256':stock.compressed_sha256,
            'stock_recipe_bytes':stock.compressed_bytes,'original_bytes':stock.data['original_bytes'],
            'original_sha256':stock.data['original_sha256'],'candidate_layout':d,
            'MDR_candidate_offsets_by_original_range_index':offsets,
            'bit_width_inverse_transform_required':False,'device_acceptance_verified':False,
            'header_checksum_rule_known':False}


def prepare_restore_binding(stock, descriptor):
    require(type(stock) is StockRecipe and stock.fixture is False,'Production API requires pinned production stock recipe')
    return _binding(stock,descriptor)


def prepare_synthetic_fixture_binding(stock, descriptor):
    require(type(stock) is StockRecipe and stock.fixture is True,'Synthetic API requires explicitly named fixture recipe')
    return _binding(stock,descriptor)


def load_restore_binding(path, expected_sha256):
    """Read a small externally sealed descriptor/binding, with immutable stat."""
    digest_field(expected_sha256);path=Path(path);before=path.stat()
    require(before.st_size<=1024*1024,'Small binding descriptor exceeds bound')
    raw=path.read_bytes()
    require(digest(raw)==expected_sha256 and path.stat()==before,'Sealed binding content/stat mismatch')
    value=json.loads(raw);require(value.get('schema')==BINDING_SCHEMA,'Unsupported sealed binding schema')
    return value


def load_output_descriptor(path, expected_sha256):
    """Read only a small, externally sealed ACTUAL output descriptor."""
    digest_field(expected_sha256);path=Path(path);before=path.stat()
    require(before.st_size<=1024*1024,'Actual output descriptor exceeds bound')
    raw=path.read_bytes()
    require(digest(raw)==expected_sha256 and path.stat()==before,'Actual descriptor SHA/stat mismatch')
    value=json.loads(raw);require(value.get('schema')==DESCRIPTOR_SCHEMA,'Unsupported actual descriptor schema')
    return value


def _layouts_and_header(stream, stock, binding, log):
    require(binding==_binding(stock,binding['candidate_layout']),'Restore binding changed or unsupported')
    d=binding['candidate_layout'];stream.seek(0,2);size=stream.tell()
    require(size==d['candidate_bytes'],'Actual explicit8K candidate size mismatch')
    prefix=bytes.fromhex(stock.data['original_prefix_hex'])
    current=parse_layout(stream,size,BLOCK8,_expected_header(prefix[:4096],BLOCK8))
    expected_components={x['name']:{'size':x['size'],'blocks':x['blocks'],'parts':len(x['parts'])} for x in d['components']}
    expected_parts={x['name']:x['parts'] for x in d['components']}
    require(current['metadata_bytes']==d['metadata_bytes'] and digest(current['prefix'])==d['metadata_prefix_sha256']
            and current['components']==expected_components and current['FAT_parts']==expected_parts
            and not current['unused_blocks'],'Actual candidate metadata/FAT binding mismatch')
    log.append({'purpose':'actual8K_header_FAT','bytes':len(current['prefix']),'sha256':digest(current['prefix'])})
    header=logical_read(stream,current['components'][MDR],BLOCK8,0,772)
    require(struct.unpack_from('<H',header)[0]==772 and header[2:12]==b'GARMIN MDR','Actual MDR header shape')
    directory_start=d['tables'][0]['start']+d['tables'][0]['bytes']
    require(struct.unpack_from('<4I',header,600)==(directory_start,120,20,1),'Actual native directory header differs from descriptor')
    raw=logical_read(stream,current['components'][MDR],BLOCK8,directory_start,120)
    for level in range(1,7):
        start,length,stride,a,b=struct.unpack_from('<5I',raw,(level-1)*20)
        widths=[(a>>18)&63,(a>>24)&63,(a>>12)&63,(a>>6)&63,a&63,b&63,(b>>11)&63,(b>>17)&63]
        actual={'level':level,'start':start,'bytes':length,'count':length*8//stride,'stride':stride,'widths':widths,'flags':[(a>>30)&1,(a>>31)&1]}
        require(actual==d['tables'][level-1],'Actual native directory table differs from bound descriptor')
    log.extend([{'purpose':'actual_MDR_header','bytes':772,'sha256':digest(header)},
                {'purpose':'actual_MDR_directory','bytes':120,'sha256':digest(raw)}])
    return current


def _restored_blocks(stream, stock, binding, read_receipts):
    before=identity(stream);r=stock.data;log=read_receipts if read_receipts is not None else []
    current=_layouts_and_header(stream,stock,binding,log)
    prefix=bytes.fromhex(r['original_prefix_hex']);components=r['original_components'];owners={}
    for name,item in components.items():
        for index,block in enumerate(item['blocks']):
            require(block not in owners,'Original block allocation alias');owners[block]=(name,index)
    offsets=binding['MDR_candidate_offsets_by_original_range_index']
    ranges=r['MDR_ranges']
    def read_original_component(name, offset, length):
        if name!=MDR:
            raw=logical_read(stream,current['components'][name],BLOCK8,offset,length)
            log.append({'purpose':'unchanged_component','component':name,'offset':offset,'bytes':len(raw)})
            return raw
        out=[];position=0;remaining=length
        for index,x in enumerate(ranges):
            stop=position+x['length']
            if offset<stop and remaining:
                inside=offset-position;count=min(remaining,stop-offset)
                if offsets[index] is None:
                    part=bytes.fromhex(x['original_hex'])[inside:inside+count]
                else:
                    at=offsets[index]+inside;part=logical_read(stream,current['components'][name],BLOCK8,at,count)
                    log.append({'purpose':'original_MDR_byte_prefix_or_unchanged_span','range_index':index,
                                'candidate_offset':at,'bytes':len(part)})
                out.append(part);offset+=count;remaining-=count
            position=stop
        require(remaining==0,'Incomplete original MDR range reconstruction')
        return b''.join(out)
    restored_digest=hashlib.sha256()
    for block in range(r['original_bytes']//BLOCK4):
        if block*BLOCK4<len(prefix):raw=prefix[block*BLOCK4:(block+1)*BLOCK4]
        elif block in owners:
            name,index=owners[block];item=components[name];offset=index*BLOCK4;count=min(BLOCK4,item['size']-offset)
            raw=read_original_component(name,offset,count)
            if count<BLOCK4:raw+=bytes.fromhex(r['original_tail_hex'][name])
        else:raw=bytes.fromhex(r['original_unused_blocks_hex'][str(block)])
        require(len(raw)==BLOCK4,'Reconstructed block differs from exact stock4K size')
        restored_digest.update(raw)
        yield raw
    require(identity(stream)==before,'Candidate source changed during full generator consumption')
    require(restored_digest.hexdigest()==r['original_sha256'],'Exact original reconstruction SHA256 mismatch at EOF')


def restored_stock_blocks(candidate_stream, stock, binding, read_receipts=None):
    """Yield original4096-byte physical blocks; never writes a restored IMG.

    Consume through EOF to verify immutable input stat. Candidate SHA is an
    explicit inherited producer binding, not recomputed by this bounded API.
    Caller compares the streamed reconstruction digest to original_sha256.
    """
    require(type(stock) is StockRecipe and stock.fixture is False,'Production restore accepts only pinned closed stock recipe')
    require(identity(candidate_stream) is not None and getattr(candidate_stream,'mode',None)=='rb',
            'Production restore requires an actual read-only file with immutable stat')
    yield from _restored_blocks(candidate_stream,stock,binding,read_receipts)


def restored_synthetic_fixture_blocks(candidate_stream, stock, binding, read_receipts=None):
    require(type(stock) is StockRecipe and stock.fixture is True,'Synthetic restore accepts only named fixture recipe')
    yield from _restored_blocks(candidate_stream,stock,binding,read_receipts)


def reconstructed_stock_hash(candidate_stream, stock, binding, read_receipts=None):
    h=hashlib.sha256()
    for block in restored_stock_blocks(candidate_stream,stock,binding,read_receipts):h.update(block)
    require(h.hexdigest()==stock.data['original_sha256'],'Exact original reconstruction SHA256 mismatch')
    return h.hexdigest()
