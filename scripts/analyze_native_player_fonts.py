#!/usr/bin/env python3
"""Read exact embedded sfnt tables from verified MAIN; no device access."""
import hashlib,json,struct
from analyze_native_sections import NativeImage,ROOT,EXPECTED


def cmap_glyph(data,code):
    count=struct.unpack_from('>H',data,2)[0];results=[]
    for n in range(count):
        platform,encoding,offset=struct.unpack_from('>HHI',data,4+8*n)
        if platform not in [0,3]:continue
        form=struct.unpack_from('>H',data,offset)[0];glyph=None
        if form==4 and code<=0xffff:
            length=struct.unpack_from('>H',data,offset+2)[0];segs=struct.unpack_from('>H',data,offset+6)[0]//2
            ends=offset+14;starts=ends+2*segs+2;deltas=starts+2*segs;ranges=deltas+2*segs
            for k in range(segs):
                end=struct.unpack_from('>H',data,ends+2*k)[0];start=struct.unpack_from('>H',data,starts+2*k)[0]
                if start<=code<=end:
                    delta=struct.unpack_from('>h',data,deltas+2*k)[0];rng=struct.unpack_from('>H',data,ranges+2*k)[0]
                    if not rng:glyph=(code+delta)&0xffff
                    else:
                        pos=ranges+2*k+rng+2*(code-start)
                        assert offset<=pos<offset+length
                        value=struct.unpack_from('>H',data,pos)[0];glyph=(value+delta)&0xffff if value else 0
                    break
            if glyph is None:glyph=0
        elif form==12:
            groups=struct.unpack_from('>I',data,offset+12)[0];glyph=0
            for k in range(groups):
                start,end,base=struct.unpack_from('>III',data,offset+16+12*k)
                if start<=code<=end:glyph=base+code-start;break
        if glyph is not None:results.append({'platform':platform,'encoding':encoding,'format':form,'glyph':glyph})
    return results


def main():
    im=NativeImage();table=im.runtime_to_load(0xf088b0,13*16);fonts=[]
    for n in range(13):
        pointer,kind,size,flags=struct.unpack('<4I',im.read(table+16*n,16))
        row={'index':n,'pointer':hex(pointer),'kind':kind,'size':size,'flags':hex(flags)}
        if kind==2:
            data=im.read(pointer,size);assert data[:4]==b'\x00\x01\x00\x00'
            count=struct.unpack_from('>H',data,4)[0];tables={}
            for k in range(count):
                tag,checksum,offset,length=struct.unpack_from('>4sIII',data,12+16*k)
                assert offset+length<=len(data)
                tables[tag.decode()]={'checksum':hex(checksum),'offset':offset,'length':length}
            cmap=tables['cmap'];cmap_data=data[cmap['offset']:cmap['offset']+cmap['length']]
            row.update(sfnt_sha256=hashlib.sha256(data).hexdigest(),tables=tables,
                selected_unicode_cmap={hex(ord(c)):cmap_glyph(cmap_data,ord(c))for c in ' Pi播放器'})
        else:row['external_family_name']=im.read(pointer,150).split(b'\0',1)[0].decode('ascii')
        fonts.append(row)
    proof={'MAIN_sha256':EXPECTED,'descriptor_table':'0xf088b0','descriptor_count':13,'descriptor_stride':16,
        'embedded_sfnt_indices':[r['index']for r in fonts if r['kind']==2],'fonts':fonts,
        'external_font_bytes_not_included_in_this_proof':True,'Chinese_UI_rendering_verified':False,'device_io':False}
    out=ROOT/'staging/native-player-text/embedded-font-tables.json';out.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'evidence':str(out.relative_to(ROOT)),'embedded_indices':proof['embedded_sfnt_indices'],
        'size_bytes':[r['size']for r in fonts if r['kind']==2]}))


if __name__=='__main__':main()
