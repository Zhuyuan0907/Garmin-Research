#!/usr/bin/env python3
"""Finite actual AP8K mapper; manual strict FAT, no host IMG writer/parser."""
import hashlib
from pathlib import Path
import struct

NAMES = ('00004171.MD2','00004171.MDR','00004171.SRT','I053061A.GMP','I053061A.SRT','MAPSOURC.MPS')


def need(ok,message):
    if not ok:
        raise ValueError(message)


def stat(path):
    s = Path(path).stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


class Candidate8K:
    def __init__(self,path,layout,expected_stat):
        self.path = Path(path);self.before = stat(path)
        need(self.before == expected_stat and not self.path.stat().st_mode & 0o222,'Completed readonly candidate identity differs')
        need(layout['schema'] == 'garmin-native-ap-explicit8k-cow-layout/v1' and
             layout['profile'] == 'AP8K-9+4-32768blocks-524288sectors','Strict AP8K descriptor profile')
        need(layout['block_bytes'] == 8192 and layout['candidate_bytes'] == self.before[2] and self.before[2]%8192 == 0,
             'Actual AP8K component/image size profile')
        self.block_size = 8192;self.log = [];self.stream = self.path.open('rb')
        try:
            header = self.physical(0,512,'actual_AP8K_header')
            need(header[0] == 0 and header[16:23] == b'DSKIMG\0' and header[65:72] == b'GARMIN\0' and
                 header[510:512] == b'\x55\xaa','Actual DSKIMG signatures')
            need(header[97:99] == b'\x09\x04' and header[15] == 0 and
                 struct.unpack_from('<H',header,0x18)[0] == struct.unpack_from('<H',header,0x5f)[0] == 32 and
                 struct.unpack_from('<H',header,0x63)[0] == 32768 and struct.unpack_from('<I',header,0x1ca)[0] == 524288,
                 'Exact explicit AP8K header allocation profile')
            need(self.before[2] <= 268435456,'Actual image exceeds declared AP8K capacity')
            start = header[64]*512;need(start == 4096,'Exact source directory start')
            root = self.physical(start,512,'actual_AP8K_root_row')
            end = struct.unpack_from('<I',root,12)[0]
            need(root[0] == 1 and root[1:12] == b' '*11 and root[16] == 3 and
                 struct.unpack_from('<H',root,17)[0] == 0,'Single exact root row')
            need(start+512 <= end <= 131072 and end%8192 == 0 and end == layout['metadata_bytes'],'Actual root metadata extent')
            prefix = self.physical(512,start-512,'actual_AP8K_unknown_header_prefix')
            rows = self.physical(start+512,end-start-512,'actual_AP8K_FAT_rows')
            metadata = header+prefix+root+rows
            need(hashlib.sha256(metadata).hexdigest() == layout['metadata_prefix_sha256'],'Actual complete metadata hash versus sealed descriptor')
            roots = self.blocks(root)
            need(roots == list(range(end//8192)) and len(roots) <= 240,'Exact root allocation')
            owned = set(roots);components = {};order = [];current = None
            for ordinal in range(0,len(rows),512):
                row = rows[ordinal:ordinal+512]
                if row[0] == 0:
                    need(row == bytes(512),'Nonzero unused FAT row');continue
                need(row[0] == 1 and row[16] != 3,'Unexpected active FAT/root continuation')
                name = row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
                part,size = struct.unpack_from('<H',row,17)[0],struct.unpack_from('<I',row,12)[0]
                if part == 0:
                    need(name in NAMES and name not in components and size > 0,'Exact six unique component names/sizes')
                    components[name] = {'bytes':size,'blocks':[],'parts':[]};order.append(name);current = name
                need(name == current and part == len(components[name]['parts']) and (part == 0 or size == 0),
                     'Continuation name/order/size mismatch')
                blocks = self.blocks(row);need(blocks,'Empty component continuation')
                need(all(b not in owned for b in blocks),'Allocation aliases another component/root')
                owned.update(blocks);components[name]['blocks'].extend(blocks)
                components[name]['parts'].append({'part':part,'size':size,'blocks':blocks,'row_hex':row.hex()})
            need(tuple(order) == NAMES and len(owned)*8192 == self.before[2],'Exact six-order/all physical blocks owned')
            for actual,pin in zip((components[n] for n in order),layout['components']):
                need(actual['bytes'] == pin['size'] and actual['blocks'] == pin['blocks'] and actual['parts'] == pin['parts'],
                     'Actual component FAT versus descriptor')
                need(len(actual['blocks']) == (actual['bytes']+8191)//8192 and len(actual['parts']) == (len(actual['blocks'])+239)//240,
                     'Exact allocation block/part counts')
            need(tuple(x['name'] for x in layout['components']) == NAMES,'Descriptor component order')
            self.extent = [start,end];self.components = components
            self.metadata_sha256 = hashlib.sha256(metadata).hexdigest();self.header_hex = header.hex()
        except BaseException:
            self.stream.close();raise

    def blocks(self,row):
        result = [];padding = False
        for value in struct.unpack_from('<240H',row,32):
            if value == 65535:
                padding = True;continue
            need(not padding and (value+1)*8192 <= self.before[2] and value not in result,'FAT sentinel/bounds/duplicate')
            result.append(value)
        return result

    def physical(self,offset,n,purpose):
        need(0 <= offset <= offset+n <= self.before[2] and n <= 131072,'Finite physical read range')
        self.stream.seek(offset);raw = self.stream.read(n)
        need(len(raw) == n,'Short actual physical read')
        self.log.append({'purpose':purpose,'physical_offset':offset,'bytes':n});return raw

    def read(self,name,offset,n,purpose):
        c = self.components[name]
        need(0 <= offset <= offset+n <= c['bytes'] and n <= 65536,'Finite logical read range')
        output = bytearray();mappings = [];cursor = offset
        while cursor < offset+n:
            block,within = divmod(cursor,8192);count = min(offset+n-cursor,8192-within)
            physical = c['blocks'][block]*8192+within
            output.extend(self.physical(physical,count,purpose))
            mappings.append({'logical_offset':cursor,'logical_block':block,'allocated_block':c['blocks'][block],
                             'physical_offset':physical,'bytes':count});cursor += count
        raw = bytes(output)
        return {'component':name,'offset':offset,'bytes':n,'sha256':hashlib.sha256(raw).hexdigest(),'hex':raw.hex(),'FAT_mapping':mappings},raw

    def close(self):
        self.stream.close();need(stat(self.path) == self.before,'Actual AP8K candidate changed during finite probe')
