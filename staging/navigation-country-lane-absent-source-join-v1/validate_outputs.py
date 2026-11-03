#!/usr/bin/env python3
"""Fresh own-output EOF/hash/order/provenance audit; no source/map/geometry rerun."""
from collections import Counter
from decimal import Decimal
import gzip
import hashlib
import json
from pathlib import Path

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
class Reader:
    def __init__(self,f):self.f=f;self.count=0;self.hash=hashlib.sha256()
    def read(self,n=-1):
        raw=self.f.read(n);self.count+=len(raw);self.hash.update(raw);return raw

def main():
    proof=json.loads((HERE/'proof.json').read_text());audits=[];geometry_held=Counter();readyparents=set();nodecounts=Counter()
    for category in ('ready','held','ready_parent_summary','joined_source_groups'):
        meta=proof['artifacts'][category];path=ROOT/meta['path'];before=path.stat();plain=hashlib.sha256();rows=0;prev=None
        with path.open('rb') as f:
            compressed=Reader(f)
            with gzip.GzipFile(fileobj=compressed) as stream:
                for line in stream:
                    plain.update(line);rows+=1;row=json.loads(line)
                    if category in ('ready','held'):
                        assert row['native_write_ready'] is False
                        house=row['house_label'];number=row['numeric_house'];parent=row['actual_parent']
                        order=(parent['record'],0 if number is not None else 1,number or 0,house)
                        assert prev is None or prev<order;prev=order
                        ids={ID for m in row['source_members'] for ID in m['source_ids']}
                        assert row['source_ids']==sorted(ids) and row['source_node_count']==len(ids)
                        assert row['source_group_ids']==[m['group_id'] for m in row['source_members']]
                        nodecounts[category+'_source_node_members']+=len(ids)
                        for m in row['source_members']:
                            assert m['native_parent']==parent
                            if m['coordinate_status']!='coordinate_ready_global_bounds':
                                assert m['coordinate_strings'] is None
                                assert row['selected_coordinate_strings'] is None and row['planned_raw24'] is None
                        if category=='ready':
                            assert not row['reasons'] and number==int(house[:-1]) and number>0
                            assert row['source_geometry_decision']['eligible'] is True
                            assert row['exact_raw24_geometry_decision']['eligible'] is True
                            assert {tuple(map(Decimal,m['coordinate_strings'])) for m in row['source_members']}=={tuple(map(Decimal,row['selected_coordinate_strings']))}
                            assert parent['raw_flags']&7==parent['next_leaf_level']
                            readyparents.add(parent['record'])
                        else:
                            assert row['reasons']
                            for label in ('source_geometry_decision','exact_raw24_geometry_decision'):
                                if row[label] is not None:geometry_held[label+':'+row[label]['status']]+=1
                    elif category=='ready_parent_summary':
                        ID=row['actual_parent']['record'];assert prev is None or prev<ID;prev=ID
            assert rows==meta['rows'] and compressed.count==meta['bytes'] and compressed.hash.hexdigest()==meta['sha256']
            assert plain.hexdigest()==meta['uncompressed_sha256']
        assert path.stat()==before
        audits.append({'category':category,'rows':rows,'compressed_and_plain_hashes_matched':True,'gzip_EOF_verified':True,'stat_unchanged':True})
    assert len(readyparents)==proof['ready_actual_parent_count']
    result={'all_own_output_audit_checks_passed':True,'audits':audits,'ready_numeric_order_verified':True,
        'ready_unique_parent_count':len(readyparents),'source_node_members':dict(nodecounts),'held_geometry_decisions':dict(geometry_held),
        'original_prepared_source_or_map_reopened':False,'old_geometry_or_CPU_suite_replayed':False}
    (HERE/'output-readback-proof.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
