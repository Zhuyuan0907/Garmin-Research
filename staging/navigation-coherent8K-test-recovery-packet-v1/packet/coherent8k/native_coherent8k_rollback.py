#!/usr/bin/env python3
"""Portable same-bundle coherent8K -> declared old-v3 view -> strict STOCK.

No workspace path lookup, device IO, file opening, writing or CLI. Caller owns
its rb source. Small recipe/control objects are loaded by the pinned installer.
"""
import hashlib
import json
import native_8k_stock_restore as old
import coherent_header_overlay as overlay

CONTROL_BINDING_SHA='f475233c965eec527ea333ddfac46b281f493d1467a87645f455f8218261d481'
COHERENT_SHA='9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'
VIRTUAL_V3_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
STOCK_SHA='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
CANDIDATE_BYTES=153346048
STOCK_BYTES=96739328
OLD_BINDING_SHA='0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89'


def require(ok,message):
    if not ok:raise ValueError(message)


class ReceiptSink:
    """Append/extend consumer; keeps counts, rolling hash and no per-block list."""
    def __init__(self):
        self.count=0;self.bytes=0;self.purposes={};self._sha=hashlib.sha256()
    def append(self,row):
        require(type(row) is dict and type(row.get('bytes')) is int and row['bytes']>=0
                and type(row.get('purpose')) is str,'Invalid strict-helper read receipt')
        require(self.count<100000,'Bounded strict-helper receipt count')
        self.count+=1;self.bytes+=row['bytes'];key=row['purpose']
        self.purposes[key]=self.purposes.get(key,0)+row['bytes']
        self._sha.update((json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode())
    def extend(self,rows):
        for row in rows:self.append(row)
    def summary(self):
        return {'append_count':self.count,'logical_bytes':self.bytes,'purposes':dict(self.purposes),
                'canonical_receipt_stream_sha256':self._sha.hexdigest(),'retained_per_block_receipt_list':False}


def prepare_objects(recipe):
    require(type(recipe) is dict and set(recipe)=={'stock','binding','control'},'Exact coherent portable recipe objects')
    stock,binding,c=recipe['stock'],recipe['binding'],recipe['control']
    require(type(stock) is old.StockRecipe and stock.fixture is False,'Pinned production stock recipe required')
    require(type(c) is dict and hashlib.sha256((json.dumps(c,ensure_ascii=False,indent=2)+'\n').encode()).hexdigest()==CONTROL_BINDING_SHA,
            'Pinned coherent overlay binding changed')
    require(c['schema']=='garmin-AP-coherent8K-inverse-overlay-stock-restore/v1' and c['control']=='eightK_end_mirror',
            'Only fixed coherent8K mirror control supported')
    require(c['candidate']=={'bytes':CANDIDATE_BYTES,'sha256':COHERENT_SHA,'block_bytes':8192}
            and c['virtual_old_v3']['bytes']==CANDIDATE_BYTES and c['virtual_old_v3']['sha256']==VIRTUAL_V3_SHA
            and c['virtual_old_v3']['binding_sha256']==OLD_BINDING_SHA
            and c['stock']['bytes']==STOCK_BYTES and c['stock']['sha256']==STOCK_SHA,'Actual/virtual/stock identity split')
    require(stock.data['original_bytes']==STOCK_BYTES and stock.data['original_sha256']==STOCK_SHA,
            'Exact closed stock target required')
    require(type(binding) is dict and binding==old.prepare_restore_binding(stock,binding['candidate_layout']),
            'Strict virtual-old-v3 stock binding changed')
    require(binding['candidate_layout']['candidate_bytes']==CANDIDATE_BYTES
            and binding['candidate_layout']['candidate_sha256']==VIRTUAL_V3_SHA,'Old binding stays virtual-old-v3')
    corrected=bytes.fromhex(c['inverse_header']['corrected_header_hex'])
    original=bytes.fromhex(c['inverse_header']['original_header_hex'])
    require(len(original)==len(corrected)==512 and old._expected_header(bytes.fromhex(stock.data['original_prefix_hex'])[:4096],8192)[:512]==original,
            'Inverse header matches unchanged helper exact profile')
    require(hashlib.sha256(corrected).hexdigest()==c['inverse_header']['corrected_sha256']
            and hashlib.sha256(original).hexdigest()==c['inverse_header']['original_sha256']
            and c['inverse_header']['window_bytes']==512 and c['inverse_header']['changed_offsets']==[452],
            'Pinned actual corrected/inverse header windows')
    spec=overlay._OverlaySpec(CANDIDATE_BYTES,corrected,original,COHERENT_SHA,VIRTUAL_V3_SHA)
    # Avoid overlay.prepare_fixed_inputs(): that original preflight loader uses workspace paths.
    return overlay.FixedInputs(old,stock,binding,spec,(),c)


def verified_view(stream,recipe):
    return overlay.verified_eightk_overlay(stream,prepare_objects(recipe))


def reconstructed_stock_hash(stream,recipe):
    inputs=prepare_objects(recipe);view=overlay.verified_eightk_overlay(stream,inputs);sink=ReceiptSink()
    value=old.reconstructed_stock_hash(view,inputs.stock,inputs.old_binding,sink)
    view._stable();view.receipt['stock_hash_verified']=True
    require(value==STOCK_SHA,'Exact coherent-control STOCK hash mismatch')
    return {'sha256':value,'bytes':STOCK_BYTES,'inverse_view_receipt':dict(view.receipt),'read_receipts':sink.summary()}


def restored_stock_blocks(stream,recipe):
    inputs=prepare_objects(recipe);view=overlay.verified_eightk_overlay(stream,inputs);sink=ReceiptSink()
    yield from old.restored_stock_blocks(view,inputs.stock,inputs.old_binding,sink)
    view._stable()
