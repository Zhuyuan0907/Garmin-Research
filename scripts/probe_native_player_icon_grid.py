#!/usr/bin/env python3
"""Fast synthetic-catalog Grid probe; not a loader/integration proof."""
from pathlib import Path
import json,struct,hashlib,sys
from analyze_native_sections import NativeImage,ROOT
from emulate_native_player_external_fonts import BUILD
from probe_native_player_resources import GIR,INPUT,STAGE
from probe_native_player_resource_cache import ResourceCacheVM
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_player_menu_selection import SQL_OUT
from emulate_native_vpm_filesystem import require

def main():
    vm=ResourceCacheVM(NativeImage(),json.loads((ROOT/BUILD).read_text()));result=dict(device_io=False,sounds_emitted=False,full_integration_checkpoint=False)
    try:
        vm.invoke(0x395981,());vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,());vm.invoke(0x4de237,(1,))
        vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        record=vm.menu_records()[0];vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(record+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,));vm.set_cell(12,PLAYER_ID,0)
        grid=vm.invoke(0x3954cc,(0x420,));vm.invoke(0x546c95,(grid,0));rows=vm.grid_rows(grid)
        widget=int(rows[11]['widget'],16);rect=SQL_OUT+0x500;vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,220))
        vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0));vm.invoke(vm.word(vm.word(widget)+39*4),(widget,0))
        vm.invoke(vm.word(vm.word(grid)+9*4),(grid,1));tree=vm.tree(grid)
        selected=next(r for r in tree['children']if r['object']==hex(widget));label=next(r for r in selected['children']if r['vtable']=='0xc19058')
        text=vm.wide(vm.invoke(0x3927f5,(int(label['object'],16)+0x218,)))
        result.update(completed=True,selected=selected,caption=text,resource_heap_requests=vm.resource_heap_requests,
            synthetic_catalog_hash_assignment_through_original_copy=True,host_called_original_resource_copy=True)
    except Exception as e:result.update(completed=False,error=str(e),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses)
    result['source_sha256_before_exit']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (STAGE/'synthetic-icon-Grid-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
