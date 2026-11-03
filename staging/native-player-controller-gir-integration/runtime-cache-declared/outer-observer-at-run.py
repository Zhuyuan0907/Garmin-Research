#!/usr/bin/env python3
"""Next cold-run candidate; declare original zero cache before CPU observation.

This is a new source/namespace. Neither earlier controller run is modified.
Native allocators still produce every header and pointer; only verified startup
zero-page mapping is supplied as an explicit memory input before emulation.
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC
import probe_native_controller_gir_component_contiguous as driver
from emulate_native_vpm_filesystem import require
ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'staging/native-player-controller-gir-integration/runtime-cache-declared'
Parent=driver.ContiguousFontControllerGIRVM
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def dump(path,data):
    with path.open('x')as out:json.dump(data,out,ensure_ascii=False,indent=2);out.write('\n')
class DeclaredCacheVM(Parent):
    def __init__(self,stock,build):
        self.declared_startup_zero_cache_pages=[];self.cache_observer_UcErrors=[];self.unexpected_emulation_UcErrors=[]
        super().__init__(stock,build)
        for page in range(driver.CACHE_LOW&~4095,(driver.CACHE_HIGH+4095)&~4095,4096):
            if any(low<=page and page+4095<=high and flags&unicorn.UC_PROT_WRITE for low,high,flags in self.uc.mem_regions()):continue
            provenance=next((row for row in stock.zeros if row['runtime_start']<=page and page+4096<=row['runtime_end']),None)
            require(provenance is not None,'Whole cache page lacks verified original startup-zero input')
            self.uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            require(bytes(self.uc.mem_read(page,4096))==bytes(4096),'Declared zero-cache input differs')
            self.declared_startup_zero_cache_pages.append(dict(page=hex(page),bytes=4096,
                original_startup_zero_range=[hex(provenance['runtime_start']),hex(provenance['runtime_end'])],
                original_allocator_headers_or_pointers_not_host_seeded=True))
        raw=bytes(self.uc.mem_read(driver.CACHE_LOW,driver.CACHE_BYTES))
        require(raw==bytes(driver.CACHE_BYTES),'Whole declared original cache baseline differs')
        self.whole_declared_cache_zero_sha256=hashlib.sha256(raw).hexdigest()
        original_lazy_entry=self.lazy.enter
        def guarded_lazy_entry(error):
            if error.errno!=unicorn.UC_ERR_INSN_INVALID:
                self.unexpected_emulation_UcErrors.append(dict(errno=error.errno,message=str(error),
                    from_boundary='kernel_invoke_UcError_before_lazy_VFP',PC=hex(self.uc.reg_read(UC_ARM_REG_PC)),
                    cache_hook_errors_already_captured=len(self.cache_observer_UcErrors)))
                raise error
            return original_lazy_entry(error)
        self.lazy.enter=guarded_lazy_entry
    def journal_cache_CPU_write(self,uc,access,address,size,value,data):
        try:return super().journal_cache_CPU_write(uc,access,address,size,value,data)
        except unicorn.UcError as error:
            self.cache_observer_UcErrors.append(dict(errno=error.errno,message=str(error),from_hook='journal_cache_CPU_write',
                PC=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=value,
                regions=[dict(low=hex(lo),high=hex(hi),permissions=flags)for lo,hi,flags in uc.mem_regions()if lo<=address+size-1 and address<=hi]))
            raise
def main():
    STAGE.mkdir(parents=True,exist_ok=True)
    source=Path(__file__).resolve();require(not (STAGE/'outer-observer-at-run.py').exists(),'Preserve previous declared-cache run')
    (STAGE/'outer-observer-at-run.py').write_bytes(source.read_bytes())
    deps=[str(source.relative_to(ROOT)),'scripts/probe_native_controller_gir_component_contiguous.py',
        'staging/native-player-controller-gir-integration/runtime-contiguous/terminal-metadata.json',
        'staging/native-player-controller-gir-integration/cache-hook-micro-v3/hook-order-controls.json']
    dump(STAGE/'outer-observer-inputs-before-run.json',dict(source_sha256={path:sha(path)for path in deps},
        complete_original_cache_pages_declared_before_emulation=True,no_native_headers_pointers_or_FP_registers_host_seeded=True,
        device_io=False,sounds_emitted=False))
    driver.ContiguousFontControllerGIRVM=DeclaredCacheVM;driver.STAGE=STAGE
    try:driver.main()
    finally:
        vm=DeclaredCacheVM.last_VM
        if vm is not None:dump(STAGE/'declared-cache-observer-state.json',dict(updated_utc=datetime.now(timezone.utc).isoformat(),
            outer_observer_sha256=sha(str(source.relative_to(ROOT))),driver_observer_sha256=sha('scripts/probe_native_controller_gir_component_contiguous.py'),
            declared_startup_zero_cache_pages=vm.declared_startup_zero_cache_pages,cache_observer_UcErrors=vm.cache_observer_UcErrors,
            unexpected_emulation_UcErrors=vm.unexpected_emulation_UcErrors,
            whole_declared_cache_zero_sha256=getattr(vm,'whole_declared_cache_zero_sha256',None),
            native_headers_or_pointers_or_FP_result_host_seeded=False,device_io=False,sounds_emitted=False))
if __name__=='__main__':main()
