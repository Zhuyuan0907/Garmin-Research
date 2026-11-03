#!/usr/bin/env python3
"""Narrow original retry/control branch supplement; no guest execution."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def main():
    out=Path(__file__).with_name('native-vfp-retry-and-control-branch-clarification.json')
    assert not out.exists()
    mainpath='staging/native-player-dispatcher-fp/fp-static/native-multiowner-vfp-observer-contract.json'
    meta='staging/native-player-settings-vfp-context/tcb-fp-static/native-tcb-fp-metadata-preflight.json'
    assert sha(mainpath)=='142ee737b8f7dd75e24fc52e6f96d1a17aba40c5c20b932b38634ec574efb419'
    assert sha(meta)=='19fc548d527d4ebb363a30e9910e1913e679f6bc5fbbc9fc4eabbdce651f08b6'
    d=json.loads((ROOT/meta).read_text());stock=FileBackedRuntimeImage(NativeImage());decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    selected={0x20ec90,0x20ec94,0x20ec98,0x20eca4,0x20ecb4,0x20eccc,0x20ecd0,
        0x20ece0,0x20ece4,0x20ece8,0x20ecec,0x20ecf0,0x20ecf8,
        0x20ecfc,0x20ed00,0x20ed04,0x20ed08,0x20ed0c,0x20ed1c,0x20ed20,0x20ed24,0x20ed28,0x20ed30}
    rows=[]
    for entry in ['0x20ebe0','0x6e0820']:
        for row in d['bounded_CFGs'][entry]['instructions']:
            pc=int(row['address'],16)
            if entry!='0x6e0820' and pc not in selected:continue
            instruction=next(decoder.disasm(stock.read(pc,4),pc,count=1))
            assert instruction.mnemonic+' '+instruction.op_str==row['instruction']
            assert stock.read(pc,4).hex()==row['opcode_hex']
            rows.append(row)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,guest_executed=False,device_io=False,
        frozen_source_proof_or_canonical_modified=False,
        source_sha256={p:sha(p)for p in [str(Path(__file__).relative_to(ROOT)),mainpath,meta,
            'evidence/firmware-analysis/main_02bd.bin','scripts/analyze_native_sections.py','scripts/analyze_native_gui_worker_boot.py']},
        main_contract_unchanged_sha256=sha(mainpath),original_instruction_evidence=rows,
        clarification='Treatsameowner separatelyfromowner0. Maincontractno_owner_or_same_owner combineslabels; followingtable isexactoriginaldecisionpredicate.',
        exact_retry_table=[
            dict(oldowner_relation='owner==current',new_slot='any/unused',original_path='20EC94->20ED30',old_save=False,
                new_restore=False,retry_D16_FPSCR='faultbank evenif metadata.slotnonzero',
                slot_query_not_executed=True),
            dict(oldowner_relation='owner0',new_slot=0,original_path='20ECA4->20ECFC;20ED08->20ED30',old_save=False,
                new_restore=False,retry_D16_FPSCR='faultbank'),
            dict(oldowner_relation='owner0',new_slot='validsavedblock',original_path='20ECA4->20ECFC;20ED0CVLDM',old_save=False,
                new_restore=True,retry_D16_FPSCR='newowner savedbank'),
            dict(oldowner_relation='nonzeroowner!=current',new_slot=0,original_path='oldsave;20ED08->20ED30',old_save=True,
                new_restore=False,retry_D16_FPSCR='faultbank; oldowner saveonly'),
            dict(oldowner_relation='nonzeroowner!=current',new_slot='validsavedblock',original_path='oldsave;20ED0CVLDM',old_save=True,
                new_restore=True,retry_D16_FPSCR='newowner savedbank')],
        observer_predicate='did_native_restore = (owner_before != current) and bool(newslot_before); requireactual20ED0C iff did_native_restore. Sameowner ignoresvalidslot and remainsfaultbank.',
        exact_existing_slot_control_case=dict(
            original_path='20ECAC6E0820 nonzeroslot ->20ECB4->20ECD8; skipsalloc/attach/clone.',
            plus136='opcode & 0xF00 from20EC08; covered358D24/6E0820 do notmodifyR2.',
            plus140='faultGP3 incoveredexisting-slotpath; noF6EDCPOP-r3 orcloneLDM.',
            actual_pre_STM_snapshot_remains_authoritative=True),
        other_control_cases_preserved='Mutablefirstattach +136=oldTCB/+14020ECC4. Readonlyfirstclone +136oldM.word36/+140oldM.word24. Nevergenericzeroassumption.',
        conditional_FP_instructions=dict(
            save_FPinst='20ECE8 executeswhenFPEXCbit31 set',
            save_FPinst2='20ECEC unconditionalTSTbit28;20ECF0 executeswhenbit28 set',
            restore_FPinst='20ED20 executeswhenloadedFPEXCbit31 set',
            restore_FPinst2='20ED24TSTNE runs onlyif priorbit31testNE;20ED28VMSRNE therefore requiresbothbit31andbit28.',
            normal_observed_scope='Original20EC80sets40000000 beforeallsaves; normalproducedcontrolwords havebothbitsclear. FPINST registersarenotrestoredonthisscope.',
            new_host_FPinst_values_or_unsupported_register_seed_forbidden=True),
        assertion_passed=True,
        limits='OnlyreusedboundedARMbranch/opcoderecheck. No guestexecution/callbackwidth/actualmultiownersave-restore orhardwareexceptionproof; no mainartifactoverwrite.')
    with out.open('x')as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),
        generator_sha256=sha(str(Path(__file__).relative_to(ROOT))),exact_instructions=len(rows),guest_executed=False)))

if __name__=='__main__':main()
