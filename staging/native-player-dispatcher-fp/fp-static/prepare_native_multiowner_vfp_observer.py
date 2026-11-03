#!/usr/bin/env python3
"""Reused exact handler/allocator/clone contract; no VM or device execution."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from analyze_native_sections import NativeImage,EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage


def sha(path):
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT/path).read_text())


def span(start,length):
    return dict(start=hex(start),end_exclusive=hex(start+length),bytes=length)


def main():
    output=Path(__file__).with_name('native-multiowner-vfp-observer-contract.json')
    assert not output.exists(),'Preserve all prior artifacts'
    paths=dict(recipe='staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json',
        metadata='staging/native-player-settings-vfp-context/tcb-fp-static/native-tcb-fp-metadata-preflight.json',
        mutex='staging/native-player-task-mutex/task-mutex-static-preflight.json',
        boot='staging/native-player-cold-fp-controller/fp-static/cold-fp-first-controller-boot-contract.json',
        proof='evidence/firmware-analysis/native-cold-fp-controller-emulation.json',
        terminal='staging/native-player-cold-fp-controller/runtime/terminal-metadata.json')
    assert sha(paths['recipe'])=='87db585fdcdda4d7c84969a429c46d2c3efdd932428316757e25fd815c6803a3'
    assert sha(paths['proof'])=='be78a70d2be6b94b0d8fecb6973f805dfe85b2618b1986b3ccae98b1d53ce5a0'
    assert sha(paths['terminal'])=='efb1cbe8e43aacb87e4a457c684cbcdcfc4141de135943ab784abac92a3f6f36'
    docs={key:read(path)for key,path in paths.items()}
    assert docs['proof']['all_passed'] and docs['proof']['only_first_same_controller_FP_verified']
    assert not docs['proof']['multiowner_FP_or_foreground_or_accepted_package_or_physical_App_or_direct_music_verified']
    terminal=docs['terminal']
    assert terminal['session_id']==76222 and terminal['terminal_exit_code']==0 and terminal['full_scoped_final_guards_passed']
    for field in ['runner','runner_snapshot','inputs','probe']:
        assert sha(terminal[field])==terminal[field+'_sha256'],field
    assert terminal['runner_sha256']=='0c4f4bb7e0077da701da225c183c262fa14346685dd605994438bd3edac1be3c'
    probe=read(terminal['probe'])
    assert probe['cold_boot_sealed'] and probe['completed'] and len(probe['component_calls'])==11
    assert all(row['returned']for row in probe['component_calls'])
    fpu=probe['actual_FPU_state']
    assert fpu['FPowner']==fpu['current_TCB']=='0x9503f90' and fpu['FPSCR']=='0x3000010'
    verified={}
    for key in ['recipe','metadata','mutex','boot']:
        for registry in ['source_sha256','rechecked_existing_source_registry']:
            for path,digest in docs[key].get(registry,{}).items():
                assert sha(path)==digest,path
                assert path not in verified or verified[path]==digest,path
                verified[path]=digest
    stock=FileBackedRuntimeImage(NativeImage())
    assert sha('evidence/firmware-analysis/main_02bd.bin')==EXPECTED
    decoders={mode:Cs(CS_ARCH_ARM,flag)for mode,flag in [('ARM',CS_MODE_ARM),('Thumb',CS_MODE_THUMB)]}
    evidence=[]
    selections=[('metadata','bounded_CFGs',['0x20ebe0','0x6e0820','0x6e0830','0xf6e08','0xf6edc']),
                ('mutex','functions',['0x358d24','0x21b6cc','0x21b6dc'])]
    for key,group,functions in selections:
        for entry in functions:
            for row in docs[key][group][entry]['instructions']:
                pc=int(row['address'],16);mode=row['mode'];instruction=next(decoders[mode].disasm(stock.read(pc,4),pc,count=1))
                assert instruction.mnemonic+' '+instruction.op_str==row['instruction'],hex(pc)
                raw=stock.read(pc,instruction.size).hex()
                if row.get('opcode_hex',row.get('bytes_hex')):
                    assert raw==row.get('opcode_hex',row.get('bytes_hex')),hex(pc)
                evidence.append(dict(row,opcode_hex=raw,reused_CFG=paths[key],containing_function=entry))
    U=0x18310fe0
    def push(pc,mode,opcode,sp_offset,registers,values,gate):
        length=4*len(registers);pre=U+sp_offset
        return dict(PC=hex(pc),mode=mode,opcode_hex=opcode,pre_SP=hex(pre),post_SP=hex(pre-length),
            range=span(pre-length,length),context_gate=gate,
            stores=[dict(address=hex(pre-length+4*n),size=4,register=reg,value=values[n])for n,reg in enumerate(registers)],
            capture_actual_preinstruction_registers=True,require_native_opcode_and_UND_mode=True)
    pushes=[
        push(0x20ebe0,'ARM','1f102de9',0,['r0','r1','r2','r3','r4','ip'],
             ['fault.GP0','fault.GP1','fault.GP2','fault.GP3','fault.GP4','fault.GP12'],'Eachacceptedtrapfirsthandlerentry'),
        push(0x20ec78,'ARM','20402de9',-24,['r5','lr'],['fault.GP5','fault.PC+4'],'EachacceptedlazyFPpath'),
        push(0xf6edc,'Thumb','70b5',-32,['r4','r5','r6','lr'],
             ['oldownerTCB','currentTCB','fault.GP6','0x20ecc4 ARM'],'OldownerexistsandFPslot0; request148'),
        push(0x6e0830,'ARM','10402de9',-32,['r4','lr'],
             ['newlyallocated_FPcontext','0x20ecd4 ARM'],'Oldownernewslotattach'),
        push(0xf6e14,'Thumb','70b5',-40,['r4','r5','r6','lr'],
             ['newlyallocated_FPcontext','currentTCB','fault.GP6','0x6e0858 ARM'],'Readonlyoldmetadata.byte4==0 clonebranch'),
        push(0xf6edc,'Thumb','70b5',-56,['r4','r5','r6','lr'],
             ['oldmetadata40pointer','oldownerTCB','fault.GP6','0xf6e2d Thumb'],'Nestedclone40allocator only')]
    GUI=docs['metadata']['first_GUI_save_recipes']
    for role in GUI:
        base=int(role['pool_base'],16);ctx=(base+15)&~7
        assert ctx==int(role['first_FP_context'],16)
        assert ctx+152==int(role['native_metadata_clone'],16)
        assert ctx+192==int(role['final_cursor'],16)<base+256
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,guest_executed=False,
        device_io=False,sounds_emitted=False,frozen_source_proof_or_canonical_modified=False,MAIN_sha256=EXPECTED,
        source_sha256={path:sha(path)for path in [str(Path(__file__).relative_to(ROOT)),*paths.values(),
            terminal['runner'],terminal['runner_snapshot'],terminal['inputs'],terminal['probe'],
            'evidence/firmware-analysis/main_02bd.bin','scripts/probe_native_lazy_vfp.py',
            'scripts/probe_native_settings_lazy_vfp_v2.py','scripts/native_cold_fp_guard_copies.py']},
        rechecked_existing_source_registry=verified,new_CFG_count=0,whole_kernel_or_fatal_path_complete=False,
        reused_exact_instruction_evidence=evidence,
        frozen_first_same_positive=dict(session=76222,helper_returns=11,full_scoped_guards_passed=True,
            actual_terminal_FPU=fpu,cold_controller_metadata='0x9400900',FPslot0=True,pool256_nativeFF=True,
            original_FPboot_listener_registered=True,multiowner_FP_not_yet_executed=True),
        trap_admission=dict(current='Actualrunning nativeTCB in scopedC/D set; require F09090==runningtask and F09094=0.',
            fault='OriginalunchangedARMCP10/11VFPopcode, SYS31 orUSR16, FPEXC.EN0, CPACRF00000; otherwisefailclosed.',
            oldowner='0 or C/D nativeTCB with exactmetadata40/pool/FPslotlifetime. Timer/idlemetadata0 and Threadnotyetadmitted.',
            architectural_input='Only bankedUNDSP/LR=faultPC+4/SPSR/CPSRmodeIRQ fixture; nohostowner/FPbank/FPEXCenable/saveallocation/contextswitch.',
            active_guard='Oneactivehandler; observed32byteprimaryframe + acceptednative nestedpushes, no recursiveundefinedhandler.',
            old_bank='SnapshotD16/FPSCR, fullGP15/CPSR and owner/context metadata/pool beforeundefinedentry.',
            new_saved_bank='Beforehandler store newownerexistingcontext148raw forlaterrestoreretrystate comparison.',
            owner_publish='20EC98 storesactualnewcurrent beforealloc/save; partialfailure remainspartialowner state, neverreset it forguard.'),
        UND_push_store_contracts=pushes,
        UND_frame_balance=dict(top=hex(U),interior_guard_low='0x18310020',range=span(U-72,72),
            maximum_listed_nested_bytes=72,
            modes='CPSR&31=1B for eachpush/store; Tbit matchesoriginalinstruction mode. Thumbhelpers remainUND.',
            original_leaf_queries=['358D24','6E0820','21B6CC','21B6DC'],leaf_extra_push_bytes=0,
            IRQ_leaf_LRs=['F6EF6BLX21B6CC->LRF6EFB','F6F1ABLX21B6DC->LRF6F1F'],
            return_checks=['F6F24BX restoredr3 returns20ECC4 ARM orF6E2C Thumb withentrySP restored.',
                'F6E44POP returns6E0858 ARM, restoresr4/r5/r6/SP;6E085CPOP returns20ECD4 ARM, restoresr4/SP.',
                '20ED30POP r5,lr returnsSPU-24;20ED34lr-=4;20ED38POP r0-r4,ip returnsSPU.',
                '20ED3CMOVS PC,LR restoresSPSR,originalfaultPC,GP15/bankedSP/LR; faultfunction is resumed, notreentered.'],
            values='Useactualsnapshot immediatelybeforeeachpush; symbolicvaluesdescribe coverednativebranch, notreplacementpayloads.',
            untouched_callee_GP='Originalr6unchangedoutsidecallee untilcloneLDM; do notsubstitute faultregisters for allcallee stacks.'),
        allocator_attach_clone=dict(request148=dict(call='0x20ecc0 ARM BLX',entry='0xf6edc Thumb',
                actual_LR='0x20ecc4 ARM',r0='oldownerTCB',r1=148,advance=152),
            attach=dict(call='0x20ecd0 ARM BL',entry='0x6e0830 ARM',actual_LR='0x20ecd4',
                r0='oldownerTCB',r1='newlyallocatedcontext',
                mutable_controller='M.byte4=1 keepsTCB+28=M;6E0858writesM+28=ctx.',
                borrowed_GUI='ReadonlyM.byte4=0->6E0854BL F6E08,LR6E0858; originalThumbF6E14 clones40.'),
            clone40=dict(call='0xf6e28 ThumbBL',entry='0xf6edc',actual_LR='0xf6e2d',continuation='0xf6e2c',bytes=40,
                copy_stores=[dict(PC='0xf6e2e',relative_span=[0,16]),dict(PC='0xf6e32',relative_span=[16,32]),dict(PC='0xf6e36',relative_span=[32,40])],
                copied_bytes='Exact40bytes oldmetadata beforeclone, including+24othercontext/+28FPslot/+32Threadidentity/+36.',
                writable_byte=dict(PC='0xf6e3c',offset=4,size=1,value=1),
                TCB_metadata=dict(PC='0xf6e40',offset=28,size=4,value='newclone40pointer',gate='Exactoldowner GUI TCB only'),
                FPslot=dict(PC='0x6e0858',metadata_offset=28,size=4,value='newlyallocatedcontext'),
                old_metadata40_unchanged=True),
            pool_header=dict(magic='0xfce3e2ca',magic_PC='0xf6f02',cold_cursor_PC='0xf6f10',bump_PC='0xf6f18',
                initial_cursor='align_up(base+8,8)',bump='oldcursor+align_up(request,8)',initialized_magic_trusts_cursor=True),
            no_native_capacity_check=True,no_native_payload_zero=True,metadata_word12_not_checked_by_allocator=True,
            external_limit='Eachallocation8aligned/nonzero/cursorinsidebase+256/end<=base+256 and strictly below liveframes/minSP; prohibit anyotherpoolallocator caller/task/request.',
            missing_metadata_or_pool_returns0_unchecked_by_handler=True,
            repeated_saves='ExistingFPslot skipsallocator/attach; no new152/40 cursorbump.',
            controller=docs['recipe']['per_task_pool_recipes']['controller'],
            Dispatcher=GUI[0],Thread_future_only=GUI[1],
            distinct_metadata_fields='+32Threadobjectidentity !=TCB+32ownedmutexhead != savedcontext+136/+140controlwords.',
            ordinary_heap_TCB_plus36_ownedmutex_lists_clock_timednode_unchanged=True),
        VSTM128_observer=dict(PC='0x20ecd8',mode='ARM UND',opcode_hex='200b80ec',base='actualr0==oldownerFPslot',
            payload='struct.pack(<16Q,actualpreinstructionD0-D15); littleendian exact128bytes.',
            before='Capturectx152before and expectedD128 beforeinstruction, activeoldowner/savephase/metadata pointer.',
            each_callback='UnchangedMAINopcode/activeUND/PC20ECD8; address+width withinctx+[0,128); comparevalue maskedtoreportedwidth againstexpectedpayload slice; recordactualwidth/address/before/value.',
            callback_width_not_observed_by_this_static_task=True,
            scalar_admission='Poweroftwo width1/2/4/8 can becomparedasfullvalue. Wider callbackneedsseparateobserveddecoder/poststoreevidence; never silentlytruncatevalue orclaimsupport.',
            coverage='Exactly128bytes covered once bycallbacktiles, nooverlap/outside; collectcoverage mask independentofnetreplay.',
            post_instruction='At20ECDC requirecompletecoverage andwhole128bytes==capturedD16; captureCPUjournalaftervalues, nothostwrites.',
            overlap='FPcontext liesinsidepool256journal; useoneauthoritativebytehistory or explicitsequencedreplay, noindependentstale snapshots.',
            low_hole='ctx+[128,132) untouched',allocation_padding='ctx+[148,152) untouched',
            readback_and_hooks_do_not_prove_hardware_memory_bus=True),
        control_STM16_observer=dict(PC='0x20ecf8',opcode_hex='0e1080e8',mode='ARM UND',base='r0=ctx+132',
            registers=['r1','r2','r3','ip'],offsets=[132,136,140,144],
            payload='Capture actualr1/r2/r3/ip immediatelybefore20ECF8; pack4I; callbacksfour4B orseparatelywitnessedexacttiles.',
            FPEXC='20EC80alreadysets40000000;20ECE0readsactualhandlerenabledFPEXC. +132!=faultFPEXC0.',
            conditional_fields='20ECE8/20ECF0 readFPINST/FPINST2 onlywhen savedr1bits31/28. Otherwise+136/+140areexistingactualR2/R3, notzero.',
            path_examples=[dict(path='oldCslot0/mutablemetadata',plus136='oldC TCB from6E0834',plus140='20ECC4 fromF6EDCPOP r3'),
                dict(path='oldDslot0/readonlyclone',plus136='oldM.word36 fromF6E34LDM',plus140='oldM.word24 fromF6E30LDM; currently0'),
                dict(path='oldownerexistingFPslot',plus136='actualR2 followingopcode/currentquery history',plus140='actualR3; noallocatorPOP orcloneLDM onthisbranch')],
            FPSCR='20ECF4capturesactualoldbankFPSCR; stockcoldcontrollerterminal03000010 iswitnessonly, notallfuturesavesconstant.',
            complete_readback='At20ECFC requirewhole16B==actualcapturedregisterpayload; coverage16/nooverlap/wholepoolreplay.',
            reserved_bytes='Comparectx+128..132 andctx+148..152 againstbeforetrap/rawjournalhistory; untouchedFFonfirstcoldalloc onlyifnativefillwitness.',
            no_host_context_payload_or_universal_constant_control_table=True),
        retry_FP_bank_contract=dict(GP_and_flags='AtoriginalfaultPCafter20ED3C: originalGP15/CPSR exactfaultsnapshot includingbankedtaskSP/LR.',
            owner_and_enable='Actualowner=newcurrent and FPEXCenabled byoriginal20EC80 ornative20ED18savedcontrol.',
            no_owner_or_same_owner='No oldsave onowner0/same; newslot0 retains actualfaultD16/FPSCR. Ifnewslotvalid, actualnativeVLDM mayrestore savedbank.',
            first_C_to_D='Cslot0 getsnative152save. NewDslot0:20ED08branch skipsVLDM/zero/allocation; retryD16/FPSCR==faultbank. ProvesCsave only.',
            later_D_to_C='Dslot0 gets152save+clone40/TCB+28 change. Cslotvalid:20ED0CVLDM/20ED14controlLDM/20ED18FPEXC/20ED2CFPSCR; retry comparesC savedbank, notDfaultD16.',
            later_C_to_D='Cexistingctxresave(noalloc), DslotvalidnativeVLDM provesDrestore when actualoriginalDfaultreached.',
            native_restore_sources='Capturefreshnewownercontext beforehandler; onlyoldowner block may beoverwritten. Requireold/newcontexts separate andlifetimevalid.',
            full_C_D_roundtrip_requires_all_three_exchange_stages=True),
        guards_to_extend=dict(controller_boundary='Pool256nativeheader/contextwholeCPUhistory + FF64[9500100,9500140); M40onlynativeword28 delta; nofrozenall256FF onceCsave.',
            Dispatcher_boundary='KeepoldFF64 untilactualDsave; thenpool256nativeFP+clonehistory + FF64[8801124,8801164); oldM40unchanged/newclone40exact.',
            Thread_boundary='ThreadoriginalFF64/oldM40/object8805220 remainunchanged; noThreadFP admittedyet.',
            TCB108='FP-onlytrapentry→retry wholeC unchanged; wholeD changesonly+28 atnativeF6E40 firstclone. Ordinarykernelphase hasseparatecontext/ready history.',
            retained_storage='PreserveALL/ready/priorities/ownedmutexchains/C+36/Threadnode20/livebackgroundframes/Timerdualconditions/module/fonts/cache/SQL/inputledger; FPpathdoesnotclocktick.',
            helper_scope='Do notconvert first/samefrozenhelper orcoldguards into broadacceptance; newexactsource must separatelyattributeallnativeexchanges andfailbeforeuncheckedNULLsave.'),
        assertions_passed=True,
        limits='Reusedboundedacceptedhandler/metadata/allocator/leafCFG exactopcode review only. No newguest/device execution, callbackwidth observation, actualDispatcherFP/save/restore, IRQclock, foreground/physicalApp/audio/package orsafeunloadproof. Genericfatalpath6E9340 notrecursed; no completekernelclaim.')
    with output.open('x')as handle:
        json.dump(payload,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps(dict(artifact=str(output.relative_to(ROOT)),sha256=sha(str(output.relative_to(ROOT))),
        generator_sha256=sha(str(Path(__file__).relative_to(ROOT))),
        exact_instructions_rechecked=len(evidence),old_registry_sources_revalidated=len(verified),
        guest_executed=False,assertions_passed=True)))


if __name__=='__main__':main()
