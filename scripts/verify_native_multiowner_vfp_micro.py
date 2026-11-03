#!/usr/bin/env python3
"""Independently replay original-fragment FP controls without executing guest."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib,json,struct,sys
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB

BASE='staging/native-player-dispatcher-fp/'
STAGE=BASE+'micro-vfp/'
PROOF='evidence/firmware-analysis/native-multiowner-vfp-fragment-controls.json'

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def require(v,m):
    if not v:raise AssertionError(m)
def main():
    require(not (ROOT/PROOF).exists(),'Preserve independently verified proof')
    metadata=read(STAGE+'terminal-metadata.json');probe=read(STAGE+'terminal-probe.json');inputs=read(STAGE+'inputs-before-run.json')
    require(metadata['authoritative_terminal_result_received_from_exec'] and metadata['terminal_exit_code']==0 and probe['all_passed'],
            'Need actual successful terminal result')
    dependencies=dict(inputs['source_sha256'])
    for p,s in dependencies.items():require(sha(p)==s,'Frozen input changed '+p)
    require(sha(metadata['runner'])==metadata['runner_sha256']==sha(metadata['runner_snapshot']), 'Exact executed source differs')
    for k in ['runner_snapshot','probe','inputs']:
        require(sha(metadata[k])==metadata[k+'_sha256'],'Terminal artifact changed '+k);dependencies[metadata[k]]=sha(metadata[k])
    stock=NativeImage();md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    replayed=[];store_count=0
    for lowtext,row in probe['partial_zone_journals'].items():
        low=int(lowtext);require(low==int(row['start'],16),'Zone start differs')
        memory=bytearray.fromhex(row['before_hex']);require(len(memory)==row['bytes'],'Zone length differs')
        for store in row['stores']:
            pc=int(store['PC'],16);load=int(store['load_PC'],16);op=bytes.fromhex(store['opcode_hex']);thumb=store['Thumb']
            require(stock.read(load,len(op))==op,'Writer not from exact MAIN')
            if any(c['runtime_start']<=pc and pc+len(op)<=c['runtime_end'] for c in stock.copies):
                require(stock.runtime_to_load(pc,len(op))==load,'Runtime-to-load source differs')
            else:require(load==pc,'Unexplained code relocation')
            ins=list(md[thumb].disasm(op,pc,count=1));require(len(ins)==1 and ins[0].mnemonic.startswith(('str','stm','push','vstm','swp')),
                'Zone history is not original store opcode')
            a=int(store['address'],16)-low;n=store['size']
            require(n in [1,2,4,8] and 0<=a and a+n<=len(memory) and memory[a:a+n].hex()==store['before_hex'],
                'Intervening mutation/cross-zone store in independent replay')
            memory[a:a+n]=store['value'].to_bytes(n,'little');store_count+=1
        corresponding=next(z for z in probe['whole_zones'] if z['start']==row['start'])
        require(hashlib.sha256(memory).hexdigest()==corresponding['after_sha256'] and corresponding['whole_zone_replayed'],
            'Independent whole-zone replay disagrees with runtime readback')
        replayed.append(dict(start=row['start'],bytes=len(memory),events=len(row['stores']),independently_replayed=True,
                             after_sha256=hashlib.sha256(memory).hexdigest()))
    rows=probe['original_handler_rows'];require(len(rows)==5 and len(probe['cases'])==5 and all(c['passed'] for c in probe['cases']), 'Need five complete controls')
    require([a['request'] for a in probe['native_allocations']]==[148,148,40] and
            [a['advance'] for a in probe['native_allocations']]==[152,152,40], 'First-save/clone allocation sizes differ')
    expected=[(False,False),(True,False),(True,True),(True,True),(False,False)]
    coverage_rows=[]
    for index,(row,(save,restore)) in enumerate(zip(rows,expected)):
        require(row['original_handler_entered'] and row['original_exception_return_seen'] and row['original_opcode_retry_reached'] and
            not row['host_wrote_FP_enable_or_context'] and row['save_complete']==save and row['restore_complete']==restore,
            'Original save/no-restore/restore stage differs')
        before,after=row['before'],row['after_native_handler']
        require(before['GP15']==after['GP15'] and before['CPSR']==after['CPSR'] and after['FPEXC']=='0x40000000' and
            after['D16']==row['expected_retry_D16'] and after['FPSCR']==row['expected_retry_FPSCR'] and after['FPowner']==row['new_owner'],
            'Retry does not preserve exact fault frame/new-owner bank')
        if restore:require(row['expected_retry_bank_source']=='new_owner_saved_context' and before['D16']!=after['D16'] and row['original_VLDM128_readback_passed'],
            'Restore did not distinguish saved bank from fault bank')
        else:require(row['expected_retry_bank_source']=='actual_fault_bank' and before['D16']==after['D16'],'No-restore retry changed FP bank')
        if save:
            pending=row['pending_save'];ctx=pending['context'];expected_bank=bytes.fromhex(pending['bank_hex']);coverage=set();chunks=bytearray(128)
            for event in row['VSTM_callbacks']:
                a=int(event['address'],16)-ctx;n=event['size'];require(0<=a and a+n<=128 and not coverage.intersection(range(a,a+n)), 'VSTM overlap/range differs')
                coverage.update(range(a,a+n));chunks[a:a+n]=event['value'].to_bytes(n,'little')
            require(coverage==set(range(128)) and bytes(chunks)==expected_bank and expected_bank==struct.pack('<16Q',*[int(v,16) for v in before['D16']]),
                'VSTM callbacks not complete actual D16 payload')
            controls=[int(v,16) for v in row['actual_control_register_words']]
            require(controls[0]==0x40000000 and len(row['control_STM_callbacks'])==4, 'Control STM not actual four-register store')
            require([(int(e['address'],16),e['size'],e['value']) for e in row['control_STM_callbacks']]==
                [(ctx+132+4*i,4,v) for i,v in enumerate(controls)], 'Control store payload/address differs')
            require(row['VSTM_full128_readback_passed'] and pending['hole_hex']=='ffffffff' and pending['padding_hex']=='ffffffff',
                'Context hole/padding/full readback differs')
            coverage_rows.append(dict(row=index,context=hex(ctx),bytes=128,actual_callback_widths=sorted({e['size'] for e in row['VSTM_callbacks']}),complete=True))
        for push in row['push_rows']:
            pc=int(push['PC'],16);n=push['before_SP']-push['after_SP'];require(n==4*len(push['expected_words']) and n in [8,16,24], 'UND push frame differs')
            require(stock.read(pc,len(bytes.fromhex(push['opcode_hex']))).hex()==push['opcode_hex'] and len(set(push['seen']))==n//4,
                    'UND original opcode/coverage differs')
    task_inputs=inputs['task_inputs'];D=task_inputs[str(0x8804fb8)];dclone=int(probe['native_allocations'][2]['result'],16)
    dpool=probe['partial_zone_journals'][str(D['pool'])];memory=bytearray.fromhex(dpool['before_hex'])
    for e in dpool['stores']:
        a=int(e['address'],16)-D['pool'];memory[a:a+e['size']]=e['value'].to_bytes(e['size'],'little')
    clone=bytearray.fromhex(D['original_metadata_hex']);clone[4]=1;struct.pack_into('<I',clone,28,D['first_context'])
    require(memory[dclone-D['pool']:dclone-D['pool']+40]==clone and struct.unpack_from('<I',clone,32)[0]==0x8805220,
        'Clone40 lost distinct metadata object32')
    for f in probe['fragments']:require(sha('evidence/firmware-analysis/main_02bd.bin')==EXPECTED and hashlib.sha256(stock.read(int(f['address'],16),f['bytes'])).hexdigest()==f['sha256'], 'Original fragment differs')
    require(probe['explicit_two_TCB_metadata_pool_and_task_selection_fixtures'] and
            not probe['original_full_boot_GUI_foreground_App_or_package_acceptance_verified'] and not probe['device_io'] and not probe['sounds_emitted'], 'Scope expanded beyond actual controls')
    dependencies[STAGE+'terminal-metadata.json']=sha(STAGE+'terminal-metadata.json')
    verifier=str(Path(__file__).resolve().relative_to(ROOT));dependencies[verifier]=sha(verifier)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,all_passed=True,case_count=5,cases=probe['cases'],
        source_sha256=dependencies,independent_guest_execution=False,independent_whole_zone_replays=replayed,
        exact_original_CPU_store_events=store_count,independent_VSTM128_coverage=coverage_rows,
        original_fragment_controls=True,complete_cold_boot_or_Dispatcher_integration_scenario=False,
        original_save148_advance152_clone40_and_saved_owner_restore_verified_under_declared_inputs=True,
        device_io=False,sounds_emitted=False,physical_App_or_direct_music_or_accepted_package_verified=False,
        limits='Five fragment controls execute unchanged original handler/allocator/clone/disable/conversion code. Two TCBs/metadata/native-filled-like FF pools, task selection, CPACR and architectural UND entry are explicit virtual fixtures. Complete cold-controller preparation still has its separate frozen proof. No native scheduler switch, actual Dispatcher foreground, visible menu App, package acceptance or hardware music claim.')
    with (ROOT/PROOF).open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,cases=5,zones=len(replayed),original_CPU_store_events=store_count,
                         VSTM_widths=probe['VSTM_observed_callback_widths'],proof=PROOF)))
if __name__=='__main__':main()
