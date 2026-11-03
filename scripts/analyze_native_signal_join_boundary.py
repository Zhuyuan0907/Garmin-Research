#!/usr/bin/env python3
"""Read exact backup bytes and preserved run46388; no VM or hardware run."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct

from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    image=FileBackedRuntimeImage(NativeImage())
    stage=ROOT/'staging/native-player-signal-dispatch'
    terminal_path=stage/'signal-dispatch-terminal-probe.json'
    metadata_path=stage/'signal-dispatch-terminal-metadata.json'
    source_path=stage/'source-at-original-1c066e-mutex-boundary.py'
    old_static=ROOT/'staging/native-player-task-runtime-full/dispatcher-mainmenu-callback-static-preflight.json'
    proof_path=ROOT/'evidence/firmware-analysis/native-task-runtime-full-emulation.json'
    out=stage/'original-join-and-independent-signal-static.json'
    assert not out.exists(),'Preserve any completed static evidence'
    terminal=json.loads(terminal_path.read_text())
    metadata=json.loads(metadata_path.read_text())
    proof=json.loads(proof_path.read_text())
    assert metadata['session_id']==46388 and metadata['terminal_exit_code']==1
    assert metadata['probe_sha256']==sha(terminal_path)
    assert metadata['source_sha256']==sha(source_path)==terminal['source_sha256_before_run']
    assert metadata['signal_holder_type_metadata_erratum_sha256']==sha(old_static)
    assert terminal['completed'] is False and terminal['full_scoped_final_guards_passed'] is False
    assert terminal['error']=='Native mutex caller outside explicit per-task GUI scope: 0x1c066e'
    assert terminal['registers']==dict(r0='0x8804f14',r1='0x4aecf3',r2='0x8800520',r3='0x0',
                                      lr='0x1c066f',pc='0x3009a0',sp='0x8804f10')
    assert len(terminal['cases'])==3 and all(c['passed'] for c in terminal['cases'])
    assert not terminal['invalid_accesses'] and not terminal['native_fatal_entries'] and not terminal['audio_requests']
    before,after=terminal['signal_before_registration'],terminal['signal_after_registration']
    assert before['entries']==[dict(pointer='0x8805120',vtable='0xc1b56c',callback='0x8800520')]
    assert after['entries'][0]==before['entries'][0]
    assert after['entries'][1]==dict(pointer='0x8809360',vtable='0xc1b584',callback='0x405341')
    assert before['vector']==['0x88051a0','0x88051a4','0x88051a8']
    assert after['vector']==['0x88051a0','0x88051a8','0x88051a8']
    chain=[int(x['entry'],16) for x in terminal['signal_chain']]
    assert chain==[0x4b571c,0x5d28fe,0x37bce4,0x52353c,0x609338]
    assert all(x not in chain for x in [0x574760,0x405340])
    recent=[int(x,16) for x in terminal['recent']]
    for entry in [0x261ce6,0x261cfe,0x261cce,0x261cd8,0x1c0640,0x1c0658,0x1c065c,0x3008a0,0x1c066a]:
        assert entry in recent,hex(entry)
    verified=[]
    assert proof['MAIN_sha256']==EXPECTED and proof['all_passed'] and proof['case_count']==3
    for path,expected in proof['source_sha256'].items():
        assert sha(ROOT/path)==expected,path
        verified.append(dict(path=path,sha256=expected))
    old=json.loads(old_static.read_text())
    for path,expected in old['source_sha256'].items():
        assert sha(ROOT/path)==expected,path
    functions={hex(a):cfg(image,a,[(a,b)]) for a,b in [
        (0x1c0600,0x1c0620),(0x1c0624,0x1c063a),(0x1c0640,0x1c069c),
        (0x4aecf2,0x4aed02),(0x4aecea,0x4aecf2),(0x4aecd8,0x4aecea),
        (0x261ce2,0x261d18),(0x261cce,0x261ce2),(0x5d2942,0x5d2982),
        (0x5d2104,0x5d2126),(0x57458c,0x5745d4),(0x46c274,0x46c28e),
        (0x3103d8,0x3103ee),(0x3008a0,0x3008b0),
        (0x616ad6,0x616ad8),(0x616ad8,0x616ada),(0x5e4bbc,0x5e4bbe),
        (0x5aed2a,0x5aed2c) ]}
    functions['0x2dc9ea']=cfg(image,0x2dc9ea,[(0x2dc9ea,0x2dc9f4),(0x2dc954,0x2dc982)])
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    for pc,target in {0x1c065c:0x3008a0,0x1c066a:0x3009a0,0x1c066e:0x1c0600,
                      0x1c067a:0x300ae4,0x1c0680:0x3009a0,0x1c0686:0x3008b0,
                      0x1c068e:0x1c0624,0x261cfe:0x261cce,0x261cd8:0x1c0640,
                      0x4aecf6:0x4aecea,0x4aecec:0x261ce2,0x5745ca:0x46c274,
                      0x46c276:0x3103d8,0x46c282:0x3008a0,0x3103e2:0x3008a0}.items():
        assert rows[pc]['direct_call']==hex(target),hex(pc)
    assert rows[0x1c0660]['literal_value']=='0xc7f374'
    assert image.read(0xc7f374,11)==b'join_smphr\0'
    assert rows[0x1c0648]['instruction']=='lsrs r0, r0, #0x1f'
    assert rows[0x1c0666]['instruction']=='strb r0, [r4, #0x16]'
    assert rows[0x2dc9ec]['instruction']=='movs r2, #8'
    assert rows[0x57458e]['literal_value']=='0xc1b59c'
    assert rows[0x5745ce]['instruction']=='subs r0, #0x1c'
    assert image.word(0x3954d4)==0x2dc9eb
    assert struct.unpack('<3I',image.read(0xc1b5b0,12))==(0x4aeceb,0x4aecf3,0x4aed03)
    tasks={t['TCB']:t for t in terminal['native_inventory']['tasks']}
    worker,thread=tasks['0x8804fb8'],tasks['0x88092b0']
    raw_thread=bytes.fromhex(thread['raw108_hex'])
    assert int.from_bytes(raw_thread[24:28],'little')==0x5ed1a247
    assert thread['state']==8 and thread['saved_frame13_words'][1]=='0x353c64'
    assert terminal['native_inventory']['ready']==['0x8804fb8','0x9508f90']
    assert worker['owned_mutex_head']=='0x88009bc'
    initial_signal_words=[0xc1b59c]+[0]*6+[0xc1b5c4]+[0]*4+[0x31041c]+[0]*5+[0x46c2c8,0]
    assert len(initial_signal_words)==20
    dependencies=[Path(__file__).resolve(),terminal_path,metadata_path,source_path,old_static,proof_path,
                  ROOT/'scripts/analyze_native_gui_foreground_boot.py',ROOT/'scripts/analyze_native_gui_worker_boot.py',
                  ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00'),source_sha256={str(p.relative_to(ROOT)):sha(p)for p in dependencies},
        frozen_run3875_dependency_hashes_verified=verified,
        preserved_run46388=dict(session=46388,exit_code=1,completed_control_groups=3,
            completed_full_signal_scope=False,full_scoped_final_guards_passed=False,
            boundary='3009A0 entry,originalcall1C066A:returncaller1C066E',
            registers=terminal['registers'],signal_before=before,signal_after=after,
            native_chain=terminal['signal_chain'],recent=terminal['recent'],
            invalid_accesses=[],native_fatal_entries=[],audio_requests=[],
            observed_register_queue_and_signal_scopes_are_preserved_emulation_not_device=True,
            no_callback405340_entry_or_body_observed=True),
        complete_bounded_new_local_CFG_count=len(functions),functions=functions,
        original_cleanup_member_chain=dict(
            static_resolved_chain=['60935A BLXholder.vtable+12','C1B56C+12=4D4565','4D4564 BX5D2943(r0=D)',
                '5D2942 loadsD+4BA4,ifnonnullBLXobject.vtable+4 at5D295A',
                'C1B5B0+4=4AECF3','4AECF2 ->4AECEA ->261CE2 ->261CCE ->1C0640'],
            typed_original_member=dict(holder='0x8805120',vtable='0xc1b56c',object='0x8800520',
                                       static_encoded_pair=['0x5d2943','0x0'],full_member16_bytes_not_captured=True),
            inventory_field_callback_is_holder4_and_means_object_for_member_vtable=True,
            current_D4BA4_raw_value_not_captured=True,
            nonnull_cleanup_branch_is_inferred_from_original_stack_return_and_observed_callee_progress=True,
            observed_stack_at_stale_Dispatcher_frame0x8804F5C_starts5D295D='Native callback savedLR indicates original5D295A indirectcall;it is not a resumable kernel-frame CPSR.',
            active_running_task_saved_frame_bytes_can_be_reused_as_call_stack=True,
            original_constructor_initial_NULL_is_later_replaced='5D2104 allocA8/4AECD8constructthread,5D211E storesobjectD+4BA4,5D2120 starts261D5C.',
            original_4AECF2_is_deleting_thread_destructor_not_pending_holder_removal=True,
            originalS_and_all_existing_holders_remain_untouched_by_suggested_independent_signal=True,
            pending_removal_S10_begin_end_are_both_zero_in_saved_before_and_after_raw56=True,
            no_claim_thread_destructor_or_original_member_callback_returned=True),
        original_join_mutex=dict(entry='0x1c0640',entry_target_r0='NonzeroThread TCB from object+8',
            symbolic_entry_SP='J',entry_stack_use=40,mutex='J-0x24',terminal_entry_SP='0x8804f38',
            observed_mutex='0x8804f14',observed_mutex_entry_SP='0x8804f10',
            original_init='1C065C->3008A0 clears24bytes;1C0662 tag=C7F374(join_smphr);1C0666 flag+22=1.',
            no_current_mutex_raw24_capture=True,
            diagnostic_branch='LSRSflags#31 carrytestsbit30;flags5ED1A247 bit30=1 =>1C064A BHS1C0658 skipsdiagnostic.',
            operations=[dict(call='0x1c066a',api='0x3009a0',return_caller='0x1c066e',status='observed APIentry;body not yet run'),
                        dict(call='0x1c066e',api='0x1c0600',return_caller='0x1c0672',status='staticnext'),
                        dict(call='0x1c067a',api='0x300ae4',return_caller='0x1c067e',status='staticnext;transfer localmutex to targetTCB'),
                        dict(call='0x1c0680',api='0x3009a0',return_caller='0x1c0684',status='staticnext;may block waitingtarget exit'),
                        dict(call='0x1c0686',api='0x3008b0',return_caller='0x1c068a',status='staticnext cleanup'),
                        dict(call='0x1c068e',api='0x1c0624',return_caller='0x1c0692',status='staticnext conditionalrelease currentTCB+38 mutex')],
            mutex_and_entire_destructor_stack_must_stay_resident_while_join_pending=True,
            observed_target_Thread=dict(TCB='0x88092b0',state=8,savedPC='0x353c64',flags='0x5ed1a247',ready=False),
            target_readiness_loop='4AED02 sleeps353BE4(1);F08C87 nonzero,2DDB28 nonzero,32C078 recordbyte4==4 needed before3316EC249/return/exit.',
            no_timer_advance_readiness_completion_target_exit_join_return_or_deadlock_proven=True,
            tag_bytes_hex=image.read(0xc7f374,11).hex()),
        independent_original_signal_candidate=dict(
            status='Static ABI/objectsize/queue compatibility only; newobject has not been constructed or queued here.',
            original_allocate='ARM3954CC(r0=80) veneerloads2DC9EB;Thumb2DC9EA passesheapF070B0 andalignmentr2=8 to2DC954.',
            allocator_ARM_veneer=extract(image,0x3954cc,0x3954d4,'ARM'),
            native_constructor='Thumb57458D(r0=P) returnsP;full80-byte initialization by originalinstructions.',
            object_bytes=80,object_words=20,alignment_bytes=8,
            geometry_evidence='OriginalDispatcher ctor uses adjacent same-type Signal fieldsstride0x50;newobject lastwriteendsatP+4F.',
            expected_initial_words=[hex(x)for x in initial_signal_words],
            expected_initial_raw80_hex=struct.pack('<20I',*initial_signal_words).hex(),
            recursive_cpp='P+1C,vtableC1B5C4;nativebasebackendP+20 tag31041C;native recursivebackendP+38 tag46C2C8.',
            vectors=dict(callbacks='P+4/+8/+C initiallyzero',pending_removals='P+10/+14/+18 initiallyzero'),
            construction_requires=['P nonzero,8-byte aligned,liveallocation covers80bytes withcanaries.',
                '57458D returnsP with exact80bytes/vtables/tags/emptyvectors and unownednativebackend.',
                'Use actualcontrollerTCB/stack afteroriginalWAITrestore;do notfakeowner/ready/context.'],
            register='Original4B571D(P,405341) creates8-byte C1B584 holder plusfirstvectorallocation;check actualoriginalmetadata andfunctiononce.',
            publish='Original5D28FF(D,P) copies[P,0]8bytes toDispatcherTCBqueue andposts event2.',
            queue_acceptance='5D2186 loadsdequeuedP;5D218A loadsP.vtable;5D218C loadsvirtualslot8;BLX5D218E. No membershipcheck againstDfields.',
            native_interface='P.vtableC1B59C slot8=52353D ->609338 ->C1B584 slot12=574761 ->405340.',
            argument_zero_skips_optional_secondary_destructor='5D28FE writesqueuearg0;523558 comparesr4=arg and52355A skipsoptionalobjectvtable+4.',
            D_native_queue_and_callback_guard_retained=True,
            originalS_D464_and_original_member_holder_retained=True,
            input_is_explicit_original_API_object_fixture_not_original_stock_UI_boot_caller=True,
            guest_vtable_mutex_ready_or_owner_patch_required=False,
            lifetime='Queue holdsrawP no refcount;retainP,vector,holder andloadedcallbackmodule through pendingqueue/callback/nativeguards;entry-onlyboundary isnot safe destroy/free/quiescence.',
            heap_services_and_boot_kernel_inventory_remain_existing_offline_fixtures=True,
            new_callbackentry_body_foreground_hardware_GUI_and_real_device_NotProven=True),
        assertions_passed=True,new_emulation_executed=False,device_io=False,sounds_emitted=False,
        firmware_modified=False,frozen_source_or_proof_modified=False,install_candidate=False,
        limits='Exactfile-backed staticbytes/CFG plusreadonly preserved46388 observations. Three controls completed;signal callback405340 entry and finalwholeguards didnot. CurrentD+4BA4/object+8/fullmember16/localjoin24rawbytes notcaptured;branch/callee implications areexplicit inferences. Futurejoin APIs and independently allocatedSignal80 candidate arestatic only. No physical GUI/App/music,taskexit/quiescence,hardwareclock/IRQ orinstallation evidence.')
    out.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(out.relative_to(ROOT)),sha256=sha(out),source_sha256=sha(Path(__file__).resolve()),
                         bounded_new_local_CFGs=len(functions),frozen_dependencies_verified=len(verified))))


if __name__=='__main__':
    main()
