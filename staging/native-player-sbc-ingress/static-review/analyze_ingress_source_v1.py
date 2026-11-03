#!/usr/bin/env python3
"""NEW FILE-only source/ABI review. No VM imports, build, or guest execution."""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

OUT = HERE / 'ingress-source-v1-peer-review.json'


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def main():
    assert not OUT.exists(), 'New output only'
    inputs = [
        'scripts/analyze_native_sections.py',
        'evidence/firmware-analysis/main_02bd.bin',
        'staging/native-player-sbc-ingress/mixer_source_ingress_v1.c',
        'staging/native-player-sbc-ingress/sbc_fifo_ingress_owner_v1.c',
        'staging/native-player-sbc-ingress/owned_media_ingress_v1.c',
        'staging/native-player-sbc-ingress/build_sbc_ingress_v1.py',
        'staging/native-player-sbc-ingress/mixer_source_ingress_v2.c',
        'staging/native-player-sbc-ingress/build_sbc_ingress_v2.py',
        'staging/native-player-mixer-handoff/audio_session_driver_v4.c',
        'staging/native-player-mixer-handoff/music_session_guard_v4.h',
        'staging/native-player-mixer-handoff/native_context_v4.c',
        'staging/native-player-mixer-handoff/pull_bridge_v4.S',
        'staging/native-player-mixer-handoff/memory_output_session_owner_v4.c',
        'staging/native-player-settings-scope/music-owner/memory_output_owner.c',
        'staging/native-player-mixer-sync/music_session_guard_sync_v1.c',
        'staging/native-player-mixer-sync/initializer_sync_bridge_v1.c',
        'staging/native-player-mixer-sync/initializer_sync_bridge_v1.S',
        'staging/native-player-sbc-sync/sbc_arena_runtime_v1.c',
        'staging/native-owned-media/owned_queue.c',
        'native/music-continuous/memory_output.c',
        'native/sbc-prototype/memory_output.h',
        'native/sbc-prototype/media_queue.h',
        'native/sbc-prototype/voice_media.c',
        'native/sbc-prototype/decoder.c',
        'native/sbc-prototype/pcm_converter.c',
        'native/ui-music-control-prototype/ui_music_control.c',
        'native/ui-music-control-prototype/ui_music_control.h',
        'evidence/firmware-analysis/avdtp-media-dispatch-emulation.json',
        'staging/native-player-sbc-sync/static-review/sbc-pipeline-build-v3-peer-review.json',
        'staging/native-player-sbc-sync/verification-v1/sbc-sync-v1-independent-file-verification.json',
        str(Path(__file__).resolve().relative_to(ROOT)),
    ]
    sources = {p: sha(ROOT / p) for p in inputs}
    assert sources['evidence/firmware-analysis/main_02bd.bin'] == EXPECTED
    text = {p: (ROOT / p).read_text() for p in inputs if p.endswith(('.c', '.h', '.S', '.py'))}
    pfx = 'staging/native-player-sbc-ingress/'
    source = text[pfx + 'mixer_source_ingress_v1.c']
    fixed = text[pfx + 'mixer_source_ingress_v2.c']
    ingress = text[pfx + 'sbc_fifo_ingress_owner_v1.c']
    owned = text[pfx + 'owned_media_ingress_v1.c']
    queue = text['staging/native-owned-media/owned_queue.c']
    guard = text['staging/native-player-mixer-sync/music_session_guard_sync_v1.c']
    output = text['native/music-continuous/memory_output.c']
    checks = []

    def check(name, ok):
        assert ok, name
        checks.append({'name': name, 'passed': True})

    check('V1 reads native37BCE4 R0 as int status',
          'int r=((int (*)(uint32_t,const void *))0x37bce5u)(tcb,message);' in source)
    check('V1 uses nonzero status to close stream',
          'r=send_mixer(18,0);\n            if(r){mh_stream_error=1;' in source)
    old = '    int r=((int (*)(uint32_t,const void *))0x37bce5u)(tcb,message);\n    mh_messages++;return r;'
    new = ('    /* Original37BCE4 is a void copied-queue transport; r0 is not a\n'
           '     * defined zero-success status. Actual native FIFO execution is verified\n'
           '     * separately. Local0 means valid target and invocation fully returned. */\n'
           '    ((void (*)(uint32_t,const void *))0x37bce5u)(tcb,message);\n'
           '    mh_messages++;return 0;')
    check('V2 repair changes only void ABI/local return semantics', source.replace(old, new) == fixed)
    check('Stage1 has no packet decoder or first-packet seed',
          'publish_pcm' not in source and 'mp_select' not in source and 'aas_register(ticket)' in source)
    check('First successful external decode precedes registration',
          source.index('int r=media_queue_step();') < source.index('r=start_first_external_packet(ticket);'))
    check('Source WAIT consumes real 0x80000 bit and bounds four work items',
          'if(bits&UMC_SOURCE_EVENT)drain_source_event();' in source and 'work<4u' in source)
    check('Local commands run before data drain',
          source.index('if(command){mh_iterations++') < source.index('if(bits&UMC_SOURCE_EVENT)'))
    callback = ingress[ingress.index('int aas_media_ingress('):ingress.index('int sbi_receive_packet(')]
    check('Ingress typed frame held through copy/coherence recheck/POST/full return',
          callback.index('mcs_event_begin(') < callback.index('media_queue_callback(') <
          callback.index('umc_media_current(') < callback.index('SBI_POST(') < callback.index('mcs_event_end('))
    check('Callback never stores temporary native handle', '(void)handle;' in queue)
    check('Compressed queue copied before lengths/count publication',
          queue.index('memcpy(slots[slot], packet, length);') < queue.index('lengths[slot] = length;') <
          queue.index('media_queue_control.count++;'))
    check('Queue callback rechecks running and epoch after unlocked copy',
          'media_queue_control.epoch != epoch' in queue[queue.index('memcpy(slots[slot]'):])
    consume = owned[owned.index('int owned_media_consume('):owned.index('int owned_media_init(')]
    check('Source actor/coherence checks precede typed consumer admission',
          consume.index('current_actor(') < consume.index('mcs_event_begin('))
    check('Whole parse precedes one whole-packet submit; failure resets state',
          consume.index('owned_packet_parse(') < consume.index('if (!result && owned_media_control.gather_bytes)') <
          consume.index('memory_output_submit(') and 'if (result) { owned_media_control.failed++; (void)reset_codec(); }' in consume)
    check('Submit is private copy and READY publish without native-call/borrow rejection',
          'memcpy(buffers[index], pcm, bytes);' in output and 's->state = READY;' in output and
          'native_calls' not in output[output.index('int memory_output_submit('):output.index('int memory_output_discard(')])
    read = owned[owned.index('uint32_t continuous_media_read('):owned.index('int continuous_media_cancel_ready(')]
    check('Read in-flight lease covers unlocked copy and precedes FREE',
          read.index('slot->in_flight++;') < read.index('memcpy(output+written,source+offset,n);') <
          read.index('slot->in_flight--;') < read.index('slot->state=0;'))
    check('Capacity wake requires actual freed FIFO + pending compressed packet',
          'int wake=freed && running && media_queue_control.count;' in read)
    check('Capacity POST occurs after output copy/silence and reader admission',
          read.index('if(written<capacity)memset(') < read.index('if(wake)sbi_capacity_wake();') and
          '!mcs_reader_admit(g,g->selected_instance)' in ingress)
    check('Generic typed event admission permits distinct existing Mixer borrow',
          'g->borrow' not in guard[guard.index('int mcs_event_begin('):guard.index('void mcs_event_end(')])
    check('Native first registration explicitly excludes existing borrow',
          'g->native_mutation || g->borrow' in guard[guard.index('int mcs_register_begin('):guard.index('int mcs_register_end(')])
    check('Stop and unavailable native completion remain explicit',
          'local Stop pending; no hardware STOP_DONE or unload' in source and
          'return -200;' in text['staging/native-player-mixer-handoff/audio_session_driver_v4.c'])

    n = NativeImage()
    ranges = [
        ('queue_entry', 'Thumb', 0x37BCE4, 0x37BD08),
        ('queue_IRQ_save', 'ARM', 0x37BD08, 0x37BD1C),
        ('queue_copy_and_unlock', 'Thumb', 0x37BD1C, 0x37BD70),
        ('queue_IRQ_restore', 'ARM', 0x37BD70, 0x37BD7C),
        ('queue_POST_and_return', 'Thumb', 0x37BD7C, 0x37BD8C),
        ('POST_normal_or_IRQ_gate', 'ARM', 0x2FCF44, 0x2FCF6C),
        ('POST_mailbox_and_priority', 'Thumb', 0x2FCF6C, 0x2FCFAE),
        ('POST_outgoing_saved_context', 'ARM', 0x2FCFB0, 0x2FCFEC),
        ('POST_ready_publication_original_restore', 'Thumb', 0x2FCFEC, 0x2FCFFA),
        ('POST_ready_insert_restore', 'Thumb', 0x2FCFFA, 0x2FD01C),
        ('POST_ARM_flags_restore', 'ARM', 0x2FD01C, 0x2FD028),
        ('POST_stack_return', 'Thumb', 0x2FD028, 0x2FD02C),
    ]
    segments, rows = [], {}
    for name, mode, lo, hi in ranges:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM if mode == 'ARM' else CS_MODE_THUMB)
        md.detail = True
        instructions = []
        for i in md.disasm(n.read(lo, hi - lo), lo):
            row = {'PC': hex(i.address), 'mode': mode, 'opcode_hex': i.bytes.hex(),
                   'size': i.size, 'instruction': i.mnemonic + ' ' + i.op_str}
            if i.mnemonic in ('bl', 'blx') and i.operands[0].type == ARM_OP_IMM:
                row.update(callee=hex(i.operands[0].imm),
                           LR=hex((i.address + i.size) | (mode == 'Thumb')),
                           normalized_continuation=hex(i.address + i.size))
            if i.mnemonic == 'ldr' and i.operands[-1].type == ARM_OP_MEM and i.operands[-1].mem.base == ARM_REG_PC:
                a = ((i.address + (4 if mode == 'Thumb' else 8)) & ~3) + i.operands[-1].mem.disp
                row.update(literal_address=hex(a), literal_value=hex(n.word(a)))
            instructions.append(row)
            rows[i.address] = row
        assert sum(r['size'] for r in instructions) == hi - lo, name
        segments.append({'name': name, 'mode': mode, 'bounds': [hex(lo), hex(hi)], 'instructions': instructions})
    expected = {
        0x37BD7C: 'adds r0, r4, #0', 0x37BD7E: 'movs r1, #2',
        0x37BD80: 'blx #0x2fcf44', 0x37BD84: 'add sp, #4',
        0x37BD86: 'pop {r4, r5}', 0x37BD88: 'pop {r3}', 0x37BD8A: 'bx r3',
        0x2FCF50: 'bne #0x2fce38', 0x2FD028: 'add sp, #8', 0x2FD02A: 'bx lr',
    }
    for pc, instruction in expected.items():
        check('Original opcode ' + hex(pc) + ' ' + instruction, rows[pc]['instruction'] == instruction)
    check('Native queue epilog never normalizes R0 after POST',
          all('r0' not in rows[pc]['instruction'] for pc in (0x37BD84,0x37BD86,0x37BD88,0x37BD8A)))
    check('POST normal saved flags and priority paths remain original code',
          rows[0x2FCF4C]['instruction'] == 'cmp r2, #0' and rows[0x2FCFA8]['instruction'].startswith('bhs '))
    result = {
        'all_passed': True, 'static_review_completed': True,
        'all_passed_means': 'FILE/source/original-opcode assertions passed; V1 still contains the separately recorded runtime ABI blocker.',
        'review_kind': 'bounded source and original mixed-mode ABI contract; no ELF/build output read or execution',
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'source_sha256': dict(sorted(sources.items())), 'checks': checks,
        'MAIN': {'HWID': 1352, 'software': '8.00', 'sha256': EXPECTED},
        'native_segments': segments,
        'bounded_analysis_limits': {'complete_kernel': False, 'external_callees_recursively_analyzed': False,
            'IRQ_POST_2FCE38_analyzed': False, '37BCE4_original_queue_body_bounded': True,
            'POST_context_restore_destination_runtime_observed': False},
        'v1_ABI_erratum': {
            'concrete_runtime_blocker_found': True, 'V1_source_safe_for_guest_without_repair': False,
            'entry': '0x37bce5', 'ABI': {'r0': 'target native TCB', 'r1': 'caller-owned copied message buffer', 'stack': 'none'},
            'queue_message': {'size': 12, 'word0': 'kind | (8 << 8)', 'word1': 'argument', 'word2': 0},
            'actual_native_tail': '37BD7C loads target TCB into R0; 37BD7E sets event2; 37BD80 calls originalPOST; 37BD84..8A returns its unnormalized R0.',
            'nonzero_R0_is_not_send_error': True,
            'normal_POST_already_ready_path': '2FCF80 branches 2FD016; flags restore and SP+8/BX LR preserve target R0; queue return preserves that nonzero target.',
            'zero_message_width_path': '37BCEE skips directly to37BD84 without copied queue publication; invocation return alone is not publication proof.',
            'V1_fault': 'drain_source_event tests send_mixer return; an ordinary nonzero target R0 can set mh_stream_error after successful native queue invocation.',
            'runtime_failure_observed_in_this_review': False,
        },
        'V2_source_only_repair_addendum': {
            'source': pfx + 'mixer_source_ingress_v2.c', 'sha256': sources[pfx + 'mixer_source_ingress_v2.c'],
            'exact_V1_to_V2_change_checked': True, 'native_transport_cast': 'void (*)(uint32_t,const void *)',
            'local_return0': 'only valid target check and full original invocation return; neither native queue acceptance nor physical output ACK',
            'additional_concrete_source_blocker_found': False, 'guest_executed': False,
        },
        'source_contract': {
            'Stage1': ['actualSource current getter', 'cold original277E20 globalqueues + eighteen269F6C maps + original277D26 profile(8,0,1)',
                'codec/FIR/copied compressedqueue/output/UMCguard init; no registration, anchor publication, Mixer creation or first packet fixture'],
            'external_packet_to_native_start': ['caller ABI event F1,status0,temporary handle,packet pointer,[SP] length',
                'ingress frame acquires media+callback', 'copy packet bytes and publish queue count only after epoch check',
                'originalPOST Source 0x80000 while ingress leases remain held',
                'actualSource WAIT consumes 0x80000; drain maximum4 packets',
                'typed Source consumer parses all frames/FIR into private gather; whole-packet commit only on success',
                'first real positive FIFO ticket -> aas_register -> original270458/277C6A list',
                'original277536 queue start -> original3B9B66 and actual46CC7A wait/ACK -> validated handoff and mh_started',
                'return to suspended caller and release ingress leases after POST completes'],
            'capacity_resume': ['actualMixer native full-pull frame owns gBorrow', 'reader pins each FIFO slot across unlocked memcpy',
                'only fully consumed slots become FREE after in_flight returns0',
                'at end of reader, freed>0 + queue.running + compressedqueue.count>0 invokes sbi_capacity_wake',
                'mcs_reader_admit validates original Mixer actor/provider/session/borrow before originalPOST Source',
                'Source may parse/commit private FIFO while Mixer native borrowed frame is suspended; existing started session requires no registration/selector mutation',
                'Source actualWAIT resumes Mixer, which must finish the complete original full-pull before release'],
            'leases': {'idle': [0,0], 'ingress_copy_POST_return': [1,1],
                'Source_decode_preempting_ingress': [2,2], 'Mixer_native_full_pull': [1,1],
                'Source_decode_preempting_Mixer_capacity_POST': [2,2],
                'counts_are_media_callback_pairs': True, 'universal_refcount2_ceiling_proved': False,
                'required_rule': 'Count actual held resident frames by generation/owner/stack; preserve other task frame and exact borrow pointer. No arbitrary >=1 relaxation.'},
            'copy_and_commit_limits': 'Single Source producer and Mixer FIFO consumer; packet copy uses independent producer reservation. Speculative decoded prefix stays gather-only if a later frame fails.',
            'profile_and_Stop': 'UMC state/epoch and R+160 coherence are rechecked after copy and before/after FIFO commit. Stop remains PENDING, rejects new admission, pins native anchor/storage; true profile callback replacement denies later decode.',
        },
        'required_next_guest_guards': [
            'Stage1 endpoint: zero native anchor/registration/Mixer capability until first external packet; no compressed fixture symbol or hidden bootstrap packet.',
            'Exact original50BBC0->525138->42758E->BX callback ABI if that route is exercised; otherwise declare outer receiver context as fixture.',
            'Ingress borrowed packet source bytes are copied before originalPOST; poison/reuse caller buffer only after callback full return, then prove queued copy unchanged.',
            'Capture ingress and consumer frame addresses, held flags/generation, GP/SP/LR and actual original scheduler restores; references equal the sum of held frames.',
            'Capacity path asserts mh_started=1 and preserves gBorrow address/actor/generation/epoch/session/instance plus original Mixer suspended full-pull frame.',
            'Across capacity Source run: zero anchor/register/selector/method/native_mutation changes; only private decoder/FIR/gather/FIFO/packet state and deliberate native copied-message queue writes.',
            'Fill all four FIFO slots; fifth copied compressed packet defers before decoder/FIR advances. Actual Mixer read frees a complete slot and actualPOST wakes Source with no new packet.',
            'Record original message width/capacity/TCB queue identity, actual copied12-byte message, lock/full return and event2; local wrapper0 is not message acceptance proof.',
            'Whole-packet bad secondframe CRC: no memory_output_submit/READY FIFO prefix; subsequent fresh packet uses reset codec/FIR history.',
            'ExactCPU/fixture joint whole-zone replay including compressedqueue, gather, FIFO pages/slots, Source/Mixer/callback stacks, TCBs/native queues; RX originals and callsite redirects explicit.',
            'Stop/profile rejection before decoder entry, actual native full-return leases and no forged STOP_DONE/safe unload.',
        ],
        'limits': [
            'Pure source/static review; no new guest, build, ELF verification or receiver runtime proof.',
            'Stage1 resets global native audio/channel state. It is a cold fixture contract and unsafe as an unchecked warm navigation initialization recipe.',
            'UMC START is a scoped local prototype lifecycle; native AVDTP remoteSTART admission, actualSEP publication/registration and real phone input remain unproved.',
            'Normal-context callback/POST only; IRQ receiver/preemption outside this bounded task domain needs separate admission and frame analysis.',
            'Compiled arena, predeclared memory/stack regions, opaque allocation/query/release and task bookkeeping remain explicit future runtime fixtures.',
            'Native hardware activation/reset transport and synthetic command17 completion/output ring consumption remain separate declared fixture gaps; no speaker/DAC timing/audio proof.',
            'Profile rewrite after packet queue publication can leave copied pending data while callback reports rejection; queue epoch/coherence must control subsequent drain, without unsafe storage reclamation.',
            'The first native start can fail after FIFO/register publication; mh_stream_error leaves resident pinned state, without rollback/retry/nativeStop completion.',
            'Per-wake budget4 is bounded work; queue refill/coalesced events/backpressure liveness still requires actual new guest evidence.',
            'No native exclusive ownership, complete warm player/App, physical acceptance, Bluetooth stream or safe unload claim.',
        ],
        'guest_executed_by_reviewer': False, 'device_io': False, 'canonical_written': False,
        'actual_phone_ingress_verified': False, 'complete_player_verified': False,
        'native_STOP_DONE_verified': False, 'native_exclusive_ownership_verified': False,
    }
    for p, digest in sources.items():
        assert sha(ROOT / p) == digest, p
    with OUT.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps({'all_passed': True, 'proof': str(OUT.relative_to(ROOT)),
        'proof_sha256': sha(OUT), 'checks': len(checks), 'source_count': len(sources),
        'v1_concrete_ABI_blocker': True, 'v2_repair_source_only': True,
        'original_instructions': len(rows), 'guest_executed': False}))


if __name__ == '__main__':
    main()
