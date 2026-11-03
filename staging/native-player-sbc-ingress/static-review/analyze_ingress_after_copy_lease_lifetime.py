#!/usr/bin/env python3
"""NEW FILE-only failure/lifetime addendum; never import or execute a VM."""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
sys.dont_write_bytecode = True
OUT = HERE / 'ingress-after-copy-lease-lifetime-addendum.json'


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def main():
    assert not OUT.exists(), 'New output only'
    failure_path = BASE / 'guest-v1/terminal-failure.json'
    failure = json.loads(failure_path.read_text())
    build = json.loads((BASE / 'build-v2.json').read_text())
    receipt = json.loads((BASE / 'guest-v1-terminal-tool-receipt.json').read_text())
    sources = dict(failure['source_sha256'])
    for p in [
        failure_path, BASE / 'guest-v1-terminal-tool-receipt.json',
        BASE / 'build-v2-terminal-tool-receipt.json',
        BASE / 'sbc_fifo_ingress_owner_v2.c', BASE / 'build_sbc_ingress_v3.py',
        HERE / 'ingress-source-v1-peer-review.json',
        HERE / 'ingress-source-static-seal.json',
        Path(__file__).resolve(),
    ]:
        sources[str(p.relative_to(ROOT))] = sha(p)
    for path, digest in sources.items():
        assert sha(ROOT / path) == digest, path
    checks = []

    def check(name, ok):
        assert ok, name
        checks.append(dict(name=name, passed=True))

    check('Authoritative failed guest receipt preserved',
          receipt['session_id'] == 15345 and receipt['terminal']['exit_code'] == 1 and
          receipt['terminal']['chunk_id'] == '82c239' and not failure['all_passed'])
    check('Failed source uses unchanged successful build-v2 image',
          build['ELF_sha256'] == 'dca0dbc54498840de000efdd7d0b2279dd72b329668c37f333cffac5d446849d')
    check('Actual ingress full return reports copied acceptance0',
          len(failure['ingress_returns']) == 1 and failure['ingress_returns'][0]['r0'] == 0)
    check('Actual first two decoded frames returned0 with foreign+Source refs2',
          len(failure['decoder_returns']) == 2 and
          all(row['r0'] == 0 and row['leases']['media'] == row['leases']['callback'] == 2
              for row in failure['decoder_returns']))
    check('Actual original synchronous function returned0 without compiled CONFIG grant',
          len(failure['sync_returns']) == 1 and failure['sync_returns'][0]['r0'] == 0 and
          failure['sync_returns'][0]['CONFIG_mixer_TCB'] == 0)
    check('Actual FIFO whole-packet committed once but Source not started',
          failure['producer']['owned'][8] == 1 and failure['producer']['owned'][12] == 4 and
          failure['producer']['started'] == 0 and failure['producer']['stream_error'] == 1)
    zones = {int(a): bytes.fromhex(value) for a, value in failure['final_whole_RW_zones'].items()}

    def word_at(a):
        hits = [int.from_bytes(z[a-lo:a-lo+4], 'little') for lo, z in zones.items()
                if lo <= a and a+4 <= lo+len(z)]
        assert len(hits) == 1, hex(a)
        return hits[0]

    observed = {}
    for name, expected in {
        'ms_before_result': (-201 & 0xffffffff), 'ms_sync_entries': 1,
        'ms_sync_rejections': 1, 'ms_original_sync_completed': 0,
        'mh_handoff_result': (-201 & 0xffffffff), 'mh_started': 0, 'mh_stream_error': 1,
    }.items():
        address = build['symbols'][name]['value']
        value = word_at(address)
        check('Actual serialized final field ' + name, value == expected)
        observed[name] = dict(address=hex(address), value=value,
                             signed_value=value-0x100000000 if value & 0x80000000 else value)
    old = (BASE / 'sbc_fifo_ingress_owner_v1.c').read_text()
    new = (BASE / 'sbc_fifo_ingress_owner_v2.c').read_text()
    guard = (ROOT / 'staging/native-player-mixer-sync/music_session_guard_sync_v1.c').read_text()
    sync = (ROOT / 'staging/native-player-mixer-sync/initializer_sync_bridge_v1.c').read_text()
    asm = (ROOT / 'staging/native-player-mixer-sync/initializer_sync_bridge_v1.S').read_text()
    ctl = (ROOT / 'native/ui-music-control-prototype/ui_music_control.c').read_text()
    queue = (ROOT / 'staging/native-owned-media/owned_queue.c').read_text()
    src = (BASE / 'mixer_source_ingress_v2.c').read_text()
    check('CONFIG requires foreign media/callback references0',
          '!g->control->status.media_references &&' in sync and
          '!g->control->status.callback_references &&' in sync)
    check('Admission wrapper still tail-calls original sync after rejection',
          'bl ms_before_original_sync' in asm and 'ldr ip,=0x46cc7b' in asm and 'bx ip' in asm)
    old_callback = old[old.index('int aas_media_ingress('):old.index('int sbi_receive_packet(')]
    callback = new[new.index('int aas_media_ingress('):new.index('int sbi_receive_packet(')]
    check('Old foreign leases span the Source-preempting POST',
          old_callback.index('SBI_POST(') < old_callback.index('mcs_event_end('))
    check('New copy/coherence checks finish before releasing leases and POST',
          callback.index('mcs_event_begin(') < callback.index('media_queue_callback(') <
          callback.index('umc_media_current(') < callback.index('mcs_event_end(') < callback.index('SBI_POST('))
    after = callback[callback.index('mcs_event_end(g,&frame);'):]
    check('New callback never reads foreign payload or temporary handle after end',
          'packet' not in after and 'handle' not in after and 'if(!r)SBI_POST(g->owner,UMC_SOURCE_EVENT);' in after)
    check('Queue owns copy; temporary handle unused; copied publication checked by epoch',
          '(void)handle;' in queue and 'memcpy(slots[slot], packet, length);' in queue and
          queue.index('memcpy(slots[slot], packet, length);') < queue.index('lengths[slot] = length;'))
    check('Event end only releases two processing leases',
          'if(b->media.held)(void)umc_media_release' in guard and
          'if(b->callback.held)(void)umc_callback_release' in guard)
    media_release = ctl[ctl.index('int umc_media_release('):ctl.index('int umc_callback_acquire(')]
    callback_release = ctl[ctl.index('int umc_callback_release('):ctl.index('static int same_source(')]
    check('Release does not reset owner/generation; Stop release may wake Source',
          'lease->held = 0; c->status.media_references--;' in media_release and
          'lease->held = 0; c->status.callback_references--;' in callback_release and
          'if (stopping) (void)wake(c);' in media_release and
          'if (stopping) (void)wake(c);' in callback_release)
    check('Stage1 is single init and Source target stable in current code',
          'if (c->magic) return UMC_PINNED;' in ctl and 'if(mh_source_tcb)return 0;' in src)
    check('Source rejects stopped queue before drain and command precedes data',
          'if(mh_initialize_result || mh_stream_error || !media_queue_control.running)return;' in src and
          src.index('if(command){mh_iterations++') < src.index('if(bits&UMC_SOURCE_EVENT)'))
    check('Capacity wake remains inside full actual Mixer borrowed reader',
          old[old.index('void sbi_capacity_wake('):] == new[new.index('void sbi_capacity_wake('):])
    result = dict(
        all_passed=True, static_review_completed=True,
        review_kind='NEW FILE-only source/failure lifetime addendum, no guest execution or complete failed-journal replay',
        updated_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=dict(sorted(sources.items())), checks=checks,
        preserved_failed_guest=dict(path=str(failure_path.relative_to(ROOT)),
            sha256=sha(failure_path), session=15345, exit_code=1, terminal_chunk='82c239',
            two_decoder_returns=[r['r0'] for r in failure['decoder_returns']],
            first_decoder_refcounts=[failure['decoder_returns'][0]['leases']['media'],
                                      failure['decoder_returns'][0]['leases']['callback']],
            actual_native_sync_return=failure['sync_returns'][0]['r0'],
            actual_callback_return=failure['ingress_returns'][0]['r0'],
            actual_final_fields=observed,
            journal_rows=len(failure['CPU_store_journal']), fixture_rows=len(failure['declared_fixture_mutations']),
            whole_joint_journal_independently_replayed_in_this_note=False,
            actual_ACK8_independently_reverified_in_this_note=False),
        previous_review_erratum=dict(
            previous_review='staging/native-player-sbc-ingress/static-review/ingress-source-v1-peer-review.json',
            old_review_preserved=True,
            missed_integration_precondition='The foreign ingress leases held over POST conflict with CONFIG requiring references0 when Source starts the first real packet.',
            old_whole_copy_and_return_contract_does_not_prove_first_registration_sync=True,
            actual_runtime_failure_not_reclassified_as_success=True),
        after_copy_lease_contract=dict(
            valid_scope='Single initialized resident guard/component, never-exiting Source task, normal-context original POST; no owner/config replacement or module unload.',
            accepted_order=['Acquire media/callback processing leases.',
                'Validate original F1/status/packet ABI and copy complete payload into reserved module queue slot.',
                'Publish copied queue lengths/count only after copy and running/epoch check.',
                'Recheck live media lease/admission and native R+160 callback coherence while leases remain held.',
                'Release both foreign processing leases before explicit Source POST.',
                'On copied acceptance0, POST the resident Source target with original mailbox event0x80000.',
                'Source acquires its own consumer frame, fully decodes/commits, releases it, then first registration/native sync can inspect reference counters0.',
                'Return through the still-resident native foreign callback stack; do not infer unload quiescence from earlier reference zero.'],
            copied_packet_owns_lifetime=True,
            foreign_packet_handle_retained_after_release=False,
            current_target_read='owner_v2 reads g->owner after mcs_event_end; this is safe only because g/config/SourceTCB are immutable and pinned throughout that interval and POST/full callback return.',
            capture_before_release_mandatory_in_current_immutable_image=False,
            future_mutable_owner_requirement='Capture target/generation while holding the admission lease; independently pin that exact TCB/guard/component until POST returns, revalidate queued identity, and reject any owner-republish race. Capturing alone does not keep a freed TCB alive.',
            no_concrete_stale_guard_owner_or_lost_wake_blocker_in_declared_scope=True,
            stale_Stop_wake='Stop between end and explicitPOST closes admission/increments queue epoch and can discard pending copies; Source consumes a harmless stale event and refuses stopped data. Target remains valid because TCB is resident.',
            release_internal_wake='umc_media_release and callback_release can themselves wake Source when STOPPING, potentially between the two releases. Zero-counter assertions therefore apply to successful ARMED first-start, not arbitrary Stop interleavings.',
            lost_wake_argument='Copied queue publication precedes POST. OriginalPOST merges 0x80000 into TCB+4 and originalWAIT observes the mailbox; event coalescing is level notification of queue work, not one wake per packet.',
            queued_data_not_live='Coherence rejection after publication may retain copied pending bytes without a POST; stopped/replaced epoch/admission must deny decode. This is not a dangling caller buffer.',
            callback_reference_semantics='The ingress media/callback counters cover copied-input processing, not every instruction until original native callback return after the new early release.',
            callback_references0_is_full_native_callback_quiescence=False,
            registration_CONFIG_refs0_is_module_unload_quiescence=False,
            independent_lifetime_pin='Module RX/data, guard/config, queue buffers, Source TCB/stack and native foreign caller stack remain resident until full returns. No current unload/STOP_DONE API may treat these counters as reclamation evidence.'),
        capacity_path_unchanged=dict(
            valid_Mixer_borrow_stays_held=True,
            during_Source_capacity_decode_media_callback_pair=[2,2],
            first_foreign_ingress_Source_decode_new_pair=[1,1],
            first_sync_after_Source_consumer_end_new_pair=[0,0],
            no_arbitrary_counter_relaxation=True,
            required_no_anchor_selector_mutation_inside_Mixer_borrow=True),
        proposed_next_guest_assertions=[
            'At Stage1 endpoint no registered anchor/Mixer capability; first compressed bytes originate only from declared external ingress caller.',
            'Show actual copied queue publication, both foreign lease held-bit clears/refcount decrements before explicitPOST.',
            'At first Source decoder entry refs1/1; beforeCONFIG refs0/0, ms_before_result0, actualnative sync/ACK fullreturn and mh_started1.',
            'Original foreign callback remains on its exact saved stack across Source preemption; it has no reads from packet/temporary handle after release.',
            'Callback full-return is serialized separately from counters and Source/native sync outcome; copied callback0 alone is not player-ready proof.',
            'Capture immutable g->owner and SourceTCB provenance/currentgetter at release and actualPOST; preserve TCB lifetime/no owner/config republish.',
            'Stop between copy/end/POST rejects Source decode/publication and permits only a stale mailbox wake; preserve pinned code/storage/noSTOP_DONE.',
            'Backpressure path still keeps original Mixer borrowed native frame while Source produces, refs2/2 from exact frames; no register/anchor/selector mutation.',
            'Whole-zone CPU+fixture replay and exact GP/IRQ/frame/returns; metadata counter changes are observed CPU instructions, not host seeds.'
        ],
        limits=['No new guest/VM executed; proposed fix has not been runtime-verified in this review.',
            'Only selected recorded failure endpoints are read; no full failed journal or all instruction semantics proof.',
            'First sync permits application admission references0 while a foreign native callback still has live code/SP. Permanent residency is a separate explicit fixture contract.',
            'Restart/republication, mutable Source target, safe unload/cancel completion and general receiver IRQ lifecycle need stronger pins and dedicated contracts.',
            'Native SEP/remoteSTART/physical phone/hardware/heap/exclusive/App remain unproved; synthetic reset-complete17 and output consumption remain separate fixtures.'],
        guest_executed_by_reviewer=False, device_io=False, canonical_written=False,
        physical_ingress_verified=False, complete_player_verified=False,
        native_STOP_DONE_verified=False, native_module_quiescence_verified=False)
    for path, digest in sources.items():
        assert sha(ROOT / path) == digest, path
    with OUT.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(all_passed=True, proof=str(OUT.relative_to(ROOT)), proof_sha256=sha(OUT),
                         source_count=len(sources), checks=len(checks), guest_executed=False,
                         current_pinned_after_lease_POST_source_contract_valid=True,
                         native_callback_quiescence_verified=False)))


if __name__ == '__main__':
    main()
