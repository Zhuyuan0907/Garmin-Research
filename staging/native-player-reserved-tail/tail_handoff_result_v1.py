"""Same frozen native-result checks, treating original TTS RWE as mutable.
Globals are explicitly bound to the frozen harness, without running it.
"""
def tail_handoff_result(self, name, commands):
    state = self.status()
    require(self.pending_full is self.pending_outer is self.pending_lower is self.pending_get is None,
            'unfinished original frame/message')
    require(not any(self.mutex.values()), 'retained generic mutex fixture')
    require([e['bytes_hex'] for e in self.message_sends] == [e['bytes_hex'] for e in self.message_receives],
            'original FIFO copy/order differs')
    require(self.word(MIXER + 0x78) == self.mixer_tcb, 'original mixer TCB replaced')
    for a, n, p in self.zones:
        if p & unicorn.UC_PROT_EXEC and not p & unicorn.UC_PROT_WRITE:
            require(hashlib.sha256(bytes(self.uc.mem_read(a, n))).hexdigest() == self.RX_before[str(a)], 'RX changed during guest')
    for a in (CONTROLLER_STACK, IDLE_STACK, self.build['symbols']['source_stack']['value'], 0x09600000):
        require(bytes(self.uc.mem_read(a, 64)) == b'\xa5' * 64, 'task stack crossed canary')
    require(bytes(self.uc.mem_read(0x09604000 + 240, 4096 - 240)) == b'\xa5' * (4096 - 240), 'FIFO exceeded opaque allocation')
    witness_before = bytes(self.uc.mem_read(old.RESULT + 256, 128))
    witness = self.invoke_kernel('mcs_native_ownership_snapshot', (0, 1, 0x1352, old.RESULT + 256), phase='uncertified ownership witness')
    require(witness == (-200 & 0xFFFFFFFF) and bytes(self.uc.mem_read(old.RESULT + 256, 128)) == witness_before,
            'uncertified witness changed')
    return dict(name=name, passed=True, status=state, commands=commands,
        source_TCB=self.source_tcb, mixer_TCB=self.mixer_tcb, controller_TCB=self.controller,
        original_scheduled_actor_entries=self.entries, original_kernel_events=self.kernel_events,
        selector_bridge_entries=self.selector_entries, full_native_returns=self.full_returns,
        original_mixer_call_site_returns=self.outer_returns, compiled_reader_entries=self.reader_entries,
        original_message_sends=self.message_sends, original_message_receives=self.message_receives,
        terminal_register_snapshots=self.endpoints, patches=self.patches,
        sync_boot_no_ack_prefix=self.sync_boot_prefix,original_sync_entries=self.sync_entries,
        full_original_sync_returns=self.sync_returns,actual_condition_entries=self.condition_entries,
        original_mixer_ACK8_entries=self.ack_entries,compiled_sync_status=self.sync_status(),
        declared_service_calls=self.fixture_services, opaque_handles=self.handles,
        original_queue_calls=self.lower_calls, original_queue_returns=self.lower_returns,
        native_visits={hex(a): n for a, n in self.visits.items()}, instructions=self.instructions,
        initial_ordinal=self.initial_ordinal, initial_whole_RW_zones=self.initial,
        final_whole_RW_zones={str(a): bytes(self.uc.mem_read(a, n)).hex() for a, n, p in self.zones if p & unicorn.UC_PROT_WRITE},
        zones=[dict(start=a, size=n, protection=p) for a, n, p in self.zones],
        CPU_store_journal=self.journal, declared_fixture_mutations=self.fixtures,
        unchanged_after_declared_patches_RX_sha256={str(a):self.RX_before[str(a)] for a,n,p in self.zones if p & unicorn.UC_PROT_EXEC and not p & unicorn.UC_PROT_WRITE},
        actual_final_RX_zones={str(a):bytes(self.uc.mem_read(a,n)).hex() for a,n,p in self.zones if p & unicorn.UC_PROT_EXEC},
        replay=self.replay(),
        native_ownership_snapshot=-200, native_STOP_DONE=False,
        physical_speaker_phone_App_installation_or_complete_player_verified=False, device_io=False)
