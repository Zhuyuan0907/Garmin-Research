def code(self, uc, address, size, data):
    self.instructions += 1
    self.visits[address] += 1
    self.last_instruction = (address, size, bool(uc.reg_read(UC_ARM_REG_CPSR) & 32), bytes(uc.mem_read(address, size)).hex())
    self.trace.append(hex(address))
    self.trace = self.trace[-48:]
    if address == self.build['symbols']['mh_source_entry']['value']:
        self.source_tcb = self.word(self.build['symbols']['mh_source_tcb']['value'])
        require(self.source_tcb and self.word(READY_TASKS) == self.source_tcb, 'compiled source entry lacks actual original TCB')
    if self.pending_sync and address == self.pending_sync['return_PC']:
        p = self.pending_sync
        require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'full original sync SP return')
        require(self.word(READY_TASKS) == self.source_tcb, 'sync did not return to actual source task')
        self.sync_returns.append(dict(p, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0)))
        self.pending_sync = None
    if address == 4639866:
        require(self.pending_sync is None, 'nested original synchronous initializer')
        require(self.word(READY_TASKS) == self.source_tcb and self.regs()[:3] == [RECORD, 1, 0], 'original sync outside exact compiled source call')
        caller = uc.reg_read(UC_ARM_REG_LR)
        is_stop = caller != 3906649
        if not is_stop:
            require(self.word(self.build['symbols']['ms_original_sync_completed']['value']) == 0, 'PLAY opened before original sync completion')
        else:
            symbol = self.build['symbols']['ns_retire_step']
            require(symbol['value'] <= caller - 4 < symbol['value'] + symbol['size'], 'Stop barrier outside compiled retirement caller')
            require(self.word(self.build['symbols']['ns_stage']['value']) == 3 and self.word(self.build['symbols']['ns_hold']['value']) == 1, 'Stop wait lost actual Source native hold')
            require(self.leases()['borrow'] == self.leases()['media'] == self.leases()['callback'] == 0, 'Stop wait entered before full-frame leases returned')
        p = dict(entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=caller & ~1, call_args=self.regs(), barrier_kind='Stop' if is_stop else 'initialize', CONFIG_mixer_TCB=self.word(self.build['symbols']['aas_guard']['value'] + self.mh_guard_offsets[0]))
        self.sync_entries.append(p)
        self.pending_sync = p
    if address in (4114082, 4114090, 4113862, 3148308):
        self.condition_entries.append(dict(PC=address, state=self.snapshot(), args=self.regs()))
    if address == 3206436 and self.regs()[1] == 8:
        require(self.word(READY_TASKS) == self.mixer_tcb, 'ACK8 outside actual original mixer')
        self.ack_entries.append(dict(state=self.snapshot(), args=self.regs(), flag_before_hex=bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0), 12)).hex()))
    if address in (old.RETURN, IDLE):
        self.endpoints.append(dict(address=address, **self.snapshot()))
        uc.emu_stop()
        return
    if self.pending_lower and address == self.pending_lower['return_PC']:
        require(uc.reg_read(UC_ARM_REG_SP) == self.pending_lower['entry_SP'], 'queue writer full SP return')
        self.lower_returns.append(dict(self.pending_lower, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0)))
        self.pending_lower = None
    if address == 2587754:
        self.lower_calls.append(self.args())
        self.pending_lower = dict(entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1, args=self.args())
    if self.pending_full and address == self.pending_full['return_PC']:
        p = self.pending_full
        view = self.leases()
        require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'] + 64, 'original 64-byte full-pull frame not returned')
        require(view['borrow'] and view['media'] == view['callback'] == 1, 'leases gone before original full return')
        self.full_returns.append(dict(p, returned=self.snapshot(), return_leases=view, r0=uc.reg_read(UC_ARM_REG_R0)))
        self.pending_full = None
    if self.pending_outer and address == self.pending_outer['return_PC']:
        p = self.pending_outer
        view = self.leases()
        require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'outer wrapper did not preserve original mixer SP')
        require(view['borrow'] == view['media'] == view['callback'] == 0, 'leases remain after wrapper return')
        before, after = (p['ring_before'], self.word(DESCRIPTOR + 16))
        count = (after - before) % RING_BYTES
        require(count <= CAPACITY, 'unbounded pull output')
        first = min(count, BUFFER + RING_BYTES - before)
        raw = bytes(uc.mem_read(before, first))
        if first < count:
            raw += bytes(uc.mem_read(BUFFER, count - first))
        self.chunks.append(raw)
        self.outer_returns.append(dict(p, returned=self.snapshot(), return_leases=view, bytes=count, PCM_hex=raw.hex(), full_native_return_count=len(self.full_returns)))
        self.pending_outer = None
    if address == 3120334:
        require(self.pending_full is None, 'nested native full pull')
        view = self.leases()
        require(view['borrow'] and view['media'] == view['callback'] == 1, 'native entry without leases')
        self.pending_full = dict(entry_PC=address, entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1, entry=self.snapshot(), entry_leases=view)
    symbols = self.build['symbols']
    if address in (symbols['memory_output_read']['value'], symbols['continuous_media_read']['value']):
        view = self.leases()
        require(view['borrow'] and view['media'] == view['callback'] == 1, 'reader lacks full-frame leases')
        require(self.word(READY_TASKS) == self.mixer_tcb, 'reader actor differs from original mixer TCB')
        self.reader_entries.append(dict(PC=address, state=self.snapshot(), leases=view))
    if address in (3122486, 3122546):
        require(self.pending_outer is None and self.word(READY_TASKS) == self.mixer_tcb, 'outer pull not original mixer actor')
        self.pending_outer = dict(call_site=address, return_PC=address + 4, entry_SP=uc.reg_read(UC_ARM_REG_SP), ring_before=self.word(DESCRIPTOR + 16), entry=self.snapshot(), full_before=len(self.full_returns))
        self.fixture(SCRATCH - 32, b'\xa5' * (CAPACITY + 64), 'explicit per-pull scratch boundary reseed')
    if address == symbols['mh_selector_bridge']['value']:
        require(self.word(READY_TASKS) == self.mixer_tcb, 'selector bridge not on original mixer')
        require(uc.reg_read(UC_ARM_REG_LR) == 3121817, 'selector veneer changed original LR')
        self.selector_entries.append(dict(state=self.snapshot(), leases=self.leases()))
    if address in (POST, WAIT, RESTORE, 3509240, 3128254, symbols['mh_source_entry']['value'], 3121372):
        row = dict(PC=address, state=self.snapshot(), args=self.regs())
        self.entries.append(row)
        if address == POST:
            self.kernel_events.append(row)
    if address == 3906590:
        self.mixer_tcb = self.word(MIXER + 120)
        require(self.mixer_tcb == 157286400 + 8192 - 108 & ~7, 'mixer TCB not built on original descriptor stack')
    if address == 3652836:
        target, pointer = self.regs()[:2]
        if target == 45069:
            self.service('external notice queue capture', 0)
            return
        if target == 0 and uc.reg_read(UC_ARM_REG_LR) == 1936525:
            require(self.word(READY_TASKS) == self.mixer_tcb and 157286400 <= pointer and (pointer + 56 <= 157294592) and (struct.unpack('<H', uc.mem_read(pointer, 2))[0] == 2), 'hardware reset transport fixture outside exact original request')
            packet = bytes(uc.mem_read(pointer, 56))
            self.service('explicit hardware reset request transport; backend queue uninitialized; no driver/ack', 0)
            self.fixture_services[-1]['original_request_hex'] = packet.hex()
            return
        require(target == self.mixer_tcb and target, 'unexpected original message queue target')
        require((uc.mem_read(target + 21, 1)[0] + 1) % 20 != uc.mem_read(target + 18, 1)[0], 'bounded FIFO admission')
        self.message_sends.append(dict(state=self.snapshot(), bytes_hex=bytes(uc.mem_read(pointer, 12)).hex()))
    if address == 3652608:
        require(self.word(READY_TASKS) == self.mixer_tcb, 'FIFO getter not original scheduled actor')
        self.pending_get = uc.reg_read(UC_ARM_REG_R0)
    if address == 3652738:
        require(self.pending_get is not None, 'message result lacks actual getter entry')
        if uc.reg_read(UC_ARM_REG_R0) == 1:
            self.message_receives.append(dict(state=self.snapshot(), bytes_hex=bytes(uc.mem_read(self.pending_get, 12)).hex()))
        self.pending_get = None
    args = self.regs()
    if address == 3704124 and (not self.native_allocator_execution):
        length, kind, out = args[:3]
        if out == 0 and kind == 2 and (length in (8192, 240)):
            require(len(self.mixer_allocations) < 2, 'unexpected additional mixer backing')
            handle = 3507486721 + len(self.mixer_allocations)
            pointer = 157286400 if length == 8192 else 157302784
            self.mixer_allocations[handle] = dict(pointer=pointer, size=length, queries=0)
            self.service('opaque mixer backing allocation', handle)
            return
        require(0 < length < 4000 and kind in (2, 3) and out, 'opaque node/selector allocation shape')
        require(self.next_handle <= 16, 'opaque backing fixture exhausted')
        handle = 3489660928 + self.next_handle
        pointer = old.HEAP + (self.next_handle - 1) * 4096 + 32
        self.next_handle += 1
        self.handles[handle] = dict(pointer=pointer, size=length, kind=kind, queries=0, released=False)
        self.fixture(pointer - 32, b'\xa5' * (length + 64), 'opaque node/selector backing and guards')
        self.fixture(out, struct.pack('<I', handle), 'opaque allocator output cell fixture')
        self.service('opaque node/selector allocation', 0)
        return
    if address == 3704836 and (not self.native_allocator_execution):
        handle = self.handles.get(args[0]) or self.mixer_allocations.get(args[0])
        require(handle and (not handle.get('released')), 'unknown/released opaque handle')
        handle['queries'] += 1
        self.service('opaque handle query', handle['pointer'])
        return
    if address == 3705634 and (not self.native_allocator_execution):
        require(args[0] in self.handles, 'unknown opaque query completion')
    if address == 3704738 and (not self.native_allocator_execution):
        handle = self.word(args[0])
        require(handle in self.handles, 'unknown release handle')
        require(not self.handles[handle]['released'], 'duplicate opaque release')
        self.handles[handle]['released'] = True
        self.fixture(args[0], bytes(4), 'opaque release output fixture')
        self.service('opaque release', 0)
        return
    if address == 3700074:
        self.fixture(args[0], 'Mixer8\x00'.encode('utf-16le'), 'opaque mixer naming service fixture')
        self.service('opaque naming service', 0)
        return
    if address in (1003568, 3120210, 3905140) and (not self.native_allocator_execution):
        self.service({1003568: 'task construction bookkeeping', 4639866: 'external audio timing hint', 3120210: 'audio pull priority policy', 3905140: 'audio diagnostic policy'}[address], 0)
        return
