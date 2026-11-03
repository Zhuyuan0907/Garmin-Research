#!/usr/bin/env python3
"""Explicit copies of frozen guards with only reviewed cold-input predicates changed.
Generated before emulation. No guest memory rewrite or synthetic read result.
"""
from probe_native_controller_gir_component import *
from probe_native_controller_gir_component_contiguous import CACHE_LOW,CACHE_BYTES,CACHE_HIGH
from probe_native_heap_settings_boot import BUFFER,WORK
import probe_native_controller_gir_component as driver
class ColdFPGuardMixin:
    def verify_memory(self,voice,exports,dbsha):
            require(not self.invalid_accesses and not self.native_fatal_entries and not self.audio,'Runtime fault or unexpected audio request')
            oldram=struct.unpack_from('<I',(ROOT/self.build['original_binary']).read_bytes(),4)[0]
            require(bytes(self.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(self.uc.mem_read(STUBS,480))==exports,
                'Whole original voice RAM or40 exports changed')
            tables={}
            for table,names in [('app_component_api',self.build['private_api']),('player_component_api',self.build['player_api'])]:
                values=list(struct.unpack('<'+str(len(names))+'I',self.uc.mem_read(self.symbol(table),4*len(names))))
                require(values==[self.symbol(n)for n in names],'Whole compiled private/player API table changed')
                tables[table]=[hex(v)for v in values]
            require(bytes(self.uc.mem_read(self.build['extension_base'],0x10000))==self.extension_code,'Whole RX extension code changed')
            for address,raw in self.initial_regions.items():
                require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Whole original initialized code/GUI region changed '+hex(address))
            for address,raw in self.code_images:
                require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Whole original code image changed '+hex(address))
            require(not self.conditional_region_writes,'Kernel singleton bootstrap unexpectedly mutated declared GUI initialized region')
            for ptr,entry in self.raw_allocations.items():self.verify_guard(ptr,entry)
            for entry in self.handles.values():
                p,n=entry['pointer'],entry['length']
                require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,
                    'Whole opaque allocation canary changed')
            self.verify_storage_guards();self.verify_descriptor_guards();self.verify_closed_files()
            for bottom in [CONTROLLER_STACK,IDLE_STACK]:
                self.verify_cold_controller_or_idle_boundary(bottom)
            require(bytes(self.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,'Native timer stack leading24 canary changed')
            for row in self.GUI_stack_canaries:
                require(row.get('whole16384_native_fill_verified') and
                    bytes(self.uc.mem_read(int(row['bottom'],16),64)).hex()==row['leading64_after_native_fill_hex'],
                    'Original GUI stack crossed its observed leading64 boundary')
            require(len(self.GUI_stack_canaries)==2,'Missing both original GUI stack boundary snapshots')
            require(bytes(self.uc.mem_read(CODE,8))==struct.pack('<2I',0xeafffffe,0xe12fff1e),'Declared synthetic code sentinels changed')
            require(sha(DATABASE)==dbsha and not self.statements and
                list(self.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==self.database_before,
                'Readonly backup or in-memory baseline DB changed')
            return dict(original_voice_RAM_and40_exports_unchanged=True,private12_and_player2_API_tables=tables,
                whole_initialized_regions_checked=[dict(address=hex(a),bytes=len(raw))for a,raw in self.initial_regions.items()],
                whole_original_code_images_checked=[dict(address=hex(a),bytes=len(raw))for a,raw in self.code_images],
                whole_RX_extension_code_unchanged=True,all_allocation_storage_descriptor_and_stack_boundaries_intact=True,
                original_GUI_stack_canary_inputs=self.GUI_stack_canaries,backup_and_inmemory_DB_unchanged=True,
                native_closed_file_inventory_verified=True,guest_memory_or_counters_rewritten_by_guard=False,
                outer=self.summarize(),outer_region_module_tasks_and_mutex_tokens_remain_resident=True,
                outer_cleanup_task_quiescence_or_safe_unload_verified=False)

    def _verify_component_base(self,voice,exports,dbsha):
            require(not self.invalid_accesses and not self.native_fatal_entries and not self.audio,'Component fault or unexpected audio')
            oldram=struct.unpack_from('<I',(ROOT/self.build['original_binary']).read_bytes(),4)[0]
            require(bytes(self.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(self.uc.mem_read(STUBS,480))==exports,'Voice/code imports changed')
            for table,names in [('app_component_api',self.build['private_api']),('player_component_api',self.build['player_api'])]:
                require(list(struct.unpack('<'+str(len(names))+'I',self.uc.mem_read(self.symbol(table),4*len(names))))==[self.symbol(n)for n in names],'Private/player API changed')
            require(bytes(self.uc.mem_read(self.build['extension_base'],0x10000))==self.extension_code,'Old RX extension changed')
            expected=bytearray(self.gui_bank_before)
            for row in self.gui_store_rows:
                offset=int(row['address'],16)-self.gui_bank_base
                require(expected[offset:offset+row['size']].hex()==row['before_hex'],'GUI journal missed mutation')
                expected[offset:offset+row['size']]=int(row['value']).to_bytes(row['size'],'little')
            for address,raw in self.initial_regions.items():
                require(bytes(self.uc.mem_read(address,len(raw)))==(bytes(expected) if address==self.gui_bank_base else raw),'Original initialized region changed outside native history')
            require(len(self.gui_store_rows)==len(self.conditional_region_writes),'GUI history missing event')
            for address,raw in self.code_images:require(bytes(self.uc.mem_read(address,len(raw)))==raw,'Original code image changed')
            require(bytes(self.uc.mem_read(COMP_BASE,4096))==self.comp_bytes+b'\xcc'*(4096-len(self.comp_bytes)),'New RX companion changed')
            require(bytes(self.uc.mem_read(CONFIG,76))==self.config_bytes,'Companion readonly arguments changed')
            require(bytes(self.uc.mem_read(GIR,len(self.resource_bytes)))==self.resource_bytes,'Readonly stock GIR changed')
            for pointer,entry in self.raw_allocations.items():self.verify_guard(pointer,entry)
            for entry in self.handles.values():
                p,n=entry['pointer'],entry['length']
                require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'Opaque allocation canary changed')
            self.verify_storage_guards();self.verify_descriptor_guards();self.verify_closed_files()
            for bottom in [CONTROLLER_STACK,IDLE_STACK]:self.verify_cold_controller_or_idle_boundary(bottom)
            require(bytes(self.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,'Timer stack guard changed')
            for row in self.GUI_stack_canaries:
                require(bytes(self.uc.mem_read(int(row['bottom'],16),64)).hex()==row['leading64_after_native_fill_hex'],'Original GUI stack guard changed')
            require(bytes(self.uc.mem_read(CODE,8))==struct.pack('<2I',0xeafffffe,0xe12fff1e),'Sentinel code changed')
            rows=list(self.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
            expected_rows=[(id,0x7f135201,0) if id==12 else (id,icon,size) for id,icon,size in self.database_before]
            require(rows==expected_rows and sha(DATABASE)==dbsha and self.statements and all(row['closed'] for row in self.statements.values()),
                    'SQL selected endpoint or original finalizers differ')
            require(len(self.component_input_stores)==3 and all(row.get('actual_CPU_store_observed') for row in self.component_input_stores),
                    'Companion SQL provider inputs incomplete')
            catalog=0x34f7730;begin,end,cap=struct.unpack('<3I',self.uc.mem_read(catalog,12))
            require(end-begin==24 and cap>=end and any(not row['freed'] and p<=begin and cap<=p+row['length'] for p,row in self.raw_allocations.items()),
                    'Native GIR catalog lacks live actual allocation')
            self.font_inventory=self.fonts()
            require(len(self.font_inventory)==13,'Font inventory count differs')
            for handle in self.font_handles:
                entry=self.handles[handle];p,n=entry['pointer'],entry['length']
                require(entry['locks']==0,'Font lower handle pinning changed')
                if entry['freed']:require(any(int(row['handle'],16)==handle for row in self.font_release_records),'Missing original font free')
                else:require(self.word(p)==handle and 0<self.word(p+4)<=n-8 and any(int(row['handle'],16)==handle for row in self.font_pointer_queries),'Resident font prefix/query differs')
            live=[dict(handle=hex(h),**entry) for h,entry in self.external_files.items() if not entry['closed']]
            require(len(live)==8 and {entry['path'] for entry in live}==set(self.raw_font_sources),'Resident font stream ownership inventory differs')
            for entry in live:
                owners=[row for row in self.font_stream_owners if row['stream']==entry['handle']]
                require(len(owners)==1 and any(row['context']==owners[0]['context'] and
                    row['source_metadata']==row['metadata'] for row in self.font_inventory),
                    'Resident stream lacks exact original parser/font context ownership')
                require(any(row['stream']==entry['handle'] and row['context']==owners[0]['context']
                            for row in self.font_stream_wrapper_observations),'Original context/stream wrapper not observed')
            return dict(all_scoped_memory_guards_passed=True,selected_SQL_rows=rows,all_SQL_statements_closed=True,
                actual_font_inventory=self.font_inventory,resident_font_streams=live,raw_font_input_ledger=self.font_raw_input_ledger,
                original_parser_stream_owners=self.font_stream_owners,
                GUI_original_write_history=self.gui_store_rows,whole_GUI_region_replayed=True,baseline_not_reset=True,
                readonly_resources_and_code_unchanged=True,hardware_IRQ_or_fullboot_or_App_or_unload_verified=False)

    def verify_component_memory(self,voice,exports,dbsha):
            result=self._verify_component_base(voice,exports,dbsha)
            require(self.cache_reader_route_pending is None and not self.cache_alloc_pending and not self.cache_returns_pending and not self.cache_free_pending and not self.cache_read_pending and
                all(row.get('actual_caller_return_observed') for row in self.cache_allocations) and
                all(row.get('actual_caller_return_observed') for row in self.cache_read_bindings),
                'Original cache allocation/free/read continuations incomplete')
            expected=bytearray(CACHE_BYTES)
            for row in self.cache_journal:
                offset=row['address']-CACHE_LOW
                require(expected[offset:offset+row['bytes']].hex()==row['before_hex'],'Independent whole-cache replay missed mutation')
                expected[offset:offset+row['bytes']]=bytes.fromhex(row['after_hex'])
            require(expected==self.cache_expected,'Independent cache replay differs from observer')
            covered=[]
            for low,end,flags in self.uc.mem_regions():
                begin,stop=max(low,CACHE_LOW),min(end+1,CACHE_HIGH)
                if begin<stop:
                    require(bytes(self.uc.mem_read(begin,stop-begin))==bytes(expected[begin-CACHE_LOW:stop-CACHE_LOW]),
                            'Whole original cache differs from native CPU/raw input history')
                    covered.append((begin,stop))
            cursor=CACHE_LOW
            for begin,stop in sorted(covered):
                require(not any(expected[cursor-CACHE_LOW:begin-CACHE_LOW]),'Modified font cache span remains unmapped')
                cursor=stop
            require(not any(expected[cursor-CACHE_LOW:]),'Modified font cache tail remains unmapped')
            descriptors=json.loads((ROOT/'staging/native-player-settings-vfp-context/gui-static/controller-gir-native-integration-contract.json').read_text())['font_input_table']['descriptors']
            external={0:'05',1:'06',2:'01',7:'07',8:'08',9:'02',10:'03',12:'04'}
            for row in self.font_inventory:
                index=row['index'];descriptor=descriptors[index]
                require(row['metadata']==hex(0x14b3c60+64*index) and row['record']==hex(0x14b4014+816*index) and
                        row['source_metadata']==row['metadata'] and row['name']==str(index),
                        'Original font record/metadata/index publication differs')
                active=index not in [6,11]
                require(row['metadata_flags']==[descriptor['kind'],int(active)] and
                        row['context_error']==('0x0' if active else '0x66'),
                        'Original present/embedded/missing font activation differs')
                if index in external:
                    owners=[w for w in self.font_stream_owners if w['context']==row['context']]
                    require(len(owners)==1,'Active external font lacks unique parser/stream owner')
                    stream=int(owners[0]['stream'],16);entry=self.external_files[stream]
                    require(not entry['closed'] and entry['path']=='0:/.System/ExtData/006-D0952-'+external[index]+'.bin',
                            'Fresh native external font index/path ownership differs')
            require(self.word(0xf071f0)==0x14b5004,'Original selected font record differs')
            result.update(full_original_font_activation_index_path_and_selector_checked=True,
                font_span_coverages=self.font_span_coverages,raw_font_callbacks_avoid_native_critical_storage=True,
                whole_original_shared_font_cache_replayed=True,whole_original_cache_bytes=CACHE_BYTES,
                native_cache_CPU_store_count=self.cache_CPU_store_count,cache_journal=self.cache_journal,
                original_cache_control_witnesses=self.cache_control_witnesses,native_cache_allocations=self.cache_allocations,
                native_cache_read_bindings=self.cache_read_bindings)
            result['original_cache_reader_frame_witnesses']=self.cache_reader_route_witnesses
            return result

    def verify_heap(self,cold=False):
            require(self.word(WORK+4)==BUFFER+4096 and self.word(WORK+0x18)==BUFFER and
                    [self.word(WORK+o)for o in [0x50,0x54,0x58]]==[8192,4096,4096],
                    'Original single-extent heap metadata differs')
            require(self.word(BUFFER)==27 and self.word(BUFFER+0x78)==BUFFER+0x7c and
                    [self.word(BUFFER+4096),self.word(BUFFER+4100)]==[0,4096],
                    'Original private prefix/free header differs')
            nodes=[];p=self.word(0x2d226b4)
            while p:
                require(p in [0x3a7f150,0x3a7f160,0x3ab1028] and p not in [r['pointer']for r in nodes],
                        'New heap exit-list listener chain differs')
                words=struct.unpack('<4I',self.uc.mem_read(p,16))
                nodes.append(dict(pointer=p,words=[hex(v)for v in words]));p=words[0]
            require([r['pointer']for r in nodes]==[0x3a7f150,0x3a7f160,0x3ab1028] and
                    nodes[0]['words'][1:]==['0x1000000','0x388b57','0x0'] and
                    nodes[1]['words'][1:]==['0x3000000','0x388b37','0x0'] and
                nodes[2]['words']==['0x0','0x7fffffff','0x20edb1','0x0'],'Three original heap/FP listeners differ')
            ops=[r for r in self.backend_initializations if r['native_caller']=='0x388bd0']
            require(len(ops)==1 and ops[0]['original_body_executed'] and len(ops[0]['native_zero_writes'])==6 and
                    self.word(WORK+44)==0x388d00,'Original heap native init/retag not complete')
            require([r['native_return'] for r in self.listener_registrations]==['0x388be6','0x388bf8'],
                    'Missing both original successful listener registration returns')
            expected_buffer=bytearray(b'\0'*4096+b'\xcc'*4096)
            for offset,value in [(0,27),(0x78,BUFFER+0x7c),(4096,0),(4100,4096)]:
                struct.pack_into('<I',expected_buffer,offset,value)
            require(bytes(self.uc.mem_read(BUFFER,8192))==bytes(expected_buffer),
                    'Whole declared extent differs from native prefix/free-page recipe')
            if cold:
                expected_work=bytearray(96)
                for offset,value in [(4,BUFFER+4096),(0x18,BUFFER),(0x2c,0x388d00),
                                     (0x50,8192),(0x54,4096),(0x58,4096)]:
                    struct.pack_into('<I',expected_work,offset,value)
                require(bytes(self.uc.mem_read(WORK,96))==bytes(expected_work),
                        'Whole cold native heap workspace differs from exact one-extent recipe')
            require(not any(self.task_mutex_ops.values()) and not any(self.mutexes.values()),'Heap ctor returned with an ordinary lock')
            return dict(workspace96_hex=bytes(self.uc.mem_read(WORK,96)).hex(),listeners=nodes,
                native_initializer=ops[0],declared_extent=[hex(BUFFER),8192],original_prefix_reserve_bytes=4096,
                whole_extent_matches_original_recipe=True,whole_cold_workspace_recipe_checked=cold,
                listener_registration_returns=self.listener_registrations,native_real_device_allocator_verified=False)
