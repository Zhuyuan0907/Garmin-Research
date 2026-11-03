"""Pure exact-MAIN guard shapes for a new actual Dispatcher observer.

This module consumes integers and snapshots only. It imports no VM, reads no
guest memory, executes no guest code and grants no whole-run admission. The
caller must separately prove original opcodes, live allocation/stack bounds,
native initialization, pending-operation and complete chronological journals.
"""

DISPATCHER = 0x8804FB8
REGISTRY_SEM = 0x34F9B28
REGISTRY_TAG = 0x38D860
MANAGER_TAG = 0x3931FC
GIR_SEM = 0x34F773C
GIR_TAG = 0x41B544
CLEANUP_HEAD = 0x3AAEC70
SCOPE = "actual_dispatcher_405340_body"


class ShapeError(ValueError):
    pass


def _require(test, message):
    if not test:
        raise ShapeError(message)


def _address(value):
    _require(type(value) is int and 0 < value < 0x100000000 and value % 4 == 0,
             "Expected a nonzero aligned 32-bit address")
    return value


def _shape(entry, continuation, pointer, function, entry_sp, frame_bytes, **extra):
    _address(pointer)
    _address(entry_sp)
    return dict(scope=SCOPE, actor=DISPATCHER, current=DISPATCHER, Thumb=True,
                entry=entry, continuation=continuation, LR=continuation | 1,
                pointer=pointer, function_entry=function,
                captured_function_entry_SP=entry_sp, entry_SP=entry_sp-frame_bytes,
                frame_bytes=frame_bytes, **extra)


def manager_init_shape(continuation, manager, function_entry_sp):
    """The getter and manager ctor need separate captured entry-SP witnesses."""
    if continuation == 0x38D470:
        row = _shape(0x3008A0, continuation, REGISTRY_SEM, 0x38D456,
                     function_entry_sp, 8, tag=REGISTRY_TAG, tag_store_PC=0x38D474,
                     once_cell=0xF2CBF4, require_actual_cold_once_word_zero=True,
                     require_actual_backend24_cold_zero=True)
    elif continuation == 0x392EFA:
        _address(manager)
        row = _shape(0x3008A0, continuation, manager+0xE04, 0x392DE4,
                     function_entry_sp, 104, tag=MANAGER_TAG, tag_store_PC=0x392EFC,
                     manager=manager, manager_live_bytes=0xE50,
                     require_malloc_preinitial_bytes_zero=False)
    else:
        raise ShapeError("Unreviewed native manager initializer continuation")
    row.update(native_zero_store_PCs=[0x3008A2,0x3008A4,0x3008A6,
                                     0x3008A8,0x3008AA,0x3008AC],
               bytes=24, native_epilogue=0x3008AE,
               host_backend_or_tag_write_allowed=False)
    return row


_MANAGER_RAW = {
    (0x3009A0,0x38D9D4):(0x38D4BE,216,False),
    (0x3008B0,0x38DA12):(0x38D4BE,216,False),
    (0x3009A0,0x390154):(0x390142,16,False),
    (0x3008B0,0x390180):(0x390142,16,False),
    (0x3009A0,0x3945A8):(0x394596,32,True),
    (0x3008B0,0x394618):(0x394596,32,True),
}


def manager_raw_shape(entry, continuation, manager, function_entry_sp):
    """Generate only the six reviewed raw pairs, each under actual D."""
    try:
        function, delta, instance = _MANAGER_RAW[entry,continuation]
    except KeyError:
        raise ShapeError("Unreviewed native manager raw pair") from None
    if instance:
        _address(manager)
    row = _shape(entry,continuation,manager+0xE04 if instance else REGISTRY_SEM,
                 function,function_entry_sp,delta,
                 tag=MANAGER_TAG if instance else REGISTRY_TAG,
                 bytes=24, classification_byte=0,
                 operation="lock" if entry==0x3009A0 else "unlock",
                 native_epilogue=0x300A0A if entry==0x3009A0 else 0x30092A,
                 epilogue_r3_must_equal_original_LR=True,
                 require_live_native_initialized_backend=True,
                 retained_condition_token_allowed=False)
    row["released_links_policy"] = "Preserve actual last-native +0/+4; do not require zero"
    return row


def current_internal_shape(entry, continuation, function_entry_sp, native_tag):
    pairs={(0x3009A0,0x1C0618):0x1C0600,
           (0x3008B0,0x1C0634):0x1C0624}
    _require((entry,continuation) in pairs, "Unreviewed current-TCB raw pair")
    _require(type(native_tag) is int and 0 <= native_tag < 0x100000000,
             "Missing actual pre-operation native tag")
    return _shape(entry,continuation,DISPATCHER+56,pairs[entry,continuation],
                  function_entry_sp,8,tag=native_tag,bytes=24,classification_byte=0,
                  tag_from_actual_preoperation_TCB=True,
                  native_epilogue=0x300A0A if entry==0x3009A0 else 0x30092A)


def clock_shape(continuation, base_constructor_entry_sp, actual_clock_word):
    _require(continuation in (0x38D912,0x38D91E), "Unreviewed native clock caller")
    _require(actual_clock_word == 0, "This scope has only the fixed existing clock0 input")
    _address(base_constructor_entry_sp)
    return dict(scope=SCOPE,actor=DISPATCHER,current=DISPATCHER,Thumb=True,
                entry=0x353A9C,continuation=continuation,LR=continuation|1,
                function_entry=0x38D4BE,
                captured_function_entry_SP=base_constructor_entry_sp,
                entry_SP=base_constructor_entry_sp-216,clock_address=0xF09098,
                clock_before=0,returned_r0=0,clock_after=0,native_read_only=True,
                host_tick_or_clock_store_allowed=False,
                native_result_store_PC=0x38D918 if continuation==0x38D912 else 0x38D91E,
                native_result_offset_from_actual_r6=0x38 if continuation==0x38D912 else 0x3C)


def gir_raw_shape(resource_function, entry, continuation, resource_entry_sp):
    """Two exact resource routes. 11C510 alone does not identify its parent."""
    routes={0x41C3DA:(112,68,0x41C412,0x41C68E),
            0x41C944:(80,4,0x41C956,0x41C998)}
    _require(resource_function in routes, "Unreviewed resource parent function")
    delta,guard_offset,wrapper_return,unlock_return=routes[resource_function]
    _require((entry,continuation) in ((0x3009A0,0x11C510),
                                    (0x3008B0,unlock_return)),
             "Unreviewed resource raw pair")
    is_lock=entry==0x3009A0
    row=_shape(entry,continuation,GIR_SEM,resource_function,resource_entry_sp,
               delta+(8 if is_lock else 0),tag=GIR_TAG,bytes=24,classification_byte=0,
               require_live_prepared_stock_GIR=True,
               RAII_cell=resource_entry_sp-delta+guard_offset,
               wrapper_entry=0x11C504,wrapper_return=wrapper_return,
               wrapper_entry_SP=resource_entry_sp-delta,
               wrapper_entry_r0=resource_entry_sp-delta+guard_offset,
               wrapper_entry_r1=GIR_SEM,
               RAII_cell_store_PC=0x11C50A,
               native_epilogue=0x300A0A if is_lock else 0x30092A,
               require_prior_actual_wrapper_witness=is_lock,
               require_actual_RAII_cell_equals_backend=True)
    return row


def check_event_shape(shape, event):
    """Check provided hook facts only, not allocation/native/journal evidence."""
    keys=["scope","actor","current","Thumb","entry","LR","entry_SP"]
    keys += [key for key in ("pointer","tag","classification_byte") if key in shape]
    for key in keys:
        _require(key in event and type(event[key]) is type(shape[key]) and event[key]==shape[key],
                 "Actor/caller/frame shape differs at "+key)
    return True


def cleanup_registration_shape(node, actual_oldhead):
    _address(node)
    _require(type(actual_oldhead) is int and 0 <= actual_oldhead < 0x100000000
             and actual_oldhead % 4 == 0, "Missing actual old cleanup head")
    return dict(scope=SCOPE,actor=DISPATCHER,original_registration=0x3896F8,
                registration_LR=0x38D4B5,allocator=0x39544C,allocator_LR=0x389707,
                allocator_request=16,node=node,head=CLEANUP_HEAD,
                actual_oldhead=actual_oldhead,node_words=[actual_oldhead,0x34F9B40,0x20DC53,0xC7F980],
                return_status=0,
                ordered_native_stores=[
                    dict(PC=0x38970E,address=node+8,size=4,value=0x20DC53),
                    dict(PC=0x389710,address=node+4,size=4,value=0x34F9B40),
                    dict(PC=0x389714,address=node+12,size=4,value=0xC7F980),
                    dict(PC=0x38971C,address=node,size=4,value=actual_oldhead),
                    dict(PC=0x38971E,address=CLEANUP_HEAD,size=4,value=node)],
                capture_oldhead_at=0x38971A,head_getter=0x6E0C08,
                caller_return=0x38D4B4,existing_head_may_be_nonzero=True)


def cleanup_reachable(head, nodes, live_nodes):
    """Traverse a supplied whole bounded node inventory; reject cycles/dead nodes."""
    chain=[];current=head
    while current:
        _address(current)
        _require(current not in chain, "Cleanup chain is cyclic")
        _require(current in nodes and current in live_nodes, "Cleanup node absent or not live16")
        words=nodes[current]
        _require(len(words)==4 and all(type(w) is int and 0 <= w < 0x100000000 for w in words),
                 "Cleanup inventory is not complete16-byte words")
        chain.append(current);current=words[0]
    return chain


def check_cleanup_linkage(shape,before_nodes,after_nodes,live_before,live_after,
                          after_head,observed_registration_stores):
    """Pure append check on snapshots; allocation/opcode/full-memory checks remain external."""
    node=shape["node"];oldhead=shape["actual_oldhead"]
    old=cleanup_reachable(oldhead,before_nodes,live_before)
    _require(node not in live_before and node not in before_nodes, "Reused existing live cleanup storage")
    _require(after_head==node and node in live_after, "New cleanup head/node not live")
    _require(list(after_nodes.get(node,[]))==shape["node_words"], "New whole cleanup node differs")
    _require(all(p in after_nodes and list(after_nodes[p])==list(before_nodes[p]) for p in before_nodes),
             "An existing inventoried cleanup node changed")
    _require(set(live_before).issubset(set(live_after)), "An existing cleanup allocation ceased being live")
    _require(cleanup_reachable(after_head,after_nodes,live_after)==[node]+old,
             "Cleanup append does not preserve ordered old reachable chain")
    projected=[{k:row[k] for k in ("PC","address","size","value")} for row in observed_registration_stores]
    _require(projected==shape["ordered_native_stores"], "Native cleanup registration stores differ/order changed")
    return True
