Offline AP writer primitives — HWID1352 / software8.00 research

native_ap_writer.py provides callable Python primitives. It has no command
that assembles or installs a real-map candidate. No frozen writer is changed.

L3 rewriting

  rewrite_l3_width23(old_table, record_count=47870)

Input is exactly the original111-bit packed L3 span,664197bytes. Output.table
is exactly670180bytes /47870 records,112bits each. Bit42 is inserted as zero,
so the first-child field grows22→23bits and the other bits retain their exact
values and order. Source IDs remain the same1-based record positions.

Result.old_unused_tail_bits/value retain the six original unused bits as
explicit metadata. There is no unused tail in the byte-aligned new table.
Result.reader_lookahead is four explicit zero bytes for a caller-provided
region following the directory-declared table span; it is not part of that
span. A real MDR assembler must ensure safe lookahead from actual next data.

Only explicit SelectedRange(one_based_street_ID,first_child,count) objects may
change first/count. Updates require a supplied child_table_count and a source
next_level of4. Duplicate IDs, field overflow and invalid child ranges reject.
Next-level5/6 and every other raw flag are preserved by widening; they cannot
silently become L4 updates through this initial API. No ref, flags, coordinate
or ID change is exposed by the API.

Streaming container rewriting

  source = StreamIMG(readonly_source_stream)
  replacement = Replacement(new_logical_size, callable_yielding_byte_chunks)
  receipt = repack_stream(source, new_empty_destination_stream,
                          {'00004171.MDR': replacement})

Supports the exact six AP names,DSKIMG/XOR0/4096-byte allocation blocks, and
an ordinary single root metadata row. StreamIMG initially reads only metadata;
iter_component(name,offset=...,length=...) reads bounded logical bytes by FAT.
Untouched components are copied in chunks, not accumulated as entire files.

The planner rebuilds allocation,240-block continuation rows,rootDIR extent,
and reserved-block lists. The directory grows on4096-byte boundaries. Original
global prefix/header/geometry and per-component metadata templates are kept.
New continuations use the last existing row's nonallocation metadata. Logical
bytes of the five untouched components remain exact. Allocation tail padding
and inactive new directory space are zero-filled, not part of logical files.

Output must fit both original declared fields:32768×4096bytes and262144×512
bytes, i.e.134217728bytes. Exceeding that capacity rejects before writes. This
is an initial writer restriction, not a claimed platform maximum. Geometry,
unknown checksums,additional IMG variants and root continuation are excluded.

Destination stream must be distinct and empty. repack_stream may leave an
incomplete caller-owned stream on source/chunk failure. repack_new_path accepts
only a new path and cleans up only the inode it exclusively created; existing
paths and source aliases are refused. There is no default real-device path.

What was tested

general-writer-focused-proof-v1.json is the terminal test result. A ~1MiB
synthetic stream exercises240→241MDR blocks,one→two FAT parts,and directory
4096→8192bytes, plus logical-byte and metadata preservation and tail padding.
Twenty-six guards cover source formats,overlap/path/continuation errors,
capacity/width/range limits,stream lengths and output protection.

Exactly one original664197-byte L3 source read and one full47870-record
in-memory rewrite were performed. An independent bit-by-bit field decoder
found all seven wire fields identical for every paired source ID. No new
670180-byte table binary was saved and no complete original IMG was copied,
hashed or rewritten. The previous CPU suites were not run.

The test script refuses to overwrite its terminal proof. Do not rerun the
closed scope; use new tests/proof destinations for later implementation work.

Still required

An integrated MDR assembler must relocate header spans/pointers,emit additional
L4/5/6 bodies and labels,keep JAI/DB/route relationships consistent,and verify
complete native queries and device acceptance. These primitives alone do not
constitute a Taiwan2026 update,candidate IMG or installable package.
