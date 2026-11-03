Stock native multilevel MDR streaming writer — version1

Source-only offline primitive. No CLI/default output, map installation,
country source extraction, native CPU, service, or publishing action.

API (choose container adapter explicitly before creating its MDR plan):

    import multilevel_mdr_writer as mdr
    # Keep the source stream open; run callers with python3 -B.
    image = mdr.core.StreamIMG(original_file)
    adapter = mdr.ContainerAdapter.original_4k(image)
    # For explicit8K output instead, use both lines below:
    # image = mdr.eight().Source4K(original_file)
    # adapter = mdr.ContainerAdapter.explicit_8k(image)

    appends = {
        6: mdr.PackedAppend(6, n6, n6*68, supplier_of_packed_level6_chunks),
        5: mdr.PackedAppend(5, n5, n5*126, supplier_of_packed_level5_chunks),
        4: mdr.PackedAppend(4, n4, n4*128, supplier_of_packed_level4_chunks),
    }
    ranges = tuple(mdr.SelectedRange(ID, first, count, next_level, raw_flags)
                   for ID, first, count, next_level, raw_flags in explicit_changes)
    plan = mdr.plan_multilevel_mdr(adapter.mdr_source,
        appends=appends, selected_ranges=ranges)
    prepared = plan.bind_container(adapter)  # Capacity is checked here.
    receipt = prepared.repack_stream(distinct_empty_destination)
    # Or use prepared.replacement with the adapter's same sealed repacker.

MDR planning does not perform or fake capacity checks. Container binding is
separate and may reject an otherwise valid MDR semantic plan. There is no
automatic4K→8K fallback. original_4k uses this module core.StreamIMG and retains
the original134217728-byte(128MiB) capacity/geometry. explicit_8k requires this
module eight().Source4K and the separately sealed8K writer, targeting an explicit
268435456-byte(256MiB) profile. Neither number is a Garmin platform maximum.
The8K header checksum and actual device acceptance remain unknown as documented
by the sealed8K writer. A plan must bind its own adapter.mdr_source instance;
mixing separately imported parser/Replacement classes or another source fails.

All three append levels must be declared, including zero:
    mdr.PackedAppend.empty(level)

Each supplier is a zero-argument callable returning byte chunks, at most64KiB.
record_count and bit_length are exact, and bit_length=count*stride. Source
streams have ceil(bit_length/8) bytes. Only the final byte may contain unused
bits; those bits must be zero. Records are contiguous bits, not individually
byte-padded records. The table validator checks every mapordinal bit, including
markers crossing chunks/byte boundaries, exact byte/bit counts and final tail.

For a supplier of individually padded records, use:
    mdr.PackedAppend.from_records(level, count, supplier_of_record_rows)
Individual rows are9bytes(level6/68bits),16bytes(level5/126bits),16bytes(level4/
128bits), with respectively4/2/0zero unused high bits. pack_records(level,rows,
count) streams these into one packed table without per-record padding. Record
count/length, mapordinal and unused input bits are checked. Callers remain
responsible for exact field widths, valid existing LBL references, coordinates,
child IDs, source geometry/name matching, ordering and record semantics.

Production source is only the exact corrected original stock directory/profile
and L3 hash. Header length772, descriptor+600=directory/120/20/1 and all six
tables are read/derived from actual source callbacks. Physical order must be
level6→5→4→3→2→1→directory with exact adjacency/EOF. Original L6 count1973316
times68bits and L5 count2341096 times126bits end exactly on bytes; the writer
retains their complete original bytes and appends their new packed bits.
Nonbyte-aligned original6/5/4ending profiles are rejected rather than silently
concatenated. Appended final tails may be nonbyte-aligned and affect the next
table's physical start by their exact ceil-bit-length bytes.

Every original6/5/4record and unknown bit remains. All original47870L3records
widen111→112bits/w0=23 through the unchanged sealed pure insertion primitive;
new source patches only explicitly selected first/count fields. Each range
names next_level4/5/6 and the full original9-bit raw_flags. Both are checked
against the actual original L3 record. Old/new child ranges are bounded against
that exact corresponding table, not assumed to be level4. Selected count stays
12bits and common L3 first stays23bits. Original L4first22/L5first21and nested
child counts/refs remain unchanged; appending does not widen those fields.

Raw flags8/13query semantics are not established. Unselected raw8/13 stay exact;
an explicitly selected raw13 remains13 and next5. Changing13 to5, guessing a
new branch from raw8, or converting next5/next6 to another type is rejected.
The caller must separately determine which unchanged branches are eligible.

Header changes only directory-start+600. The directory rebuilds affected
starts/spans, with counts derived from span/stride. Only L3 stride/first width
change; all other width/flag/reserved words remain. Prefix before L6, complete
old6/5/4bytes, original L2/L1body bytes, and unknown header bytes are preserved.
Actual L2 directly follows L3 and supplies4-byte reader lookahead. No stray4-byte
lookahead is inserted into any table. Original L3's6unused tail bits have true
value0, bound to corrected-source-v2; nonzero unknown values are rejected.

Execution evidence:
  EXIT0, chunk2d2eae, wall time0.052120706seconds (tool receipt only).
  18new packing cases,40new rejection controls.
  New tiny three-table suffix→4K and suffix→8K container integrations.
  Large-capacity controls are size arithmetic only; no large stream allocated.
  One actual bounded original plan,722437original bytes read, L3read/widen once.
  Actual original clone-only groups: ID1next6,ID2next5,ID16707next4.
  Appended declarations: L6count1/68bits/9B; L5count10/1260bits/158B;
                         L4count84/10752bits/1344B.
  Selected new firsts:1973317/2341097/2133949, retaining counts1/10/84.
  Actual plan newMDR92661094bytes/directory92660974; original raw13ID5 preserved.
  Cached old group suppliers were not executed; actual new house count0.
  No original97MBcopy/full MDR stream/CPU/device/old closed suite was performed.

Proof SHA-256:
c78098d9b3ade7b804fe45e454bd0d0a115463bb479a71ca51829f8dbe9bf88b

The caller owns cleanup of partial destinations after supplier failure. This
is a record/container integration primitive, not completed country addresses,
new street/JAI/LBL/routing generation, full query/order verification, or device
acceptance. Country merge inputs and the eventual candidate need their own
structural/native/physical validation.
