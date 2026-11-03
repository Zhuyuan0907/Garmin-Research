# Current-profile COW MDR and explicit AP8K container API

This new API accepts the exact sealed country v2 source, preserves current lower
significant-bit prefixes, and patches explicitly selected current L3 roots. The
append producer is responsible for cloning current lower parent groups,
patching their permitted child first/count fields, and encoding new house
leaves. The writer does not infer a parent by name or modify any existing lower
record. There is no default output, device/USB action, canonical destination,
CLI installer, or automatic fallback to a wider profile.

## Integration

Load `current_profile_cow_writer.py` by importlib and register its module in
sys.modules before executing it (dataclasses require this). Set
sys.dont_write_bytecode=True to keep frozen directories unchanged.

```
with open(exact_v2_source_path, 'rb') as f:
    image = writer.eight().Source4K(f)
    adapter = writer.Explicit8KAdapter.from_container(image)
    appends = {
        level: writer.PackedAppend(level, record_count, record_count*stride,
                                   repeatable_bounded_chunks_supplier)
        for level, stride in [(4,128), (5,126), (6,68)]
    }
    selected = [writer.SelectedRange(one_based_street_ID, first_child, count,
                                     next_level, original_flags) for ...]
    plan = writer.plan_current_mdr(adapter.source, appends=appends,
                                   selected_ranges=selected)
    bound = plan.bind_container(adapter)  # capacity check; no supplier read
    # Only after independent producer proofs and parent authorization for
    # full candidate integration: bound.repack_stream(new_empty_destination).
```

Use the Source4K type returned by this module's `eight()` loader, rather than a
separately loaded class with the same name. `adapter.source` exposes exact
reads <=64KiB and streaming chunks <=64KiB for producer metadata/group reads.
Logical component requests map through actual source FAT allocations.
Production bindings pin exact v2 source path, inherited whole-image hash,
size/dev/inode/mtime, header and directory profile, complete actual L3 hash,
and captured current ctime. Root-created hardlinks may change ctime since the
prior seal; current ctime is captured and must stay unchanged while in use.
A full source hash is inherited from the completed v2 readback and is not
recomputed by bounded source construction.

Packed append declarations are mandatory for all three levels, including
explicit `PackedAppend.empty(level)` for a zero stream. A supplier must be
repeatable, yield nonempty byte-like chunks <=65536 bytes, and contain exactly
ceil(record_count*stride/8) bytes. Only its final byte may contain padding, all
high padding bits zero. Every record's first bit is AP mapordinal1. Optional
`PackedAppend.from_records(level,count,callable)` accepts individually padded
records and packs them continuously. This does not prove leaf encoding,
original comparator ordering, source geometry, or cloned-parent correctness;
those belong to producer proof and full integration readback.

SelectedRange fields match the producer's `selected-l3-range-changes.json`
keys. Current_first_child/current_count/was_selected_in_v2/group_key are
provenance fields for independent review; the writer derives the old range
from actual112-bit L3 bytes and checks original_flags/fullbranch itself. All
7,650 affected current roots need patches:6,366 were already selected in v2,
plus1,284 retain stock ranges. Arbitrary current branches4/5/6 are supported;
there is no restriction to the prior selected subset. COW new ranges must
lie entirely in the appended matching lower table, with nonzero12-bit counts,
23-bit first fields, and no selected output overlap/alias. Raw flags cannot
be converted. The entire remaining L3 payload stays byte-verbatim.

## Significant bits and width limits

Source L3 is already112 bits with first width23. It is not reencoded111->112.
Current table counts are L4=3781594,L5=2667573,L6=1984066. Appends for the
planned COW closure are1114642/410272/78705 rows, yielding counts
4896236/3077845/2062771. Lower strides remain128/126/68. Current L5 ends in
2 zero unused bits; the writer streams exactly its count*126 valid bits and
then immediately begins append bits in the same byte. It never concatenates
its padded byte span with an append's first byte. Each rebuilt table has only
one final zero-padding tail. Current significant prefixes are retained; a
non-byte-aligned current prefix is not promised as a complete byte prefix.
Original stock lower prefixes are byte aligned and remain recoverable.

Incoming first widths remain L3->L4=23,L4->L5=22,L5->L6=21. Their corresponding
new table count maxima are8388607/4194303/2097151. L4 total4896236 exceeding
4194303 is valid: its incoming pointer is in L3, already23bits. No lower first
field is widened. Header changes only the MDR directory start; directory
changes only table starts/byte spans, retaining complete descriptor bitfields.
Unknown header/prefix/L2/L1 bytes remain unchanged. L3 lookahead uses actual
following L2 bytes; no synthetic four-byte gap is inserted.

## Explicit container and restore handoff

`bound.capacity_plan` comes from the sealed AP8K primitive. The complete
replacement MDR length149220356 gives planned AP8K IMG153346048, below
268435456 bytes (256MiB) declared capacity. Original AP4K capacity134217728
cannot hold that COW result. Capacity binding precedes append consumption or
any full output write. Uniform per-component continuation metadata is
required because AP8K reblocking can discard continuation rows. Exact six
component paths/order, author/license/unknown prefix bytes are preserved.
Only allocation header fields change; byte15 is set to zero by the sealed
adapter. The original AP checksum algorithm and real device acceptance are
unknown. This is not a GarminOS platform maximum or an installed update.

`output-layout-contract.json` defines the future normalized actual readback
descriptor for the separate restore API. It requires actual whole/output
metadata hashes and FAT row bytes; this scope creates no such output image or
descriptor. `actual-current-source-layout.json` describes SOURCE4K only and
must not be passed as an8K output descriptor. Exact stock restore additionally
binds the closed stock recipe and performs actual prefix/inverse-L3 checks.

## Actual verification here

The NEW controls passed8 positive cases and39 rejecting controls, using an
independent absolute-position bit reference and manual FAT reader. Tiny
fixtures cover current L5/L6 partial tails, all eight bit carries,64KiB carry,
raw13 preservation, producer-owned cloned-parent payload edits, all three L3
branches, zero-append identity, unknown prefix/L2/L1/descriptor preservation,
explicit4K->8K full six-component/metadata/tail/prefix readback and lazy
planning/capacity. Guards cover profile mismatches, current-source changes,
wrong flags/branches/selection/counts, truncated or malformed packed streams,
unchanged-width capacity limits, source reads, output alias/nonempty output,
and explicit AP8K capacity overflow. Historical test runners were not invoked.

A separate actual v2 bounded source check read183 physical fragments totaling
744805 bytes. The largest physical read69120 bytes is the fixed source FAT
metadata extent from the inherited parser; MDR logical reads/chunks stay
<=64KiB. It verified the exact descriptors/counts/profile and complete current
L3 hash, zero current lower padding, and explicit planned AP8K capacity without
consuming any actual append supplier. No original lower tables were fully
read. Root/producer are responsible for full actual closure/tree preservation,
all new leaves, resulting component hashes, native CPU/query/UI and device
search/routing tests. No large append/MDR/IMG, source-ledger/PBF scan,
installer, ZIP, service, report, canonical or device writes occurred here.
