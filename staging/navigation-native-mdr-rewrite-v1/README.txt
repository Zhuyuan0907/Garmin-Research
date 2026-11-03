Offline MDR suffix writer — version 1

mdr_suffix_writer.py prepares a streamed replacement of 00004171.MDR from
the stock original AP container. It does not create a map by default and has
no device, service, publishing, or installation command.

Use the same sealed core classes for parsing and repacking:

    import mdr_suffix_writer as mdr
    core = mdr.core
    with original_path.open('rb') as original_file:
        image = core.StreamIMG(original_file)
        source = mdr.MDRSource.from_container(image)
        plan = mdr.plan_mdr_rewrite(
            source,
            new_l4_count=number_of_appended_16_byte_records,
            new_l4_supplier=lambda:iter_appended_byte_chunks(),
            selected_ranges=tuple(mdr.SelectedRange(ID, first, count)
                                  for ID, first, count in explicit_ranges))
        replacement = plan.replacement()
        # An integrating caller supplies a distinct, empty destination.
        receipt = core.repack_stream(
            image, destination, {'00004171.MDR': replacement})

Run callers with python3 -B. Keep the original stream open until repacking
returns. The Replacement class is the one loaded as mdr.core.Replacement;
mixing independently imported copies of the sealed module can fail its
intentional exact-class check.

MDRSource.from_container binds read/stream callbacks to the original logical
component and the original container capacity planner. A custom MDRSource
must provide callable read_range(offset,length), range_supplier(offset,length),
unchanged(), and, for production, capacity_plan(new_MDR_size). Bounded reads
return exact immutable bytes. Stream suppliers yield nonempty bytes-like
chunks of at most65536bytes, covering their explicit range exactly. Appended
record boundaries may cross chunks. Typed memoryviews are counted by nbytes.
Each complete appended16-byte record must retain AP mapordinal1. The caller
must validate record fields, coordinates, existing label references, ordering,
and source join semantics separately; this primitive does not invent them.
Suppliers are not consumed during planning. For repeat consumption, suppliers
must start a fresh complete stream on each call.

Production accepts the original772-byte header, header+600 descriptor120/20/1,
and the exact original directory/table binding from corrected-source-v2.
Locations are parsed from the original directory, rather than copied from a
prior candidate. Physical order is level6,5,4,3,2,1,directory, with exact
adjacency and directory EOF. Original level4 bytes and the prefix through
its end are copied, followed by supplied new level4 records. Existing47870
L3 records widen111→112bits, w0=22→23. Only explicit valid original next4
street ranges may change first/count. Other flags, refs, coordinates, IDs,
and next5/next6 relationships rely on the unchanged sealed purewriter and
its separately sealed corrected-source verification.

Header mutation is only the directory-start word at600. Directory mutations
are level4 size; level3 start/size/stride and word3 bits18..23; level2 and
level1 starts. All other directory bits, original level2/level1 bodies,
level5/level6 tables, and unknown header/prefix bytes are retained. Actual
L2 bytes immediately follow the new declared L3 span and provide its4-byte
reader lookahead. No extra zero bytes are inserted into any declared span.
The real original L3 has6unused tail bits with value0, as corrected-source-v2
proved. This writer rejects nonzero unknown tail values rather than silently
discarding them.

The sealed repacker rebuilds allocation within the original declared
134217728-byte capacity (128MiB). Geometry expansion is not implemented.
This is an original-container constraint, not a Garmin platform maximum.
Planning rejects capacity overflow before reading L3 or consuming appended
records. The integrating caller owns destination cleanup after a failed
stream; a partial result is not a completed candidate.

New verification only:
  python3 -B staging/navigation-native-mdr-rewrite-v1/test_mdr_suffix_writer.py

The test refuses to overwrite its terminal proof. It executed small six-table
fixtures,35MDR-specific rejection cases, a small in-memory suffix→sealed
repacker integration, and one bounded original plan with a new selected range.
It did not repeat the closed all47870field-preservation/240-block/CPU suites.

Actual original plan:
  Appended demonstration85rows: cached original84 plus existing-reference6號.
  Selected street16707 first2133949 count85.
  Derived original L3 start91983716 / bytes664197 / stride111.
  New L3 bytes670180, start91985076; L2start92655256; L1start92660487.
  New directory92660823; MDRsize92660943; container plan96747520bytes.
  Original bytes read723329 (722437positive plan +892capacity guard).
  L3 bounded reads1; width rewriter calls1; actual full stream executions0.

Proof SHA-256:
4874e42f936a275a3b7f9e4fcdd293f66c9d413f8c8ba80d96f9adb91fc45a07
Actual tool execution: EXIT0, chunk2048f5, wall time0.03137333seconds.

This supplies the integration primitive for existing streets. It is not a
new-street hierarchy/JAI/LBL/routing writer, completed nationwide address
update, complete native-query proof, physical test, or installable candidate.
