There is now a small JAI family/FTS8 writer prototype. It operates on a new
partial SQLite sandbox, not the original database or a complete install package.
No new-street writer existed in the local sealed evidence before this scope.
Existing code supplied a pure token codec, actual original-instruction codec
proof, stock AP reader and JAI record-to-packed reader bridge.

The actual original schema is:

```sql
CREATE TABLE japan_addr_info
  (id INTEGER PRIMARY KEY, index_record TEXT, record INTEGER);
CREATE TABLE japan_addr_family
  (parent_record INTEGER UNIQUE, the_first_record INTEGER PRIMARY KEY);
CREATE VIRTUAL TABLE japan_addr_index_8 USING FTS3
  (index_record TEXT, record_info INTEGER);
CREATE TABLE japan_addr_prefix
  (prefix_id INTEGER PRIMARY KEY, index_record TEXT, seg_id INTEGER);
CREATE INDEX japan_addr_prefix_index ON japan_addr_prefix(index_record);
CREATE TABLE japan_addr_segments
  (seg_id INTEGER PRIMARY KEY, segment BLOB);
```

The three integer spaces are separate: `info.id` is a SQLite key;
`FTS.record_info >> 8` is that key; `info.record` is the packed logical key
`level << 28 | one_based_recordID`. FTS bits4..7 match the level, while the
complete low4 flag policy remains unknown. The prototype uses explicit observed
ordinary fullstreet lowbyte0x31. The original selected family has412 full-name
entries with0x31 and29 with0x30; no general normalization/annotation policy is
inferred from these observations.

Original SQL selects info rows by `id IN (SELECT record_info >> 8 FROM
japan_addr_index_8 WHERE index_record MATCH ?)`. Therefore a host query can use
new global info.id48219 in index_8 without renumbering the old city8 info IDs.
This does not verify all native frontend branches. All existing info IDs,
encoded names, FTS rowids/tokens/record_info and old prefix/segment info-ID
references stay stable when only selected `info.record` keys change.

One parent has exactly one family start. The predecessor query
`the_first_record <= child ORDER BY the_first_record DESC LIMIT 0,1` cannot
represent a second disjoint new range for the same parent. The prototype moves
the complete441-record 北屯區 family to L3 tail, preserving every old physical
slot in original relative order, then adds one new street. This selected family
has441 named rows and no unnamed physical slots. The library's synthetic guard
also checks a family containing an unnamed physical slot.

The exact minimal plan is:

| Value | Original | Proposed |
|---|---:|---:|
| City logical record | 0x10000008 | unchanged |
| District logical record | 0x2000004A | unchanged |
| District info.id | 12988 | unchanged |
| District L2 first/count | 12924 /441 | 47871 /442 |
| Old district StreetIDs | 12924..13364 | 47871..48311 |
| New 敦富六街 StreetID | absent | 48312 |
| New info.id | absent | 48219 |
| Final L3 count | 47870 | 48312 |
| L2 first/count widths | 16 /10 | unchanged |

L2 fullflags3, map ordinal, both references, raw24 and every other significant
field must remain exact. The L2 first/count patch mask is the16-bit first field
at bit39 and10-bit count field at bit55. All441 L3 copies must come from the
current v3 112-bit records (first23), preserving their current child pointers,
counts, flags, references and coordinates. Copying the original111-bit street
records would lose prior address updates. The original physical L3 prefix stays
unchanged; selected old info rows move to the new range. The retired old range
has no live selected info rows. Other family boundaries remain unchanged.

`jai_family_writer.relocation_plan(snapshot, street_text, encoded_text,
current_L3_count=..., new_info_id=..., full_name_low_byte=49)` returns every
physical old→new key mapping, the sole family change and the L2 patch.
`make_sandbox(path,snapshot)` creates a caller-owned partial DB.
`apply_relocation(connection,snapshot,plan)` checks exact preimages and performs
the info-key remap, one family-start update, one new info row and one full-name
FTS row atomically. Failed preimages roll back earlier updates. It preserves
all1444 selected old FTS tuples. It generates no MDR or LBL bytes.
This version requires the connection's entire index_8 to equal the selected
snapshot, so it deliberately accepts the prepared small sandbox rather than a
full stock-DB copy. A full-DB adapter must validate only the selected info-ID
scope and separately preserve all other index_8 rows; that adapter is not part
of this prototype.

The actual155,648-byte SQLite sandbox passed every441 old name query with the
same info IDs/tokens and intended new record keys; all old FTS tuples remained
exact. The new exact-name host query and original SQL predecessor chain reach
敦富六街→北屯區→台中市. Other families are unchanged and quick_check returns ok.
The sandbox uses4096-byte pages and includes only families, selected old name
rows, the selected city/district and FTS8 rows; it is explicitly incomplete.
A later complete DB writer must preserve the original DB's pragmas, metadata,
license, all other tables/indices/rows and format, and apply the atomic plan to
a new full original-DB copy. No original copyright/author metadata is changed.

Prefix/segment support is the concrete remaining indexing blocker. Actual
original lookup of encoded firstchar敦 returned no prefix entry. An existing
一 entry is prefix_id28→seg_id1116; its84-byte actual blob contains21 raw pairs
(1,1074),(2,1076),…,(21,1114). Their roles are not established. The sealed older
schema evidence additionally supplies a102-byte seg_id2 witness with six chained
entries containing info IDs231..236, flags1, lowbyte0x31, next offsets17..85/0,
and encrypted suffixes linked to info.index_record. That old sample is referenced
without rerunning its case. The new writer does not assume these two blob forms
are interchangeable, does not append a fabricated prefix entry, and does not
claim the native segment consumer is closed.

The next production primitives required are (a) a current-profile MDR L3 append
and explicit L2 field-mask patch writer with actual following-table lookahead,
(b) the separately prepared aligned CP950 label-pool helper, and (c) a bounded
prefix/segment serializer plus original consumer proof. A single additional L4
house would require16 bytes;441 current L3 copies plusone new112-bit street
require6188 bytes. These do not require wider lower tables or L2 widths for this
example. Layout/count/capacity must be derived again from the actual chosen base
by that later writer, rather than treating this arithmetic as completed output.

The source-name candidate is sourcegroup37506/node8280986017, raw source address
臺中市/北屯區/敦富六街/368. A separate sealed source scope checks the source and
raw24 points in the complete 台中市 polygon; no complete 北屯區 polygon,
historical alias, physical new-road, compiler street-centroid, native UI,
complete query, route or device acceptance is proved here. No PBF/source ledger
was reread by this scope; current v3 IMG/ZIP/CPU/review stayed sealed. Host FTS8
success does not close the full frontend. `native_write_ready=false`.
