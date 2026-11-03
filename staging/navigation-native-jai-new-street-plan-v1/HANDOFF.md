The finite new-street JAI/FTS8 prototype scope passed and is ready to seal.

No existing JAI/new-street writer was found. The new source is
`jai_family_writer.py`: a small explicit single-family migration plan plus
atomic SQLite sandbox mutation, with12 new controls. This is a partial sandbox
writer, not a full original-DB adapter or complete frontend writer. See
`WRITER-DESIGN.md` for exact schema, API, width limits and remaining primitives.

One actual original family was read: 台中市→北屯區, districtrecord0x2000004A,
originalStreetIDs12924..13364,441 named/441 physical records/no hidden slots.
The original L2ID74 first12924/count441/fullflags3 exactly matches the JAI family.
The sole family moves to L3 tail47871..48311 and 敦富六街 uses48312; newinfo.id48219,
L2 first47871/count442 preserves first16/count10/fullflags3. Existing info IDs,
all1444 selected FTS tuples, old encoded names and allother family boundaries
stay unchanged. A second disjoint family with the sameparent is prohibited by
the original UNIQUE constraint. All441 old name hostqueries plus the new exact
name and street→district→city chain passed. Partial SQLite155,648B is not an
install candidate.

The actual original tiny prefix lookup for newfirstchar敦 returned no entry.
Existing 一 points prefix_id28→seg_id1116, whose84-byte raw blob has21 u16 pairs;
their field roles/native interpretation are not proved. The older sealed
seg_id2 sixinfoID/suffix links are referenced without rerunning that case.
New prefix/segment serialization is missing, so host FTS3 success does not
close the complete frontend.

Actual original capture EXIT0/terminala67d00. Externally traced source DB reads
4,903,012B/4,786operations (fixed original DB path only, mmapdisabled), plus
54,456B original AP metadata/directory andone L2 record. Exact original stats
were unchanged. No sourcegroup ledger/PBF or currentv3 IMG was opened. Source
and geometry were inherited from the separately sealed source example, not
rerun here. No old main, CPU case, firmware scan or completed suite ran.

New synthetic writer controls EXIT0/5dc6b2. Actual family/FTS8 sandbox
EXIT0/524ac6, proofSHA5e41d4e96face4dc960966494f91599af37413eef4468d363295efd33b1f2dbd.
Source binding EXIT0/9daa7f binds the sealed source candidate
d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c:
group37506/node8280986017,敦富六街368號,sourcepoint24.1882244/120.7079937,
raw24[1127253,5625400],existinghouse ref2967. Both source/raw24 full台中city
geometry gates passed in that separate source scope. Historicalalias,
official/physicalnewroad,addressauthenticity,北屯polygon,streetrepresentative
point policy and device/UI/query/route acceptance remain unproved.

`source-candidate-binding.json` contains complete inherited source provenance,
the441 old→new ID mapping, original L2 fields and next house slot4896237.
441 currentv3 L3 copies plusone new112-bit street require6188 bytes;one L4house
adds16 bytes. This is planning arithmetic. No MDR/GMP/IMG/ZIP/USB/canonical
write occurred here. Root has prepared a separate actual current441-record
payload source and label plan; this scope did not modify or consume those bins.

The next writer must copy currentv3 L3 fields (first23/stride112), not original
stock111-bit child ranges, and explicitly patch L2 only first/count. Newname
label allocation is supplied by root's separate label helper. Prefix/segment
writer and native consumer proof remain necessary before a frontend-ready
claim. `native_write_ready=false`, `install_candidate=false`, and full Taiwan
native address update is still incomplete.
