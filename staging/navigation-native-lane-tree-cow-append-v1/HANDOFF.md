# Prepared current lane-tree COW appends

This scope produced and read back three actual packed append streams for 58,233 missing integer-house leaves under 20,613 lane/alley parents. It also prepared all 7,650 necessary current L3 range changes and copied-parent mappings. No full IMG, archive, USB, database, canonical report or device operation occurred. `native_write_ready` remains false until assembled-image preservation, native consumer, rollback and device checks pass.

The immutable base content is country v2, SHA-256 `925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb`. The producer checked its sealed device/inode/size/mtime identity and an unchanged fresh before/after stat during actual reads. Its ctime differs from the old seal because root had already made authorized package hardlinks. This is recorded explicitly; no whole image hash was repeated.

## Writer API

Import `append_api.py` and call `appends, changes, receipt = load_inputs(writer)` using the sealed current-profile writer module. It returns that writer's actual `PackedAppend(level, record_count, bit_length, supplier)` objects and `SelectedRange(streetID, first, count, nextlevel, originalflags)` tuple. It binds producer proof SHA-256 `1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9`, metadata pins and exact level profiles. Suppliers emit at most 65,536 bytes, then verify complete size, SHA and immutable stat at EOF. Root integration must treat a failed or partially consumed supplier as an incomplete result.

The loader was checked against the actual sealed writer source SHA-256 `71673de65c6e94da664ad8bc8b81307c37a6dfbf94d819eebfa888274b688c9e`, without opening a candidate or consuming suppliers. The writer's current-profile source is width23/stride112 L3. Lower profiles stay L4 128, L5 126 and L6 68 bits.

| Stream | Records | Significant bits | Bytes | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| L4 | 1,114,642 | 142,674,176 | 17,834,272 | `9764887df691fe22e757dc8541b057bad1f4bc72d42847d8fb9710950aece408` |
| L5 | 410,272 | 51,694,272 | 6,461,784 | `79f09d92efcf5a8bc98423a4bf2732171d773f7f984f2581a9769f204004ddad` |
| L6 | 78,705 | 5,351,940 | 668,993 | `1e3a20a95d92e22b53e32bb6aa2de54fdee674cd0e180645d04c085993330157` |

Every append stream starts independently at bit zero. Only its final byte has padding; L6 has four unused zero high bits. There is no per-group padding. Actual L5 group starts cover shifts 0/2/4/6, and L6 starts cover 0/4. The base L5 table has two unused final high bits: the current writer must splice only its `count * 126` significant bits before this append, rather than concatenate full bytes.

Final L4/L5/L6 counts derived from actual base directory and output counts are 4,896,236 / 3,077,845 / 2,062,771. The existing 23/22/21 first fields remain sufficient. The sealed overlay capacity estimate requires the explicit 8K container profile; the original 4K capacity does not fit this complete closure. Device acceptance of 8K remains unproved.

## Integration metadata

- `appends.json` describes the three tight streams; bin paths are relative to this directory.
- `selected-l3-range-changes.json` contains 7,650 current roots. Of these, 6,366 already used v2 cloned ranges and 1,284 still used stock ranges; both classes must be patched. Full original flags and current first/count are recorded.
- `emitted-cow-groups.jsonl.gz` contains all 29,866 groups, with bound current window/significant hashes, exact new first/count, relative append bit offset, explicit patch count, insertion ordinals and actual new significant-record hash.
- `cloned-parent-mappings.jsonl.gz` contains 22,216 current lower parents and their new encoded IDs. It retains original raw fields/payload, actual new payload and the exact first/count mask. L4 has 18,288 patches and L5 3,928. All other significant bits, including complete raw flags, references and coordinates, are identical.
- `new-lane-house-records.jsonl.gz` contains 58,233 new leaves in `(stock_parent_record, numeric_house)` order, with actual append offset/ID/payload, current v2 parent, new copied parent, group position, exact point/reference, complete source IDs and members, and the full sealed `source_ready_target` witness. There are 111,147 source-node memberships. Embedded earlier match-only flags remain historical witnesses; the outer joined target and actual payload fields carry this scope's values. Geometry and quantization were inherited and not reexecuted.
- `new-tree-parent-paths.jsonl.gz` contains 20,613 complete stock → current v2 → new COW paths, 24,442 ancestor links and all 7,650 roots. Every link's recorded next level and first/count reaches the exact copied child, with flags unchanged. It is prepared metadata; full actual IMG traversal remains pending.
- `prior-v2-new-leaf-identity-status.jsonl.gz` classifies all 130,637 existing v2 new leaves. The 51,332 within this closure have identical actual copied append payloads. The remaining 79,305 stay in the bound current base prefix; full preservation of that prefix in a new IMG is an integration gate, not a result of this append-only scope.

Patch and source IDs distinguish three locations: stock IDs, current v2 copies, and newly appended COW copies. Patching only a stock original parent would leave a v2 copied path stale. The producer patches the actual current parent's copied record and maps all ancestor links to the new group. Old child ordinals follow their records when house insertion shifts the merged positions; output mapping records include both old and new group ordinals.

The closure cloned 1,545,386 current old records: L4 1,114,642, L5 365,654 and L6 65,090. Their raw flags include 217 flag13 and 86,679 flag8 records. Unknown flags and nested branches are copied unchanged; this adds no interpretation or conversion policy. Only named first/count fields changed. Every original current record retains relative order inside its new group, and every other significant bit is checked against actual output-file records. New leaves use the unchanged stock-profile serializer with existing numeric text references and explicit zero child fields; no labels or JAI families were created.

## Receipts and remaining gates

Producer EXIT 0: session 87638, terminal `a77060`, source SHA-256 `42e2ae902b907121e57bfaf1761a16f2e15bf2bab40bd548aba74869a131df55`. Bounded candidate reads totaled 25,283,028 bytes in 41,881 operations; the image handle is closed. Reported process `ru_maxrss` was 424,240 KiB under the unchanged 512,000 KiB guard. A live PID receipt independently observed PID 801170 with VmHWM/VmRSS 404,592 KiB. The live value is a sample, not an asserted final peak, and audit-process peak was not measured. Elapsed receipts are not performance measurements.

Thirteen new tiny carry, ordinal-shift, explicit mask and rejection controls passed. Producer actual readback checked every retained current record, every explicit patch, every newly encoded leaf and every copied prior new leaf. A later output-only audit freshly checked all ledger hashes/EOF/stats, every real tight group's hash, independent fixed-profile masks and leaf fields, complete source-ID unions, exact copied-parent reachability, all root classes and prior identity totals. The complete-path supplement was derived from sealed current-path metadata and own mappings, then independently read back. The actual sealed writer API binding was checked without planning a map. No old main, CPU suite, full prepared source, PBF or geometry pass was repeated.

The next required scope is full current-profile IMG integration preserving all v2 significant prefixes, followed by independent actual tree/new-leaf/prefix readback, native CPU consumer checks, exact 8K→stock4K rollback and device acceptance. Native complete comparator/query/UI/routing and full Taiwan address coverage remain unproved.
