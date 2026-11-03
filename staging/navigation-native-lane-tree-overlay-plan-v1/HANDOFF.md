# Current native lane-tree overlay feasibility

All 58,233 qualified missing integer-house targets resolve through the actual sealed country v2 candidate. They belong to 20,613 existing lane/alley parents and 7,650 root streets. None is already present in its current final child group; none was held by this scope's path, numeric-anchor, count, collision or range-overlap checks. This is host planning. `native_write_ready` remains false throughout: no new leaf, descriptor, MDR, IMG, archive or device file was written.

## Actual current paths and clone counts

The base image is `navigation-country-native-candidate-v2/gmapprom1.img`, 128,356,352 bytes, SHA-256 `925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb`. Its root-created `sealed-files.json` SHA-256 is `659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766`. Only bounded records/groups and labels were read. The whole image SHA is inherited from completed builder readback and is not recomputed here. The exact seal stat matched before reads and was unchanged when the image handle closed; root may subsequently make a hardlink, changing ctime without changing the content bound by this receipt.

Of the 7,650 roots, 6,366 point to v2 cloned groups and 1,284 retain stock ranges. Selected groups were decoded from actual candidate bytes; removing their true kept-new leaf ordinals reproduced the pinned original significant-record sequence and hash. Original child IDs were mapped through those retained ordinals, then each resolved current child was checked against the candidate's unchanged stock record bits and exact GMP/LBL token text. This changed 15,035 final parent IDs. For example, 三民路二段154巷's stock parent `1073877774` is currently `1075875938`. Patching only the stock record would leave the branch used by v2 stale.

The deduplicated copy-on-write closure contains 29,866 groups. It must clone all current records in those groups and patch child links inside the appended copies, then patch the affected current L3 roots to the new group ranges.

| Table | Current records cloned | New house leaves | Proposed total records |
| --- | ---: | ---: | ---: |
| L4 | 1,114,642 | 0 | 4,896,236 |
| L5 | 365,654 | 44,618 | 3,077,845 |
| L6 | 65,090 | 13,615 | 2,062,771 |

All 58,233 source targets and their 111,147 actual source-node memberships are retained. All final-group numeric base anchors are nondecreasing, and the plan interleaves integer houses without changing old relative order. This does not establish the complete original firmware comparator or prefix query.

Among the actual final groups, 26,712 old records have nested children; raw child flags are 0 for 338,742 records, 8 for 23,004, and 6 for 26,712. Their significant bits are bound by actual current-group hashes. Mixed, nonnumeric and unknown child records are scheduled for copying unchanged, except explicitly named descendant range patches. No flag is converted. No unknown ancestor flag branch was encountered among selected paths; the planner would hold such a path. Raw13 decoding was checked in a new pure control, without modifying its bits or replaying a historical suite.

There were no exact-name closure collisions, partial overlaps among affected final or ancestor groups, or exact/partial current L3 root range aliases. All 47,870 actual L3 ranges were checked for root ownership using the newly read bounded L3 table. Lower-level owners outside the affected paths were not scanned globally; copy-on-write retains their old views and introduces no inferred name equivalence.

## Integration ledgers

- `current-path-mappings.jsonl.gz`: 20,613 stock-to-current paths. Each edge identifies the actual current parent, its exact child group, mapped current child ID and ordinal. The stock parent witness remains intact.
- `planned-parent-groups.jsonl.gz`: 20,613 final groups with stock parent, current path, actual group window/significant hashes, old child raw-flag counts, missing source targets and host numeric insertion ordinals. Targets contain exact source coordinates, planned raw24, existing label ref, complete source IDs and group IDs from the sealed source join.
- `held-parent-groups.jsonl.gz`: zero rows for this actual input. Its empty ledger is hashed and EOF-checked.
- `transitive-ancestor-groups.jsonl.gz`: 29,866 deduplicated actual groups. Each row names current parent owners, full current group receipt, clone count, new leaf count, proposed append first/count, integer insertions and explicit child patches to another planned group.
- `capacity-and-width-plan.json`: exact resulting table spans/start/counts, first-field requirements, physical suffix layout and capacity arithmetic.
- `candidate-bounded-read-receipts.jsonl.gz`: 88,520 physical reads totaling 26,402,727 bytes. Every relevant group has a separate actual window and significant-record hash. No full map copy or source/PBF rescan occurred.

Group keys are `(level, current_first, current_count)`. `planned_new_first` is a one-based ID in that same table. Patch `current_child_ordinal` is an ordinal in the current old group; it must follow that record when integer insertions shift positions. A writer can patch the named old record's first/count, preserve all other fields, then interleave the new leaves; it must not treat the old ordinal as the final merged ordinal. Final-house insertion ordinals are the new merged positions. No target/parent/raw field may be inferred from a source-street name.

The future writer must reread each bound current group, verify its hash, and preserve every old significant bit except those explicitly allowed range fields. These ledgers contain receipts and patch plans, not newly encoded records or a preservation claim for an output map. The source join's geometry/quantization scope remains unchanged: complete-city checks outside Kaohsiung, exact complete districts inside Kaohsiung, and host raw24 rounding without an original compiler rounding claim.

## Width and capacity

The largest new first fields are L3 4,896,135, L4 3,074,291 and L5 2,062,754. They fit their current 23-, 22- and 21-bit fields respectively. The final L6 count 2,062,771 also lies below 2,097,151, with 34,380 remaining. No lower-table first-field widening is necessary for this plan. L4's total count exceeding 4,194,303 is valid under these descriptors because the L3 first field that points into L4 is already 23 bits; L4's own 22-bit first field points into L5 or L6.

The replacement MDR would be 149,220,356 bytes, with directory start 149,220,236. Its physical order remains L6 → L5 → L4 → L3 → L2 → L1 → DIR, each table using the minimal significant-bit span. No synthetic four-byte lookahead belongs inside a declared table span.

The exact 4K allocation estimate is 153,337,856 bytes, with 161 FAT rows and directory extent ending at 90,112. It exceeds the original declared container capacity 134,217,728 bytes (128 MiB) by 19,120,128 bytes. This is a capacity failure for the original container profile, not a platform maximum. The explicit 8K profile estimates 153,346,048 bytes within its 268,435,456-byte capacity, but actual device acceptance is unproved. The estimate follows the sealed reblock arithmetic; an integration must still validate original header/continuation metadata requirements in that adapter.

## Required implementation and rollback

The existing sealed multilevel writer accepts the corrected stock original profile and selected L3 ranges. It does not accept v2 as a current-profile source, patch lower parent records, or handle its L5 non-byte-aligned final padding when appending a new bitstream. A new current-profile MDR descriptor/tree writer is required. It must preserve current significant-bit prefixes, discard only unused final padding, pack appended groups continuously, patch the current copied ancestors, preserve complete flags/references/coordinates, rebuild affected spans/starts/counts, and use the actual subsequent L2 bytes as L3 reader lookahead.

Since lower-table widths stay unchanged here, their stock significant prefixes can remain recoverable. An 8K output would still need verified original 4K reconstruction and L3 23→22 inverse restoration for a compact exact rollback. If a future plan widens L4/L5 first fields, byte-prefix truncation rollback becomes invalid: it needs a streaming inverse bit-width reencode restoring all original fields, table descriptors and container layout. Neither a new writer nor this rollback was implemented in this planning scope.

The planner completed EXIT 0 in session 53787, terminal chunk `350085`; the image handle is closed. Process `ru_maxrss` reported 424,240 KiB, below the unchanged 512,000 KiB guard. This is the planner process's reported peak, not workspace memory or an audit peak. A tiny measurement-provenance check reads no task data. Elapsed time is an execution receipt, not a performance result.

Fourteen new pure planning controls passed. Only final candidate seal filename/SHA/stat bindings were added afterwards; exact AST equality records that the tested mapping, numeric ordering, overlap and raw-field functions are unchanged. A fresh output-only audit verified every new ledger's compressed/plain hash, EOF and stat, independently summed clone/leaf/source totals, checked continuous append ranges and every transitive patch's current ID/group target, and confirmed the minimal physical table spans and capacity distinction. It reopened no original candidate, source, geometry or CPU suite.

Native consumer/order/query/UI, 8K device acceptance, implementation preservation, rollback and physical routing remain unproved. No full native address update completion is claimed.
