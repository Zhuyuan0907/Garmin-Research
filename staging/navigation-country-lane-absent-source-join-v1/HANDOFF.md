# Existing lane absent-house source join

This is a read-only source and geometry planning result. All 76,849 absent keys from the sealed existing-lane match were joined to their actual prepared source groups. Of these, 58,233 integer house targets qualify for later native-tree planning: 44,618 would use level 5 leaves and 13,615 level 6 leaves, under 20,613 original parent records. The other 18,616 targets remain held. No native records, map, database, package or device files were changed.

## Integration files

- `ready-lane-house-targets.jsonl.gz`: 58,233 targets, strictly sorted by `(actual_parent.record, numeric_house)`. Each target has its exact parent, old range and path, existing house-label reference, complete source node IDs, exact selected Decimal coordinates, planned raw24 point and both geometry decisions.
- `held-lane-house-targets.jsonl.gz`: 18,616 targets with complete source provenance and explicit reasons. A held target must not be admitted merely because it has a label reference or a point.
- `ready-parent-summary.jsonl.gz`: 20,613 original parents in numeric record order, with qualified house-target and source-group counts.
- `joined-absent-source-groups.jsonl.gz`: all 76,849 selected source groups in prepared-ledger group order. The `members` retain both the actual prepared source information and the upstream exact lane-match evidence.
- `sorted-joined-runs/`: sixteen durable sort runs, at most 5,000 joined groups each. These and the joined provenance are retained rather than deleted before sealing.
- `proof.json`, `output-readback-proof.json`, `execution-receipt.json`, `terminal-tool-receipts.json` and `seal.json`: source pins, input and output EOF/hash/stat receipts, scope limitations and exact tool sessions.

The reader API is gzip JSONL. Use only rows with `planning_eligibility == "source_join_geometry_ready"`, empty `reasons`, both geometry decisions eligible, and `source_and_native_points_checked == true` for further planning. Every row still has `native_write_ready == false`. The writer must first construct a true tree overlay preserving old ranges, paths, flags and any earlier relocated clones; an original encoded parent record must not be treated as the automatically current parent in another candidate. No JAI family append or native house-order policy is implied.

## Target schema

`actual_parent` contains `record` (encoded native record), `level`, `ID` (level-local ID), `label`, `raw_flags`, `high_flags`, `next_leaf_level`, `old_first_child`, `old_child_count`, `root_street_record`, `path_record_ids`, `path_tokens`, `city`, `district` and `source_full_street`. These fields are inherited unchanged from the sealed actual-original lane traversal. Only known direct house branches were admitted upstream; this join introduces no flags policy.

`house_label` is the exact resolved house text; qualified `numeric_house` is its positive integer value. `primary_ref` is the pinned existing global house-label reference and is not a house-membership proof. Original exact leaf membership was `absent` for all joined targets.

`source_group_ids` identify prepared groups. `source_ids` are the complete sorted unique actual node IDs recovered from those groups; `source_node_count` is their length. `source_members` retain raw and normalized address values, original group classification, coordinate status, group node IDs, floor/unit metadata, old native parent and embedded `actual_absent_house_matching_plan`. The embedded plan is a historical witness: its `coordinate_values_available:false` and `complete_source_IDs_available:false` describe the earlier match-only stage, while the outer joined fields provide the recovered values. Do not mutate or read the historical flags as current join readiness.

`selected_coordinate_strings` is `[latitude, longitude]` in exact Decimal degrees, or null. `planned_raw24` is `[latitude_wire_u24, longitude_wire_u24]`, or null; signed interpretation is two's complement in 24 bits. Quantization uses the pinned prototype nearest signed24 circle conversion with Decimal ROUND_HALF_UP. Stock rounding has not been established. Original source coordinate strings are retained in each member.

Coordinates are selected only when every contributing group is coordinate-ready and all points are exactly equal as Decimal values. Equal decimal values with different string scales may coalesce; unequal values, references or parent plans hold the whole target. No cross-group coalescence occurred in this actual dataset: 76,849 source groups produced 76,849 targets. Conflicting groups retain complete node IDs and an explicitly unselected historical first-coordinate witness, not all node-specific coordinates. Their selected point and planned raw24 remain null.

`source_geometry_decision` and `exact_raw24_geometry_decision` check both points. Outside Kaohsiung the applicable complete city polygon is checked, without a geographic district claim. Kaohsiung uses the pinned exact district engine and exact raw administration; its 37 complete districts qualify, while incomplete 旗津 geometry stays held. The native point is tested as its exact signed24 rational coordinate; no intermediate rounding to the boundary engine's coordinate grid is used.

## Counts and limits

Held reason counts overlap: noninteger/subnumber 17,834; coordinate conflict or unavailable 740; missing/invalid existing numeric label reference 46; same-city geometry 1; same-district geometry 89. The district holds consist of 11 outside-district cases and 78 incomplete 旗津 cases. Qualified source node memberships are 111,147 and held memberships 28,739. No count extrapolates to unmatched source addresses, new streets or full Taiwan coverage.

The initial driver failed its unchanged 500 MiB memory guard during a partial prepared-source scan at row 2,600,000. Its exact source, exception, progress and terminal receipt are archived. The last printed peak was 506,704 KiB; the peak after the guard was not recorded. No source EOF/pin acceptance or final target acceptance occurred in that attempt.

The corrected driver kept raw key bytes on disk/in a bounded index, streamed joined provenance and 5,000-row sort runs, released the key index progressively and loaded geometry after prepared-source EOF. It completed one full prepared-source pass with a measured process peak of 424,240 KiB (about 414 MiB), below the unchanged 512,000 KiB guard. Overall there were two prepared-source read attempts: one failed partial scan and one corrected full scan. The corrected pass read all 4,630,959 rows and verified the inherited compressed pin, EOF, row count and unchanged stat. Its plaintext SHA-256 `b2192b640fa6ca662180d86148c14ee4991acef8d6fc81a89cdade06a9994b9e` is newly established; no prior plaintext pin existed.

Seven new pure eligibility controls passed on the archived initial source. The corrected source has an identical eligibility AST, recorded separately; the controls were not replayed. A later output-only audit freshly checked ready/held/parent/provenance compressed and plaintext hashes, EOF and immutable stats, strict ready numeric order, complete source-ID unions, flags/leaf-level consistency, both geometry acceptance witnesses and no coordinate selection for conflicts. It did not reopen the prepared source, original map or geometry engine. The 424,240 KiB peak applies to the corrected join process, not the output audit, all historical attempts or the whole workspace. Elapsed receipts are not performance measurements.

Actual tree overlay, packed-group preservation, capacity, native consumer/order/query/UI/route and device acceptance remain required. This scope performed no original-map access, CPU execution, PBF extraction, exact-ready ledger rescan, device I/O or historical suite replay.
