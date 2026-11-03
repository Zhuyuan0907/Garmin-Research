The 128 MiB restriction is the original AP container profile, not an established
universal 4 KiB format, OS or native CPU limit. The sealed 4 KiB writer computes
min(header-u16-block-count × 4096, partition-sector-count × 512) and deliberately
retains the stock 32768-block / 262144-sector declaration. Keep those old guards.

Four actual IMG headers (2048 bytes total) were read without a whole-image
hash rerun. Original AP and v2 have identical first512 bytes, 4 KiB blocks and
byte0x0F=219. V3 has 8 KiB blocks and byte0x0F=0; its five changed byte offsets
are 0x0F, 0x18, 0x5F, 0x62, 0x1CC. Searchv2 uses 2 KiB blocks and a header
block count64371, above32768. Its current physical rendering success is a
parent-provided observation, not a test run by this review.

The six complete v3 component sizes need153337856 bytes at4 KiB:37436 physical
blocks,161 FAT rows and90112 metadata bytes. The largest used block would37435,
below the65535 sentinel. MDR alone is149220356 bytes, already larger than the
original128 MiB capacity; shrinking FAT/padding cannot preserve the complete
v3 payload inside that declaration. An expanded4 KiB profile is arithmetically
possible, with at least299488 partition sectors, but is not yet an accepted
container or a safe device candidate. Semantic COW compaction would be a
separate tree rewrite with a different validation scope.

Existing frozen original instructions provide useful evidence: shared embedded
DSKIMG parser1E8046 loads header0x63 as unsigned16 at1E8304..1E8316; its allocation
bound comparison at1E85D4..1E85DC is unsigned. Allocation translator123920 loads
a uint16 FAT block at1239D6, recognizesFFFF at1239D8, then shifts by the runtime
block exponent at123A44..123A46. The closed parser has no explicit32768 constant.
This lower parser was identified and executed in prior VPM filesystem scopes.
It is not a proof that AP high-level admission/checksum policy is identical.

The v3 native CPU proof used a Python IMG FAT/geometry mapper. Original CPU
executed MDR header/directory and finite packed-prefix/LBL fragments. It did
not run the full AP IMG admission, metadata getter, query, registry or rendering.
The physical A/B therefore does not establish that8 KiB alone caused the road
visibility regression; COW/high-child references and map-layer interactions
remain alternatives. Byte0x0F's original AP checksum algorithm and enforcement
remain unknown. The mkgmap reference's zero-byte policy is not a target-device
acceptance proof. Do not synthesize a checksum or weaken the sealed old guard.

Minimum recovery: use the existing sealed v3 --rollback, exact original hash
readback and safe unmount. After cold start, use stock AP+Searchv2 with original
CN unchecked for one road-visibility observation. Keep CN available as the
recovery layer. If that baseline works, a subsequent already-sealed4 KiB v2
test can separate larger-MDR/layer effects from v3-specific COW/geometry changes.
A geometry-focused test requires a separately validated expanded4 KiB profile
carrying all six identical v3 logical payloads. That profile is not ready now.

No IMG/component, device, firmware, sealed installer, report, canonical or
service was written by this scope. No closed suite or native CPU was rerun.
All source input stats remained unchanged during the bounded review. Actual
review tool returned EXIT0, chunk ee693f, without a running session. Its proof
SHA256 is b50914f3ebba65db14d9f6d5ee9ee06fb6e673c9f674c32e7bd107a6304c2ffe.
