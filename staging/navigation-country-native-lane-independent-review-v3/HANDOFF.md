The actual v3 independent host review passed. The image handle is closed.

Candidate: `staging/navigation-country-native-lane-candidate-v3/gmapprom1.img`,
153,346,048 bytes, inherited sealed SHA-256
`1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360`.
The full IMG digest was bound to root's completed integration receipt and was
not recomputed here. Exact frozen dev/inode/size/mtime/ctime matched before and
after this actual read phase.

`review_actual_v3.py` has its own strict 8,192-byte FAT mapper, descriptor decoder,
and bit-window reader. It imports no writer, repacker, shared parser or CPU
harness. Six actual component allocations, directory and LBL offsets came from
the actual candidate headers/FAT. The actual MDR physical sequence is 6,5,4,3,2,1,
then its six-entry directory. The L3 descriptor has first-child width23/stride112;
lower strides128/126/68 retain their distinct nonbyte positions. Labels came
through the actual GMP/LBL descriptor and existing CP950 pool.

Actual checks passed for all58,233 new leaves (payload, reference, raw24, label,
and true terminal-parent ordinal), all20,613 complete paths/all24,442 links from
7,650 true L3 roots, and all51,332 copied prior v2 new leaves reached inside the
actual selected root groups. There are4,420 selected roots with first-child
greater than4,194,303. All111,147 source-node memberships and full provenance were
bound to the sealed append producer; geometry/source extraction were not rerun.
The79,305 prior leaves outside this COW closure use root's completed full current
significant-prefix gate. That distinction is explicit in `proof.json`.

All old unknown flags use root's complete prefix and actual shifted-append hash
gates. A separate finite actual host sample found one true unchanged raw13 clone
within60 root groups/11,188 rows (limits100 groups/30,000 rows): L4 newID4499671,
current-prefixID3033432, sourcegroup[4,3033379,59], label88巷, first1417151/count1.
Its full significant payload matches the actual current-prefix record. The
unknown branch was not followed or converted.

`actual-native-CPU-witnesses.json` is100,873 bytes, mode444, SHA-256
`7431c5821d1f322d6c7a74c473b3df450fd62dcc785fc3a06e1d7e841d28b59a`.
It contains full sealed leaf rows for L5 global shifts0/2/4/6, L6 shifts0/4,
a multilevel path, corresponding full parent-path rows, and the raw13 clone
witness. It was collected during the one required complete58,233-row source
ledger pass after compressed/plain digests, row count, gzip EOF and immutable
stats passed. Before that pass, schema preparation read only the first row of
the leaf/path ledgers; it did not perform another full scan. The witness was
chmod444 before its SHA was sent; final sealing skips chmod on already444 files.

Execution:27 NEW small synthetic controls EXIT0/chunk835b3d; actual review
session49682/initial3e9b70/terminal0803a8 EXIT0. Actual image reads total2,927,790
bytes/148,178 operations, saved individually with physical offsets and hashes.
The process reported ru_maxrss424,240KiB below the unchanged512,000KiB guard;
an attempted live `/proc` sample found the process already exited, so no live
process peak is claimed. Elapsed time is an execution receipt, not a performance
benchmark. No candidate rerun or IMG reopen occurred after the successful pass.

Fresh output-only EOF/digest/uniqueness audit passed session67494/terminal8ee4d1.
Its initial attempt EXIT1/chunk5c899b incorrectly required labels to contain only
digits; real existing CP950 labels include號 (for example13號). The original
audit source and failure receipt are preserved. The corrected output-only audit
validates positive integer＋號 and passed; this did not alter the actual review
source, repeat source ledgers, or reopen the candidate.

This is an independent host field/path/label review. Original CPU, complete
native comparator/query/UI, 8K device acceptance, routing, and full Taiwan
coverage remain separate. No PBF, prepared/ready source, geometry, append bins,
old closed suite, device, USB, ZIP, canonical report, or previously sealed source
was changed. `native_write_ready=false`; the full address goal is still active.
