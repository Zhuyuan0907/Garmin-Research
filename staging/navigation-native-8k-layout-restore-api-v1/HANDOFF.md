# Exact stock4K restore API handoff

NEW source `native_8k_stock_restore.py` and public contract `API.md` are ready. Final focused execution ae18a1 EXIT0;26 guards passed. Proof SHA `3cf2fd48dad5931385af183aed0a47972b4fcb46702e59dda5a22f17f8ec72d5`.

First fragmented six-component fixture reconstructs every original61,440B from81,920B8K candidate, original/restored SHA `c0f915e056b80c0d942fcfcd995c92a78e5aa9b904c94cb76993a0996923fc6f`. Second continuation fixture reconstructs every original2,023,424B from2,039,808B, original/restored SHA `093f7b38d98589a52d1caf3ec8191fe50ac3089cfeaffc5ff4501f9388e199ad`; a component has three4K FATparts and two8K FATparts. Header/FAT/L3/padding/unusedblocks are exact, both currentL5 tail2bits are consumed in new significant append, original lowerbyteprefix remains exact, and no8Ktails survive.

Production only accepts the closed879,499B stock/v2 recipe SHA `6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7`. Future actual output descriptor must match the sealed writer schema with source_v2, six component array, exact part row_hex and levels1..6 table array. New binding keeps the recipe reference plus explicit actual8Klayout; it does not duplicate the compact recipe. Candidate SHA and metadata SHA must come from actual complete output readback. No actual future descriptor or IMG was read in this API scope.

Production runtime verifies bounded actual header/FAT/MDR directory, then reconstructs original4Kblocks with source8K logical reads; full EOF verifies exact stockSHA and immutable file stat/linkcount. No lower width inverse transform; unsupported width changes reject. NativeL3 original111 is restored from stored recipe, while futurecurrentL3 stays112/first23. Strict knownfuture lowercounts are4896236/3077845/2062771.

No original/candidate/full restoredIMG was opened or written, no second fullbackup, no device/USB/ZIP/canonical/installer change or prior suite replay. Unknown headerchecksum/device8Kacceptance remain unresolved. The next separate scope may bind an actual future candidate and compute stock reconstructedSHA without writing a restoredIMG; this API scope is complete and stopped.
