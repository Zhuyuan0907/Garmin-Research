# Minimal lane render control: actual capture and finite plan

Chosen OSM control: **新北市／板橋區／四川路二段 → 4巷 → 2號**.
Node **12084620255**, group **3508619**, source point
`24.996635, 121.4562137`, native24 `[1164928,5660270]`.
The complete source members and inherited ledger EOF/SHA pins are in
`selected-control.json`. The small sealed CPU/full-review samples contained
the full provenance; this scope did not open the large source/append ledgers.
No nonempty floor/unit/door/level metadata, embedded floor/unit, source
coordinate conflict, or name alias transformation was used. Geometry evidence
is inherited **complete city only**, not a source district polygon assertion.
This remains OSM address semantics, not official postal verification.

Actual ordinary FILE reads confirmed:

- V2 `925a515b...`: L3 root1153 has L4 first2134701/count267. Its unique
  ordinal5 `4巷` is L4 ID2134706, L5 first169831/count4; `2號` is absent.
- V3 `1f468eb7...`: the same root has L4 first3890582/count267. Unique
  ordinal5 `4巷` is L4 ID3890587, L5 first2668080/count6. Its unique `2號`
  is L5 ID2668082, primary_ref19, flags0, exact sealed payload/raw24.
- Both actual L3 profiles are **23-bit first_child / 112-bit stride**.
  Stock22/111 is not a country-v2 baseline.

The first actual run exited **1**, terminal `1fcd04`, at the assumption that
every old/new L5 record had zero flags/child fields. `prepare_control.py` and
`failure.json` preserve that failed assumption without alteration. This is not
reported as a single successful run. Root explicitly authorized the separate
capture-only pass, **EXIT0**, terminal `a1b085`; it did not execute the failed
guard again or patch/relax the original source.

The old four records are `+ 交叉路口 +` (flags6, L6 first120119/count1), `1號`
(flags8, no lower pointer), `4號`, `7號` (flags0). Their full significant bits,
relative order and lower pointers are identical in the V3 six-record group.
The new flags0 `2號` belongs at insertion ordinal2, retaining the original
four-record relative order. V3 also contains `3號`, excluded from this single
source control. Three root sibling child ranges differ in V3, so copying the
entire V3 L4 group would pull other COW changes into the comparison.

Use only these captured originals for the next writer scope:

- `v2-root-raw-window.bin`: **4272 bytes**, 267 exact original-v2 L4 records,
  34176 significant bits, initial shift0.
- `v2-lane-raw-window.bin`: **64 bytes**, L5 ID169831/count4, initial shift4,
  504 significant bits. Keep surrounding non-record bits distinct.
- `v3-selected-2-house-significant-bits.bin`: **16 bytes**, 126 significant
  bits extracted from the cached actual V3 group, original shift6. Primary
  ref19 already decodes as `2號` in both actual GMP pools.
- `actual-raw-capture-metadata.json` gives exact logical table offsets,
  parent bit offsets/shifts, byte hashes and source capture metadata.
- `actual-v2-v3-records.json` contains both original groups, labels, refs,
  raw flags, child ranges, and actual FAT/DIR/header descriptions.

No pointer or append payload was patched/generated. The raw files are original
read windows and one extracted actual leaf, not a newly built delta.

`minimal-cow-plan.json` describes the future one-leaf writer: clone the V2
267-record L4 group, keep all sibling bytes/pointers, patch only the cloned
`4巷` range, and append a five-record L5 group comprising the old four exact
records plus `2號`. Preserve flags6/8 and the crossing's L6 pointer verbatim;
do not clone its descendants or interpret unknown flags. Projected L4 first
3781595/count267; chosen cloned lane ID3781600; L5 first2667574/count5.
The old L5 end has two padding bits; significant-bit splicing leaves four
padding bits after the five-record append. Existing L3 root1153 needs only
first/count patch; suffix starts, MDR directory header and six table entries
must follow the new lower-table lengths. No GMP text or JAI row is required.

Projected counts: `[22,343,47870,3781861,2667578,1984066]`.
MDR grows **4351 bytes** (L4 4272, L5 79), 30336→30337 4K blocks, still127
FAT parts. Actual V2 metadata has zero free rows, but this plan needs zero new
FAT rows. Projected IMG **128360448 bytes** fits declared134217728 capacity,
so unchanged V2 4K header geometry is feasible as arithmetic. No new IMG or
output header preservation/device acceptance has been verified.

Capture-only actual IMG reads: **186799 bytes**. The first failed run did not
persist its exact read ledger; this receipt gap is explicit. The unchanged
first runner's strict metadata/group/label limits prove a conservative
**740000-byte** bound. Capture was limited to308576 bytes, making the combined
read upper bound **926799 bytes**, below1MiB. `actual-IMG-read-receipts.json`
contains the exact capture-only reads and the bound derivation. No full IMG
hash repeat; producer full readback hashes are inherited with immutable
content inode/size/mtime and fresh before/after ctime/nlink checks. All handles
closed. MAIN0, CPU0, PBF0, device0, source/report/canonical writes0.

Renderer, real UI, physical acceptance, official house validity, App and whole
Taiwan update completion remain unverified. The source172188 昌平路 existing
address discrepancy is a separate control and was not used here.
