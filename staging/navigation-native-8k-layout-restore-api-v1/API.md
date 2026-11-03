# Exact stock4K reconstruction from explicit8K COW

This read-only API reconstructs the exact original stock physical blocks from the compact closed v2 recipe and a future actual explicit8K candidate. It writes no IMG and includes no installer or CLI.

The production recipe is exactly `staging/navigation-country-layout-restore-v2/restore-layout.json.gz`: 879,499 bytes, SHA-256 `6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7`. Its original stock image is 96,739,328 bytes, SHA-256 `864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2`. A different recipe or arbitrary IMG profile is rejected.

The candidate descriptor must be a sealed **actual output readback** with schema `garmin-native-ap-explicit8k-cow-layout/v1` and profile `AP8K-9+4-32768blocks-524288sectors`. It has exactly these fields:

```text
schema, profile, block_bytes, candidate_bytes, candidate_sha256,
metadata_bytes, metadata_prefix_sha256, source_v2, components, tables
```

`source_v2` is `{bytes,sha256}` bound to the sealed 128,356,352-byte v2 candidate SHA `925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb`. `components` is the six-component array in stock order; every item is `{name,size,blocks,parts}`. Each part is `{part,size,blocks,row_hex}` with the actual 512-byte FAT row represented by 1,024 lowercase hexadecimal characters. `tables` is the level1..6 array with `{level,start,bytes,stride,count,widths,flags}`. This matches the sealed `navigation-native-current-profile-cow-writer-v1/output-layout-contract.json`; source layouts and capacity plans cannot substitute for actual output descriptors.

The descriptor SHA is checked before loading. Preparing a binding validates the exact source-v2 identity, table byte/count/profile bounds, six component order, original other-five component lengths, unique allocation bounds, FAT row declarations and continuation metadata. It does not establish that an output exists or that all payload bytes are preserved. Those checks occur when the reconstruction generator is consumed to EOF.

```python
from native_8k_stock_restore import (
    load_stock_recipe, load_output_descriptor, prepare_restore_binding,
    reconstructed_stock_hash,
)

stock = load_stock_recipe(closed_recipe_path)
actual = load_output_descriptor(actual_output_layout_path, descriptor_sha_from_seal)
binding = prepare_restore_binding(stock, actual)
reads = []
with open(actual_candidate_path, 'rb') as candidate:
    original_sha = reconstructed_stock_hash(candidate, stock, binding, reads)
```

`binding` is small JSON data that a caller may persist and seal; it contains the actual layout and a reference to the closed stock recipe, without duplicating the stored header/FAT/L3/padding. `load_restore_binding(path, expected_sha256)` verifies a sealed binding. The caller must pin both the actual descriptor seal and the inherited complete candidate readback SHA. This API does not repeat the whole candidate hash.

`restored_stock_blocks(candidate, stock, binding, read_receipts=None)` yields exactly 4,096-byte original physical blocks. The candidate must be an actual file opened `rb`. It checks actual8K header/FAT/root metadata, six components, row hex, original supported header transformation, the actual MDR header and all six directory entries before streaming. Logical reads use 8,192-byte candidate blocks, and output allocation uses the stored original 4,096-byte blocks.

The recipe supplies exact original header/FAT, original 111-bit L3 table, original MDR header/directory, component padding and any originally unused blocks. The candidate supplies unchanged components, the unchanged MDR prefix/L1/L2 span, and original-length byte prefixes read separately at each future L6/L5/L4 start. Lower strides must remain 68/126/128; final counts are explicitly pinned to L6 2,062,771 / L5 3,077,845 / L4 4,896,236. Original lower table lengths are byte aligned. Current-v2 L5's two unused tail bits are outside that original prefix and may be consumed by COW append. No inverse lower-width transform is implemented.

Full generator consumption checks immutable file dev/inode/size/mtime/ctime/link count and the exact complete original SHA at EOF. Early generator termination leaves the complete reconstruction unverified. The API can yield blocks before the final digest check; it does not provide an atomic transaction. `reconstructed_stock_hash` consumes the stream completely and writes nothing.

Small synthetic fixtures have a separate named schema and separate functions. Production binding/generator functions reject them. Tests do not open the original or any complete candidate IMG. They cover exact physical equality, original metadata/L3/padding/unused blocks, fragmented allocations, multibody FAT continuations, real consumption of v2 L5's two unused bits, and exclusion of all candidate8K tail padding from the output. Unsupported layouts, descriptor/recipe mutations, stride changes, aliasing, invalid FAT rows and corrupt payloads are rejected.

Header checksum rules and physical8K device acceptance remain unknown. These controls do not claim native search/UI/route acceptance, complete Taiwan address coverage, or that a future actual candidate has already been reviewed. Later bit-width widening requires a different explicitly verified inverse transform; it must not use this truncation API.
