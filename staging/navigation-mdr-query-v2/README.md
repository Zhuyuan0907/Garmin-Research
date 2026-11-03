# V2 MDR reader preparation

`query_candidate_mdr_v2.py` is prepared but has not been executed. No v2 IMG has been opened by this preparation. The v1 reader, results, receipts and seal remain unchanged.

ROOT must first select a successful, completed `staging/navigation-repair-v2/build-manifest.json`. The reader requires its existing final build identity fields (FID 7053, maps 70530001–70530036, sort 19/7053, UTF-8), `state=compiled_candidate_not_device_verified`, `exit_code=0`, `finished_utc`, `image`, `image_bytes`, and `image_sha256`. It also checks the existing finite validation and producer Sort source path/hash bindings. It does not require a packaged ZIP.

Before sealing the final manifest, ROOT must add:

```json
{
  "producer_controls": "staging/navigation-firmware-sort-v1/packed-fixture-aligned-v2.tsv",
  "producer_controls_sha256": "<actual frozen TSV SHA-256>"
}
```

After ROOT explicitly sends the completed map selection, the intended one-shot command is:

```sh
python3 staging/navigation-mdr-query-v2/query_candidate_mdr_v2.py --producer-controls staging/navigation-firmware-sort-v1/packed-fixture-aligned-v2.tsv
```

The reader checks the actual IMG's SRT `0x6F02` flags and 5-byte `<BHH>` character / 4-byte `<HH>` expansion records. It decodes primary 16 bits, secondary low 10 bits, tertiary high 6 bits; checks section bounds, page pointers, expansion pointers and field ranges; then reconstructs final Java producer KEY/CMP controls. The verified Han ranges use two primary units, secondary `[32,32]` and tertiary `[2,2]`, with verified ExtB codepoints treated as one codepoint. Other characters retain actual stored SRT weights and the selected producer's original UTF-16 semantics.

For actual MDR tables, it checks all section bounds; exact MDR7 joins from MDR20/22; producer partial/full/map order; repeat flags; MDR5 city/region/country/map order, repeat flags and deduplication via actual LBL place pointers; MDR20/22/25 monotonicity; MDR29's actual three-pointer layout; and 臺中市 → 民權路 / 民和路一段 / 民和路二段 record reachability. It writes a bounded result, not complete MDR tables. Empty Unicode device fast-prefix sections remain explicit.

The declared whole-image SHA is inherited from ROOT's terminal build. This reader checks image size and inode/mtime/ctime stability, and does not repeat the full IMG digest, copy the IMG, rerun NET/RGN geometry, refetch official sources, rerun any native probe, or hash the old protected registry. Exact official r4924 layout sources from `../navigation-mdr-query-v1/reference/` are reused.

A passing result means producer order/flags/joins and these finite controls pass. Native all-level compatibility, actual Garmin address caller, device UI search, installation and routing remain unverified. No canonical or service writes occur. Actual terminal receipt and a new file-only seal must be recorded after the eventual reader execution; this preparation receipt is not that runtime receipt.
