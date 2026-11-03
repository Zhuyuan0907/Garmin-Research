# Prepared small output sealer; do not run before root terminal/receipt

`seal_completed_output.py` is a separate helper outside the live V4 scanner
namespace. It has not been executed. It reads only final small JSON/phase/source
outputs, validates root's saved final actual tool receipt and original
preparation identities, then seals completed data evidence. It never opens
an IMG, source ledger, old algorithm, firmware, guest or physical device.

After root supplies the terminal chunk and saves one final complete tool-result
JSON in the V4 output namespace:

```sh
python3 /root/garmin/staging/navigation-v3-compaction-current-mm-v4-output-sealer-v1/seal_completed_output.py \
  --receipt /root/garmin/staging/navigation-v3-reachable-suffix-compaction-current-mm-v4/actual-root-tool-receipt.json \
  --receipt-sha256 REPLACE_WITH_ACTUAL_SHA256 \
  --terminal-chunk REPLACE_WITH_FINAL_CHUNK
```

The final receipt must be a raw tool result with `exit_code:0` and the exact
root `chunk_id`, not a still-running session. No live process is polled, resumed
or restarted. Failure or incomplete output is refused rather than converted
into a passing seal. A separate scope is required if actual execution fails.

The helper validates complete small-file EOF/SHA/stat, actual single149220356B
MDR stream hash, read budget≤160000000B, phase counters and current-mm393216KiB
guard, source handle closure, both plan summaries, and external/force_all
limits. It does not recompute reachability/rank/alias or require4K arithmetic
to succeed. Preserving an actual failed-to-fit result is valid data evidence.

Original preparation files and the prepared manifest retain full byte/stat
identity. Only new output files are made0444. `actual-output-audit.json` and
`sealed-files.json` are added after successful closure checks. All small files
must remain under1MiB. Future actual sealer exit/receipt must be saved separately;
this preparation certifies no live output or completed data result.

The actual V4 terminal was subsequently EXIT1/f176d1. The success-only helper
above remains unexecuted. `seal_failed_output.py --terminal-chunk f176d1`
closes only that saved failure, exact prepared identities and small durable
phase/root receipts. No completed feasibility summary is asserted.
