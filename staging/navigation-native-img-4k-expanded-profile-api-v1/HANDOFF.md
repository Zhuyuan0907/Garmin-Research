This is a new, noninstallable capacity/header-planning API. It neither imports
nor changes the original4 KiB writer or any installer. It provides no full IMG,
payload-copy, filesystem-output, USB, renderer or native CPU execution API.

expanded_4k_profile.py exposes:

- bind_original_4k_header(raw, source_kind=...): checks exact512-byte original
  XOR0/DSKIMG/GARMIN/end-marker,9+3 exponents, directory-sector8, stock geometry,
 32768 blocks/262144 sectors and opaque byte0x0F=219. A real sealed-stock-header
  claim additionally requires exact stock header SHAb8afc5f2...eb191. Synthetic
  fixtures are explicitly labelled; they cannot claim that stock hash binding.
- plan_expanded_4k(binding, six ordered size pairs, declared_blocks=...): requires
  an explicit expanded count32769..65534 and enough capacity for every contiguous
  allocation plus rounded metadata. Six exact names/order, positive uint32 sizes,
  root single-row bound, no overlaps/gaps by construction, FFFF sentinel fencing,
  exact sector mirror and source/plan integrity are checked. Images that still
  fit the old declaration are refused by this expanded API; use the stock profile.
- header_bytes_for_offline_control(plan): returns only512 in-memory bytes. It
  changes u16 block count at0x63 and u32 LBA sector mirror at0x1CA. Exponents,
  opaque byte0x0F, CHS and every other source byte remain unchanged. This narrow
  experimental patch is not proved valid/accepted at the expanded size.
- fat_row_for_offline_control(...): returns one512-byte component row in memory,
  preserves name/status/flags/unknown fields, checks part/template identity, and
  uses finite non-sentinel allocation entries. It does not validate real
  continuation-template uniformity or copy any logical component payload.

The v3 six sizes were inherited from the closed narrow review and used only
for new arithmetic/metadata controls:153337856 image bytes,37436 blocks,
161 FAT rows,90112 metadata bytes and299488 minimum partition sectors.
Three sampled MDR FAT parts include the actual32768-block boundary and final
partial/sentinel padding. Python independently decodes uint16 rows and checks
block-to-sector arithmetic; no original CPU ran. The synthetic header and
opaque FAT templates contain patterned unknown bytes to check preservation.

Unknown fields/policies are explicitly carried in every plan report:

- Original AP checksum byte0x0F algorithm, coverage and high-level enforcement.
- CHS meaning/coherence/enforcement at0x18/0x1A/0x1C,0x5D/0x5F and partition
  CHS mirror0x1BF..0x1C5 for an expanded4 KiB AP. Leaving them unchanged is an
  experimental isolation choice, not a declaration that they are unnecessary.
- Opaque header fields including0x24..0x38 and0x83 onward.
- AP admission/map-layer registry, ownership, priority and rendering.
- Complete AP FAT/continuation reader behavior, including high part ordinals
  outside the sampled v3 range. Shared DSKIMG/VPM code is not the AP renderer.

Every plan has installable=false, device_verified=false and checksum_verified=false.
require_installable() always rejects. No caller flag grants installation.
No checksum is guessed/zeroed, and the old128 MiB capacity guard is not relaxed.
Future exact expanded-profile/container/native-reader validation must be a
separate scope, including all real FAT metadata, component logical SHA, high
block translation, header admission policy and exact rollback. Arithmetic or
metadata success here cannot authorize a device candidate.

Physical context from the parent: sealed v3 was rolled back to exact stock and
safely unmounted. User confirmed stock AP+Searchv2 with CN off displays roads.
This establishes the v3 regression, without isolating8 KiB geometry from the
added MDR/COW structure. The parent's sealed4 KiB v2 A/B is the next physical
step. This API is independent preparation, not an observed bug fix.

Fresh small controls passed48 cases, actual EXIT0/chunk6a4051, no running session.
No actual candidate/backup IMG was opened, full IMG/component allocated/written,
closed suite replayed, native CPU executed, or installer/device/report/service
touched. The old writer and closed narrow-review hashes were checked unchanged
before/after. Source, proof and receipts are sealed independently in this folder.
