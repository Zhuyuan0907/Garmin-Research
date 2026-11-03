#!/usr/bin/env python3
"""Static writer/layout review against the frozen new MDR query header."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main():
    output = BASE / 'candidate-MDR-prefix-layout-review-v1.json'
    assert not output.exists()
    proof = json.loads((BASE / 'candidate-mdr-query-proof-v1.json').read_text())
    assert proof['all_passed']
    reference = BASE / 'reference'
    writer = (reference / 'MDRFile.java').read_text()
    country = (reference / 'Mdr29.java').read_text()
    needed = ['if (forDevice && Arrays.asList(13, 14, 15, 21, 23, 26, 27, 28).contains(sectionNumber))',
        'if (forDevice && !isMulti)', '//writeSection(writer, 8, mdr8);']
    assert all(fragment in writer for fragment in needed)
    assert 'boolean has17 = (magic & 0x30) != 0;' in country
    section = {int(k):v for k,v in proof['sections'].items()}
    checks = dict(candidate_Unicode65001=True,
        street_prefix_MDR8_empty=section[8]['bytes'] == 0,
        name_prefix_MDR12_empty=section[12]['bytes'] == 0,
        combined_name_prefix_MDR17_empty=section[17]['bytes'] == 0,
        MDR29_no_string_or17_pointer=(section[29]['magic'] & 0x31) == 0,
        MDR29_flags_match_three24_22_25_pointers=section[29]['magic'] == 6,
        official_multibyte_condition_excludes_MDR17_additions=True,
        MDR21_28_region_indexes_intentionally_omitted=True)
    names = ['MDRFile.java', 'Mdr29.java', 'Mdr6.java', 'Mdr8.java', 'Mdr12.java',
             'Mdr17.java', 'Mdr18.java', 'Mdr19.java', 'Mdr2x.java', 'Mdr5.java']
    result = dict(all_passed=all(checks.values()), checked_utc=datetime.now(timezone.utc).isoformat(),
        checks=checks, scope='Static exact-r4924 writer interpretation plus frozen candidate MDR headers; no new candidate reads or key execution.',
        exact_sources={str((reference / name).relative_to(BASE.parents[1])):
            hashlib.sha256((reference / name).read_bytes()).hexdigest() for name in names},
        frozen_MDR_query_proof_sha256=hashlib.sha256((BASE / 'candidate-mdr-query-proof-v1.json').read_bytes()).hexdigest(),
        actual_nonempty_related_sections=dict(MDR6='map index + local ZIP index; sorted in writer, no serialized name-prefix bytes',
            MDR18='POI natural-type field plus first MDR19 record pointer',
            MDR19='flagged MDR11 POI record pointers, grouped by POI type',
            MDR20='direct map/LBL/name-offset/repeat records grouped by city',
            MDR22='direct map/LBL/name-offset/repeat records grouped by country',
            MDR29='MDR24 start, MDR22 start, MDR25 start; exact widths1/3/2 bytes here'),
        host_SortKey_first_bytes_serialized_in_requested_city_street_fast_prefix_tables=False,
        hypothetical_nonempty_PrefixIndex_generation_implementation_reviewed=False,
        native_key_byte_difference_by_itself_proves_current_prefix_corruption=False,
        native_CJK_order_equivalence_or_address_UI_verified=False,
        candidate_status='held_pending_native_order_and_physical_search_clarification',
        limitations=['This scoped finding concerns actual current city/street MDR tables, not all firmware search acceleration.',
            'Empty prefix tables remove this particular serialized-prefix hypothesis; they do not prove native comparison, duplicate grouping or UI compatibility.',
            'Actual mixed-name native ordering and caller behavior require a separate bounded check.',
            'No image/backup hash, old scope rerun, guest, USB, installation or canonical mutation.'])
    with output.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=result['all_passed'], checks=checks, output=str(output))), flush=True)


if __name__ == '__main__':
    main()
