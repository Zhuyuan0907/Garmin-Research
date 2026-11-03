"""Small snapshot consistency audit; no report mutation or external I/O."""
from pathlib import Path
from collections import Counter
import hashlib,json,os,re
HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def save(name,data):
    (HERE/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def main():
    rows=json.loads((HERE/'parsed-paragraphs.private.json').read_text());byid={r['paragraph_id']:r for r in rows}
    reads=json.loads((HERE/'input-read-receipts.json').read_text())
    prefix=json.loads((HERE/'top-field-read-receipts.json').read_text())
    web=json.loads((HERE/'private-inputs/web.json').read_text())
    live=json.loads((HERE/'private-inputs/download-livecheck.json').read_text())
    reportsha=sha((HERE/'private-inputs/report.html').read_bytes())
    assert web['local_report_sha256']==web['served_report_sha256']==reportsha
    assert web['report_bytes']==285643 and reads['total_original_artifact_bytes']==419847
    assert prefix['total_original_artifact_bytes']==428039<=786432
    assert not web['full_goal_complete'] and not web['goal_complete']
    order=web['offline_24h_work_order']
    assert order['user_away'] is True and order['unsolicited_presence_questions'] is False
    assert order['current_device_address_candidate']=='country_AP_v2_original_4K'
    assert order['current_daily_layers']==['Address Point v2','Search v2']
    assert web['current_physical_test_requested'] is True and web['user_away_for_class'] is False
    status={(r['method'],r['route']):r['status'] for r in live['live_checks']}
    assert status[('GET','/Garmin-2565RT-lane-address-test-v3.zip')]==410
    assert status[('HEAD','/Garmin-2565RT-lane-address-test-v3.zip')]==410
    assert status[('HEAD','/Garmin-2565RT-existing-street-address-test-v2.zip')]==200
    assert live['retired_archive_preserved'] is True
    findings=[]
    for ident,bad,replacement,reason in [
        (80,'新街道／子號離線前置原型尚未合併到已安裝v3',
         '新街道／子號離線前置原型尚未合併到車機目前使用的v2；v3已因道路顯示回歸停用',
         'Located in the current 接著處理 list; unqualified 已安裝v3 conflicts with current v2 and rollback evidence in the same section.'),
        (78,'這些原型不放入可安裝v3包。',
         '這些原型仍只供離線研究；舊v3包已撤下下載並停用。',
         'Current new-street limitation calls v3 installable even though its known regressing download is retired and installation stopped.')]:
        r=byid[ident];assert bad in r['redacted_text']
        findings.append(dict(id='HTML-'+str(ident),kind='confirmed_current_guidance_conflict',
            paragraph_id=ident,dom_path=r['selector'],heading_context=r['heading_context'],
            enclosing_ids=r['enclosing_ids'],html_line=r['html_line'],
            paragraph_text_sha256=r['text_sha256'],paragraph=r['redacted_text'],
            replace_exact=bad,replace_with=replacement,reason=reason,
            minimal_replacement_paragraph=r['redacted_text'].replace(bad,replacement),
            evidence_paragraphs=[1,18,66,68,79],delete_historical_record=False))
    structured=[dict(id='WEB-current-presence',kind='independently_read_current_structured_conflict',
        source='evidence/report-web-latest.json',json_pointers={
            '/current_physical_test_requested':dict(actual=True,suggested=False),
            '/user_away_for_class':dict(actual=False,suggested=True)},
        evidence='/offline_24h_work_order declares user_away=true, no unsolicited presence questions, user will notify return; HTML paragraphs 14 and 18 agree',
        change_historical_physical_checkpoints=False)]
    inherited=[dict(id='ROOT-task-state-presence',source='evidence/task-state.json',
        json_pointer='/user_away',root_reported_actual=False,suggested=True,
        provenance='Parent root current-state scan; requested key not independently obtained from the authorized 4096B prefix',
        independently_verified_here=False),dict(id='ROOT-findings-goal',source='reports/findings.json',
        json_pointer='/research_goal_status',root_reported_actual='paused',suggested='active_offline',
        provenance='Parent root current-state scan, compared by root with canonical deep.research_goal_status=active_offline; key beyond decoded prefix',
        independently_verified_here=False,actual_goal_API_status_in_existing_web_capture='active')]
    historical_ids={10,12,13,25,26,27,28,29,30,34,40,42,44,46,52,55,57,58,64,65,244}
    inventory=[]
    for r in rows:
        if not r['selected']:continue
        if r['paragraph_id'] in (78,80):classification='confirmed_current_guidance_conflict'
        elif r['paragraph_id'] in historical_ids:classification='historical_stage_or_completed_observation_preserved'
        elif any('前輪' in v or '較早' in v for v in r['heading_context'].values()):classification='explicit_historical_heading_preserved'
        elif r['paragraph_id'] in (293,579,606):classification='v3_token_other_than_navigation_candidate'
        else:classification='scoped_statement_no_confirmed_conflict_with_supplied_current_controls'
        inventory.append({k:r[k] for k in ['paragraph_id','selector','html_line','tag','enclosing_ids','heading_context','text_sha256','keyword_matches']}
                         |dict(classification=classification))
    assert len(rows)==746 and len(inventory)==142
    # These are search results only; false is not a renderer/UI or global correctness claim.
    v3rows=[r for r in rows if re.search('v3',r['redacted_text'],re.I)]
    search=dict(v3_latest_prepared_count=sum('最新準備' in r['redacted_text'] for r in v3rows),
        v3_not_yet_physically_installed_count=sum('尚未實機安裝' in r['redacted_text'] for r in v3rows),
        v3_acceptance_only_waiting_count=sum('實機接受度尚待測試' in r['redacted_text'] for r in v3rows),
        only_check_layers_occurrences=[r['paragraph_id'] for r in rows if '只勾' in r['redacted_text']],
        only_check_layers_current_unversioned_instruction_count=0)
    assert search['only_check_layers_occurrences']==[26]
    assert all(search[k]==0 for k in ['v3_latest_prepared_count','v3_not_yet_physically_installed_count','v3_acceptance_only_waiting_count'])
    save('paragraph-inventory.json',dict(schema='garmin-report-current-guidance-inventory/v1',
        body_blocks=746,keyword_selected_blocks=142,selection='目前|最新|下一步|待實機|v3|尚未實機|實機接受|兩圖層|兩層|只勾|待測試',
        implicit_body_under_main_supported=True,dom_path_format='tag[sibling-of-same-tag-index] and #id; diagnostic DOM paths, not asserted executable CSS',
        coverage='All selected blocks reviewed against the supplied finite current-state controls; relevant adjacent navigation paragraphs also inspected',
        classification_counts=dict(Counter(r['classification'] for r in inventory)),rows=inventory))
    audit=dict(schema='garmin-report-current-guidance-audit/v1',report_snapshot_sha256=reportsha,
        snapshot_updated_utc=web['updated_utc'],html_confirmed_current_conflicts=2,
        independently_read_structured_conflict_records=1,independently_read_stale_structured_fields=2,
        inherited_parent_observation_records=2,HTML_findings=findings,structured_findings=structured,
        inherited_parent_observations=inherited,requested_wording_search=search,
        historical_records_preserved=dict(physical_v3_install_and_road_failure=True,rollback_to_stock_then_v2=True,
            only_check_two_layers_paragraph_26_is_reported_v3_failure_not_a_current_instruction=True,
            paragraph_244_is_old_installer_stage_not_active_presence_request=True,
            all_old_phase_logs_unchanged=True),
        current_fact_checks=dict(v2_plus_Search_v2_visible=True,Minquan_6_150_184_scope_visible=True,
            no_all_130637_verified_claim_found=True,v3_road_failure_and_retirement_visible=True,
            header_virtual_controls_not_device_renderer_fix=True,full_country_incomplete_visible=True,
            native_App_40_estimate_not_completed=True,user_away_no_question_visible=True),
        publisher_action='Root may apply the two exact HTML substitutions and four current structured-field updates; preserve historical checkpoints',
        report_and_canonical_edited=False,full_UI_renderer_routes_validated=False)
    save('audit.json',audit)
    save('parse-implicit-body-erratum.json',dict(initial_terminal='ebfc1f EXIT0',initial_body_blocks=0,
        initial_source='parse_report.initial.py',cause='Report legally omits explicit body start; initial parser selected explicit body only',
        corrected_terminal='0db7dd EXIT0',corrected_body_blocks=746,corrected_selected_blocks=142,
        original_source_artifact_rereads=0,original_HTML_content_unchanged=True))
    proof=dict(schema='garmin-report-current-guidance-audit-proof/v1',
        all_assigned_checks_passed=True,review_found_current_conflicts=True,
        report_snapshot_sha256=reportsha,report_bytes=285643,web_snapshot_sha256=reads['reads'][1]['sha256'],
        producer_web_claims_match_actual_snapshot_hash_and_size=True,
        actual_original_artifact_read_bytes=428039,cap=786432,HTMLcap=524288,
        original_read_breakdown=dict(partial_first_capture=418054,continuation_livecheck=1793,
            partial_task_prefix=4096,continuation_findings_prefix=4096),
        report_and_web_source_before_after_checks='initial source assertions passed; exact initial stat values were lost before receipt creation and are not reconstructed as captured values',
        source_mutability_limit='Audit is of the captured 15:59 snapshot; no claim later report publications remain identical',
        current_HTML_conflicts=2,independently_read_structured_stale_fields=2,
        root_reported_other_structured_fields=2,root_reported_fields_freshly_verified=False,
        closed_download_receipt_hash_size_mode_verified=True,
        download_statuses_in_inherited_closed_receipt=dict(v3_GET=410,v3_HEAD=410,v2_HEAD=200,old_archive_preserved=True),
        no_new_HTTP_observation=True,all_original_source_handles_closed=True,
        failed_attempts_preserved=['fc9279 host missing seal stat field','ff1553 host final UTF8 decode on split prefix'],
        parser_zero_rows_preliminary_result_preserved=True,
        prohibited_IO=dict(IMG_read_bytes=0,MAIN_read_bytes=0,PBF_read_bytes=0,guest_CPU_executions=0,
            audio_operations=0,device_IO=0,service_mutations=0,HTTP_requests=0,canonical_report_writes=0),
        limits=['Finite semantic consistency review against provided facts, not complete historical evidence/ABI revalidation',
            'No browser render, hardware acceptance, route execution or new renderer fix',
            'Large task-state/findings read only first4096B each; target values supplied by root remain inherited'],
        full_country_update_complete=False,native_App_or_direct_music_complete=False)
    save('proof.json',proof)
    (HERE/'HANDOFF.txt').write_text(
        'READ-ONLY current-guidance audit of report snapshot 2026/10/07 15:59:28.\n'
        'Two exact HTML findings in audit.json: current 接著處理 still says 已安裝v3; current limitation calls the retired v3 package 可安裝.\n'
        'Web current_physical_test_requested=true/user_away_for_class=false are independently read stale top flags.\n'
        'Parent root additionally reported task-state top user_away=false and findings top research_goal_status=paused. These two are inherited only: bounded prefixes do not contain their completed top values.\n'
        'Preserve v3 historical install/failure/rollback and old phase logs. Current installed v2+Searchv2 and three Minquan controls are correctly visible; complete130637 coverage is not claimed.\n'
        '428039B original artifact I/O, zero IMG/MAIN/PBF/guest/audio/device/HTTP/service/canonical/report changes.\n'
        'Initial schema and UTF8 prefix failures are preserved; continuations reuse captured bytes. HTML implicit-body parser correction also recorded.\n'
        'Private input copies are0600; do not publish raw web captures or unrelated local paths. No required444 mode claim.\n'
        'Root alone publishes changes. Finite scope stops after seal; no device/renderer/full-goal success.\n')
    os.chmod(HERE/'parsed-paragraphs.private.json',0o600)
    print(json.dumps(dict(HTML_conflicts=2,structured_actual_fields=2,inherited_root_fields=2,
        artifact_bytes=428039,proof_sha256=sha((HERE/'proof.json').read_bytes()))))
if __name__=='__main__':main()
