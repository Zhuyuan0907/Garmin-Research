"""Estimated research milestones for the public report, including deferred work.

Weights describe the research plan, not measured engineering effort or remaining
time. They can be revised when a newly discovered prerequisite changes the plan.
Only observed state changes advance milestones; a running process or test count
alone never implies a native installation or a working phone session.
"""
import datetime as dt
import html

TAIPEI=dt.timezone(dt.timedelta(hours=8))

def timestamp(value):
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(TAIPEI)

def build_progress(research, *, backup_verified, theme_verified, map_verified):
    s=research or {};aa=s.get('native_android_auto',{});app=s.get('native_app_music',{})
    f=app.get('static_findings',{});firmware=s.get('firmware',{})
    aoa=aa.get('AOA_negotiation_prototype',{});controller=aa.get('USB_controller_peripheral_path',{})
    decoder=f.get('sbc_decoder_prototype',{});loaded=f.get('native_loaded_playback',{})
    phases=[]
    def phase(name,weight,steps,next_step,*,deferred=False):
        score=sum(points for points,complete,description in steps if complete)
        assert sum(points for points,complete,description in steps)==100
        phases.append({'name':name,'weight':weight,'estimate_percent':score,
          'completed':[text for points,complete,text in steps if complete],
          'remaining':[text for points,complete,text in steps if not complete],
          'next':next_step,'deferred':deferred})
    phase('備份、圖資與韌體基礎盤點',15,[
      (25,backup_verified,'完整 USB 邏輯磁碟備份及 1,402 個檔案讀出核對'),
      (25,map_verified,'新版台灣 OSM 地圖安裝並讀回核對，保留原廠圖資'),
      (25,theme_verified,'Pi Contrast 主題已由使用者確認正常顯示'),
      (25,firmware.get('round_trip_identical') and firmware.get('main_checksum_verified'),
          '精確台灣 8.00 韌體解析、重建與主程式校驗')],
      '新版圖資的中文搜尋、路由及戶外 GPS 仍另待實測。')
    phase('原生音訊與元件原型',20,[
      (25,decoder.get('pcm_reference_byte_identical'),
          'ARMv6 SBC 解碼原型：32 組格式／162 音框符合上游參考'),
      (25,loaded.get('test_result')=='passed',
          '原廠載入器與音訊工作離線整合，保留 40 個原廠介面'),
      (25,app.get('native_app_running'),'自製 App 已在原機執行'),
      (25,app.get('direct_phone_music_verified'),'手機直接連 Garmin 播放音樂已實測')],
      '優先追真正 A2DP 端點註冊與音樂能力協商，再確認原機載入、菜單入口、導航共存與安全停止。')
    phase('USB 主機與手機連線',20,[
      (5,bool(aa.get('USB_ID_classification',{}).get('offline_cases_passed')),
         '原廠 USB 類型判讀已離線驗證'),
      (5,controller.get('all_cases_passed'),'原廠裝置模式控制端點的 22 個離線案例通過'),
      (5,bool(aoa.get('offline_cases_passed')),'AOA 握手 ARMv6 原型的 50 個離線案例通過'),
      (5,aa.get('AOA_configuration_prototype',{}).get('configuration_interface_bulk_endpoint_selection_implemented'),
         '配件介面／bulk 端點解析與設定配置原型的 62 個離線案例通過'),
      (30,aa.get('USB_host_board_wiring_or_driver_verified'),'Garmin 實機 USB 主機及資料傳輸已驗證'),
      (50,aa.get('phone_session_verified'),'Garmin 與手機的原生投影連線已實測')],
      '接上真正的主機／VBUS／傳輸入口，再整合資料分段、TLS 與手機投影通道。')
    phase('畫面、影片與觸控投影',20,[
      (5,bool(aa.get('display_path')),'找到原廠影像描述資料與條件式畫面提交路徑'),
      (5,aa.get('original_touch_event_consumer_executed_offline'),'原廠按下／拖曳事件處理已離線執行'),
      (30,aa.get('H264_decoder_or_real_time_performance_verified'),'H.264 解碼與實時效能已驗證'),
      (30,aa.get('native_screen_presentation_verified'),'原機實際呈現投影畫面'),
      (30,aa.get('native_projection_touch_verified'),'原機觸控能操作手機投影')],
      '建立 H.264 解碼、螢幕呈現、縮放與觸控回傳；目前未顯示手機畫面。')
    phase('原生 App 入口與功能整合',10,[
      (50,aa.get('actual_input_driver_or_native_App_registered'),'原生 App 入口與操作介面已註冊'),
      (50,aa.get('native_receiver_running'),'Android Auto 接收端在 GarminOS 執行')],
      '完成可接受的安裝／載入方式、App 選單及協定／影音整合。')
    phase('原生整合後的實機驗證',5,[
      (50,aa.get('phone_session_verified') and aa.get('native_receiver_running'),
          '目前手機與原機端到端投影實測'),
      (50,aa.get('navigation_coexistence_long_run_verified'),
          '長時間穩定度、導航共存與停止／重新連線實測')],
      '待原生功能接通後，再驗證畫面、音訊、觸控與導航共存。')
    phase('原機離線 Google Maps',10,[
      (100,s.get('google_maps',{}).get('offline_on_device_verified'),
         'Google Maps 在 Garmin 原機離線執行已實測')],
      '依使用者指示延後；目前先研究原生音樂與播放器 App，Android Auto 排在後面。',
      deferred=bool(s.get('google_maps',{}).get('research_deferred_by_user')))
    assert sum(p['weight'] for p in phases)==100
    estimate=sum(p['weight']*p['estimate_percent'] for p in phases)/100
    completed=[]
    for p in phases:
        completed.extend(p['completed'])
    audio=s.get('audio',{})
    native_wav=audio.get('native_WAV_tests',[])
    if any(t.get('format',{}).get('sampling_hz')==16000 and
           t.get('speaker_confirmed') for t in native_wav):
        completed.append('原廠音訊診斷頁實機播放自製 16 kHz 單聲道 WAV，使用者確認五個音符；已驗證本機檔案播放，獨立菜單 App 與直接藍牙音樂仍待完成')
    if audio.get('phone_a2dp_bridge_audible_verified'):
        completed.insert(4,'Pixel → Pi → Garmin 通話音訊已實測持續播放 60 秒；音質與音量起伏仍待改善')
        if audio.get('latest_music_reconfirmation_utc'):
            completed[4] += '。本次現場再確認旋律與手機音樂有聲；未驗證完整播放上限時長'
    bulk=aa.get('AOA_bulk_prototype',{})
    if bulk.get('offline_cases_passed'):
        completed.append('ARMv6 雙向傳輸原型：'+str(bulk['offline_cases_passed'])+
          ' 個離線案例驗證同時收送、短寫入、未讀資料保留與取消／斷線；實機 USB 傳輸待接入')
    role=aa.get('USB_role_helper_analysis',{})
    if role.get('offline_cases_passed'):
        completed.append('原廠 USB 輔助程式：'+str(role['offline_cases_passed'])+
          ' 個離線案例辨識電氣測試與暫時控制流程，排除主機入口誤判；實際主機／供電仍待確認')
    framing=aa.get('framing_prototype',{})
    if framing.get('offline_cases_passed'):
        completed.append('ARMv6 封包解析／明文重組原型：'+str(framing['offline_cases_passed'])+
          ' 個離線案例通過，已串接先前傳輸原型；真正 TLS、手機及原機載入仍待確認')
    if aa.get('latest_diagnostic_menus') and aa.get('USB_hub_power_plan'):
        completed.append('現場提供七頁診斷選單；More 無法操作，未見主機切換入口。已釐清 Hub 下游供電與 Garmin 同孔充電的差別，主機／供電／Hub 驅動仍待驗證')
    capabilities=f.get('avdtp_capabilities',{})
    if capabilities.get('all_passed'):
        completed.append('原廠 AVDTP 音樂能力回覆：'+str(capabilities['case_count'])+
          ' 個離線案例通過；未啟用端點仍拒絕，合成啟用端點可回覆 SBC 資料。真正註冊／手機直連與原機 App 仍待驗證')
    control=f.get('avdtp_control',{})
    if control.get('all_passed'):
        completed.append('原廠 AVDTP 設定／開始／暫停控制：'+str(control['case_count'])+
          ' 個離線案例通過；該組 Open 留在等待狀態，後續連線流程另列。已找到回呼與狀態防護需求，未接上實機端點')
    ui=f.get('native_music_ui',{})
    if ui.get('bounded_function_count'):
        completed.append('原廠音訊設定／混音頁完整方法表為 66／57 項，已定位 virtual slot 60 的原生頁面建立路徑與 8 個有界流程；自製 App 的菜單註冊與安裝仍待完成')
    lifecycle=f.get('avdtp_lifecycle',{})
    if lifecycle.get('all_passed'):
        completed.append('原廠媒體連線完成／串流／暫停／斷線重連：'+str(lifecycle['case_count'])+
          ' 個離線案例通過，同一模擬系統由原指令推進狀態並交出封包；實際端點註冊與手機連線仍待接入')
    menu=f.get('native_music_menu_action',{})
    if menu.get('all_passed'):
        completed.append('原廠音訊菜單按鈕：'+str(menu['case_count'])+
          ' 個離線案例驗證回呼儲存、virtual slot 60 呼叫及原頁面動作；真正畫面建立、事件派送和自製 App 仍待完成')
    policy=f.get('native_music_policy',{})
    if policy.get('all_passed'):
        completed.append('原生 SBC 設定／串流檢查原型：'+str(policy['case_count'])+
          ' 個離線案例通過，涵蓋 128 種支援設定、媒體通道就緒、接收上限、連線世代與音框格式；尚未接入實機端點或原生回呼')
    gate=f.get('native_music_configuration_gate',{})
    if gate.get('all_passed'):
        completed.append('編譯後的原生音樂設定攔截原型：'+str(gate['case_count'])+
          ' 個離線案例驗證原廠拒絕回覆、支援設定的完整連線流程及未接管端點行為；已定位傳送失敗後的部分設定狀態，真正註冊／派送掛接與實機載入仍待完成')
    endpoint=f.get('native_music_endpoint',{})
    if endpoint.get('all_passed'):
        completed.append('自製原生音樂端點原型：'+str(endpoint['case_count'])+
          ' 個離線案例由程式建立端點，再執行原廠服務啟用、Audio Sink 查詢、能力回覆與媒體流程；已移除未實作的標頭壓縮宣告，派送／載入與手機實測仍待完成')
    dispatch=f.get('native_music_dispatch',{})
    if dispatch.get('all_passed'):
        completed.append('原廠收到完整藍牙訊息後的原生派送：'+str(dispatch['case_count'])+
          ' 個離線案例驗證固定派送表呼叫編譯入口、分段重組與完整媒體控制；找到長度截斷／方法表範圍問題並做模擬修正，實機配置／載入仍待確認')
    send=f.get('native_l2cap_send',{})
    if send.get('all_passed'):
        completed.append('原廠 L2CAP 傳送與佇列：'+str(send['case_count'])+
          ' 個離線案例執行傳送、配置與串接，確認未支援指令回覆沒有被後段修正；小封包複製後可跨堆疊重用保存。作業排程與無線送達仍待驗證')
    reply=f.get('native_music_reply',{})
    if reply.get('all_passed'):
        completed.append('未支援音樂指令的回覆修正原型：'+str(reply['case_count'])+
          ' 個離線案例通過，保留指令與交易編號，正常原廠回覆維持相同；'+str(reply['compiled_code_bytes'])+
          ' bytes 原型只在模擬副本使用，實機元件配置、載入及手機相容性仍待驗證')
    registry=f.get('native_voice_registry',{})
    if registry.get('all_passed'):
        completed.append('原廠語音包掃描與登錄：'+str(registry['case_count'])+
          ' 個離線案例驗證三組原語音、排序、重複與失敗控制；外層儲存與平台資料仍由測試提供')
    reads=f.get('native_voice_package_reads',{})
    if reads.get('all_passed'):
        completed.append('重新封裝的語音元件已核對原廠完整讀回：修正延伸區塊配置後，2,353,068 bytes 逐 byte 相同；先前讀回不一致的版本已排除，封裝僅供離線研究')
    selection=f.get('native_voice_selection',{})
    if selection.get('all_passed'):
        completed.append('原廠選取／載入自製元件：'+str(selection['case_count'])+
          ' 個離線案例通過，元件在原廠 3 MiB 保留區執行，保留 40 個原語音介面並初始化 12 個私有介面；相容性提示、實機接受與 App 選單仍待確認')
    outer=f.get('native_voice_outer',{})
    if outer.get('all_passed'):
        completed.append('完整原廠語音外層流程：'+str(outer['case_count'])+
          ' 個離線案例執行通用檔案 API、區域映射／讀取／解除、啟用與路徑快取，成功載入自製元件；底層磁碟驅動與設定快取仍由測試提供')
    compatibility=f.get('native_voice_compatibility',{})
    if compatibility.get('all_passed'):
        completed.append('原廠語音 ID／版本相容性：'+str(compatibility['case_count'])+
          ' 個離線案例核對 94 項原對照表；補齊目前語音快取後檢查通過，空快取會出現先前提示。真正設定初始化與實機接受仍待確認')
    music_loaded=f.get('native_music_loaded',{})
    if music_loaded.get('all_passed'):
        completed.append('前輪原生音樂元件載入整合：'+str(music_loaded['case_count'])+
          ' 個離線案例讓原廠流程讀入整合元件，由元件自行建立端點、掛接派送與發布服務；同一模擬環境完成設定／串流／重連，保留 40 個語音介面。當時媒體明確丟棄，尚未播放或安裝實機')
    music_stream=f.get('native_music_stream',{})
    if music_stream.get('all_passed'):
        completed.append('原生端點到解碼佇列與 PCM：'+str(music_stream['case_count'])+
          ' 個離線案例串接連線世代、狀態／接收上限與音框檢查；8 種 44.1／48 kHz 格式、48 音框的私人 PCM 與參考逐 byte 相同。工作由測試呼叫，尚未接實際音訊排程或喇叭')
    music_runtime=f.get('native_music_runtime',{})
    if music_runtime.get('all_passed'):
        completed.append('原生藍牙端點到原廠工作排程與虛擬輸出：'+str(music_runtime['case_count'])+
          ' 個離線案例接通解碼、音訊發布／混音／完成／容量喚醒，包含兩種工作優先序、暫停／重連與 CRC 恢復；仍是虛擬硬體，尚未實機播放或安裝 App')
    music_ready=f.get('native_music_ready',{})
    if music_ready.get('all_passed'):
        completed.append('音樂工作啟動與就緒檢查：'+str(music_ready['case_count'])+
          ' 個離線案例確認初始化完整回傳前／失敗時拒絕設定、取消狀態採一致快照，並限制 START 清單以避免原廠 8 位元計數器繞回；原有播放、停止與重連流程也通過。實機接受、連續串流與 App 仍待確認')
    continuous=f.get('native_music_continuous',{})
    if continuous.get('all_passed'):
        completed.append('持續音訊來源原型：'+str(continuous['case_count'])+
          ' 個離線案例讓同一原廠來源持續讀取四格 PCM 緩衝，缺資料補靜音、容量釋放喚醒解碼，暫停／斷線後完整停止並恢復；虛擬時間由測試提供，實機音質、延遲與 App 尚未完成')
    player_menu=f.get('native_player_menu',{})
    if player_menu.get('all_passed'):
        completed.append('自製播放器的私有菜單入口原型：'+str(player_menu['case_count'])+
          ' 個離線案例執行原廠圖示登錄、擴充、按鈕回呼複製與按下處理，呼叫自製 ARM 播放回呼；完整畫面、實機載入與 App 仍待驗證')
    player_loaded=f.get('native_player_menu_loaded',{})
    if player_loaded.get('all_passed'):
        completed.append('原廠載入器到播放器功能清單：'+str(player_loaded['case_count'])+
          ' 個離線案例由元件入口自動登錄回呼，保留原語音 40 個介面與既有項目、拒絕重複編號；這版無 MAIN 改動，實機封裝接受、完整菜單／觸控仍待驗證')
    player_selection=f.get('native_player_menu_selection',{})
    if player_selection.get('all_passed'):
        completed.append('播放器名稱及菜單選取：修正未初始化的名稱附加欄位，原廠 SQL 函式通過 6 項選取情境並派送載入回呼；新增分類已追到建構前，完整按鈕／畫面仍待驗證，資料庫只用記憶體副本')
    player_widget=f.get('native_player_widget',{})
    if player_widget.get('all_passed'):
        completed.append('原廠播放器按鈕建構及訊號：三組離線驗證建立一般 Widget，原按鈕訊號呼叫已載入播放器；參數 1 控制沒有播放訂閱，新增項目建構完成。完整頁面／觸控／畫面及實機接受仍待完成')
    return {'estimate_percent':round(estimate),'weighted_estimate_percent':estimate,
      'estimate_is_milestone_assessment':True,'goal_completed':False,
      'includes_deferred_Google_Maps':True,'phases':phases,'completed':completed,
      'research_updated_utc':s.get('updated_utc'),
      'ordered_priorities':s.get('ordered_priorities',[]),
      'microphone_cancelled_by_user':s.get('microphone_amplifier',{}).get('status')=='cancelled_by_user',
      'next':'優先完成一般菜單可顯示及按下的播放器入口、可接受的原機載入方式，以及手機直接藍牙音樂功能。補齊程式存活、停止與失敗回復；聲道／音質精修暫停。現場配對要求立即優先，Android Auto 排在後面。',
      'method':'各階段里程碑按研究計畫比重加權。離線原型、實機安裝、手機連線與長時間驗證分別計算；百分比為估計，會隨新證據調整。'}

def render_progress(progress,report_time):
    e=html.escape;pct=progress['estimate_percent']
    report_dt=timestamp(report_time);research_dt=timestamp(progress['research_updated_utc'])
    def time_tag(value,element_id):
        if value is None:return '尚無紀錄'
        return f'<time id="{element_id}" datetime="{e(value.isoformat(timespec="seconds"))}">{value.strftime("%Y/%m/%d %H:%M:%S")}</time>'
    rows=''.join('<tr><td>'+e(p['name'])+'</td><td>'+('延後' if p['deferred'] else
         e(str(p['estimate_percent']))+'%')+'</td><td>'+e(p['next'])+'</td></tr>' for p in progress['phases'])
    completed=''.join('<li>'+e(text)+'</li>' for text in progress['completed'])
    weights='、'.join(p['name']+' '+str(p['weight'])+'%' for p in progress['phases'])
    priorities=''.join('<li>'+e(text)+'</li>' for text in progress.get('ordered_priorities',[]))
    return f'''<section class="card research-progress-card" aria-labelledby="progress-title">
<div class="progress-heading"><h2 id="progress-title">研究進度</h2><span class="progress-status">持續研究中</span></div>
<div class="progress-total">約 <strong>{pct}%</strong><span>依研究里程碑估算</span></div>
<progress id="research-progress" max="100" value="{pct}" aria-label="整體研究進度估計" aria-describedby="progress-method">{pct}%</progress>
<p id="progress-method" class="progress-note">{e(progress['method'])}原機 Google Maps 雖延後，仍保留在整體計畫中。</p>
<div class="progress-times"><p>報告更新：{time_tag(report_dt,'report-updated-time')}</p><p>研究紀錄：{time_tag(research_dt,'research-updated-time')}</p><p>時間均為台灣時間（UTC+8）。</p></div>
<h3>目前研究順序</h3><ol class="research-priorities">{priorities}</ol>
<h3>已處理的進度</h3><ul class="completed-progress">{completed}</ul>
<h3>各階段與下一步</h3><div class="scroll"><table class="progress-phases"><thead><tr><th>研究階段</th><th>階段估計</th><th>接下來處理／待確認</th></tr></thead><tbody>{rows}</tbody></table></div>
<p><strong>下一步：</strong>{e(progress['next'])}</p>
<details class="progress-calculation"><summary>百分比怎麼估算？</summary><p>計畫比重：{e(weights)}。整體百分比為各階段估計乘以其比重後加總。</p><p>原生 Android Auto、原機自製 App、手機直接音樂與 Google Maps 尚未完成；仍需主機驅動、實機載入與影音整合等驗證，完成時間尚無可靠估計。</p></details>
</section>'''
