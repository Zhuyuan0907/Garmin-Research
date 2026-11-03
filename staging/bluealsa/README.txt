BlueALSA v4.3.1 通話狀態修正候選

已編譯：bluealsa-4.3.1-garmin。SHA-256 與編譯選項見 manifest.json。
來源 patch 與真實 RFCOMM socket 回歸測試 patch 一併保留。
5 項 HFP/HSP 協定測試全部通過。未修正版在外部 CIND 回覆測試失敗，修正版通過。
沒有替換 /usr/bin/bluealsa，沒有重啟連線中的服務；候選尚未部署。

修改：當 RFCOMM 外部處理器已連接時，CIND? 交由它回覆；沒有外部處理器仍回覆原有閒置狀態。
scripts/test_hfp_call_audio.py 依來電／撥出／通話中狀態回覆 CIND、CLCC，拒絕 ATD，不撥真實電話。
候選啟用 debug 和 mSBC 編譯；保留 Garmin external CIND state handler 字串供 helper 偵測能力。

實機證據：使用者確認暫時同步原 daemon 的 CIND 格式後，模擬來電可接聽且有旋律，測試含 Pi 解碼 MP3。
證據 evidence/audio-playback-20261002T175259349859Z.json；暫時改動已還原且讀回確認。
這個實驗不是新版 daemon 的實機部署驗證，也不證明長時間播放穩定。

切換候選服務時維持標準 org.bluealsa。先查代理實際 PID／D-Bus、準備音訊服務，Garmin 連線列第一優先。
目前保持已連線的服務。下一次現場切換，需以新的 incoming 播放確認候選實機效果。
使用者後續已允許有聲測試；不再引用較早的禁止播放狀態。
