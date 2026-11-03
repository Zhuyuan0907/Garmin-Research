Garmin nüvi 2565RT 台灣 HWID1352 / 軟體8.00：既有街道與巷弄階層門牌候選 v3

此包累計新增188,870筆整數門牌：保留v2的130,637筆，再依原有巷弄階層補58,233筆。累計影響20,107條既有街道；本次改動7,650個街道根和22,216個下層父記錄。新街道、之號、未解名稱／路徑、衝突坐標與其他缺漏仍未完成，不能視為全台2026地址全面刷新。

候選Address Point：candidate/gmapprom1.img，153,346,048 bytes，SHA-256
1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360

本次使用明確8K allocation profile。原生有限CPU、来源／坐標與原廠精確還原證據，均不等於原機已接受8K、完整中文搜尋UI或路線已成功。header checksum規則及實機接受性仍未知。不要把檔案驗證結果說成實機驗收。

安裝工具只接受manifest中這台已授權裝置的精確model、軟體、unit與USB身份，保護原廠底圖／道路／時區／JCV／SID／G2S／資料庫／解鎖檔案，要求SearchRepair v2道路圖已在機台且SHA符合。包內roadmap/Taiwan_OSM_SearchRepair_v2.img是相同版本的提供檔；此工具不更新道路／韌體／原JAI，也不播放音訊。

五個可升級的Address Point前身必須size和完整SHA皆完全符合：原廠、已驗證9門牌、Taichung候選、country v1候選、country v2候選。未知狀態或任何既存partial／recovery檔案均拒絕。唯一目標為.System/gmapprom1.img。

預設命令是唯讀preflight：
  python3 install_native_house_supplement.py

明確受控操作：
  sudo python3 install_native_house_supplement.py --install
  sudo python3 install_native_house_supplement.py --rollback

執行依赖本包的device_support.py、native_8k_stock_restore.py、manifest.json、restore-layout.json.gz、actual-stock-restore-binding.json與candidate/gmapprom1.img；只需Python3標準函式庫和原v2支援的Linux USB／mount工具。這些可攜式執行檔不依赖/root/garmin或研究工作區。validation內的研究測試程式不供裝置操作。

任何裝置修改前，先驗證完整候選SHA、固定compactstock recipe及actual8K binding，串流計算精確原廠4K SHA。rollback用879,499-byte原廠recipe加292,144-byteactual binding；另讀候選各下層表的原廠長度prefix以及未改元件，在原廠4K配置下還原96,739,328-byte檔案。不建立第二份完整原廠備份。

transaction／execute／image_state／device_preflight／main和device_support均與封存v2保持AST／逐byte一致：先唯讀核對裝置、所有保護檔案及空間，明確操作才remount rw，建立獨占partial，完整寫入／fsync／雜湊讀回，替換前重查來源、裝置與inode，再atomic replace、完整讀回及安全unmount。rollback建立完整較小暫存檔才替換，不直接truncate現有Address Point。commit後失敗須依回傳state檢查，不自動隱藏錯誤或刪除不屬於此程序的檔案。

現有compact還原證據是唯讀雜湊核對，不是實體rollback測試或原子交易保證。為完整暫存目的檔加reserve準備足夠可用空間。partial存在時勿自行忽略；程序會保留該狀態並拒絕覆寫。

小檔案準備階段尚不含candidate／roadmap IMG hardlink，實際整包load_manifest控制需等所有review讀取者關閉，由root補入後另外記錄。root負責最後bundle／ZIP／LAN發布；目前的準備proof與seal只綁定小檔案。
