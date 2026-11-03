Garmin nüvi 2565RT 導航搜尋修復候選 v1

這包已通過離線地圖結構、中文排序與城市／道路索引檢查。
尚未安裝到車機或確認地址搜尋正常，不能視為已完成修復。
資料日期：2026-10-01。這是 OSM 地圖，不是 Garmin 官方 NT 更新。

請由本專案在原 Raspberry Pi 上處理，車機需 USB 隨身碟模式。
解壓縮後：
  python3 install.py --bundle .
上述只做唯讀預檢；確認身份後才執行：
  python3 install.py --bundle . --install
還原：
  python3 install.py --bundle . --rollback

只新增 Map/Taiwan_OSM_SearchRepair_v1.img；上一版專案 OSM 會改為
.img.disabled 保留，以免兩版同時載入。原廠道路主圖、門牌層、底圖 DEM、
時區、授權與版本配套檔全部保留。Windows 手動複製不是此安裝流程。

實機驗證請依 device-ab-checklist.txt，記錄路名、結果及耗時。
一開始只勾新版 OSM，暫時取消 CN 與 Address Point，再測原廠配套作對照。
原廠 CN 與 Address Point 同勾本來是互補；不是兩者必然衝突。
tests/road-anchors.gpx 僅供比對道路位置，不代表地址搜尋成功，亦不自動匯入。

這包不含新 GarminOS、原生 App 或藍牙音樂程式。
導航問題實機確認修好後，才繼續原音樂／App 研究。
