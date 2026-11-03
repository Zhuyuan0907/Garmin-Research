v2 候選封裝：準備完成，尚未執行封裝或實機安裝

封裝程式：scripts/package_navigation_repair_v2.py。
目前審核資料：preparation-review-rev2.json；初版 preparation-review.json 與舊程式 gzip snapshot 保留。

由 ROOT 在本輪 terminal build、sort、MDR、road proofs 都完成並審核後執行：
python3 scripts/package_navigation_repair_v2.py --road-proof staging/navigation-road-regression-v2/road-city-regression-proof-v2.json

固定新圖：Map/Taiwan_OSM_SearchRepair_v2.img，FID7053，sort19/7053。
輸出只到 staging/navigation-repair-v2/package、package-result.json 與 reports/downloads/v2 ZIP。
使用 compiler IMG hardlink，不複製第二份 raw map；ZIP 每一成員讀回驗證。
封裝程式不操作 USB／服務、不寫 canonical state，不覆寫 v1 結果或 ZIP。
ROOT 後續的 publisher 才更新報告／state。

輸入明確綁定 terminal build 圖資 bytes/SHA、v2 sort allocation bytes/SHA、
MDR candidate-mdr-query-proof-v3.json（圖資仍是 v2，reader source revision 為3）、
v2 road/city regression、packed native finite proof、producer controls、immutable Java source/classes。
包內沒有 GarminOS、原廠 NT／DB／授權 binary；原廠圖層以 metadata/hash 參照保留。
舊 RESULTS.txt 不當作新排序相容性的成功證據，也不放入 v2 包。

installer 只有 NEW_PATH 一項常數從 v1 改到 v2。
normalized AST、全部 function bytecode/constants 等價；6 個新的 bundle load／identity／
tempdir install-rollback roundtrip／未知圖資拒刪控制通過，原 v1 19 tests 只繼承、不重跑。
未驗 Garmin FAT 實體 rename、USB、原機地址入口、導航或實機成功；包裝後仍屬候選。
