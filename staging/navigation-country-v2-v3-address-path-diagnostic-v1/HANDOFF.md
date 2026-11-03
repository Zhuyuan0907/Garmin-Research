# navigation-country-v2-v3-address-path-diagnostic-v1 HANDOFF

兩圖既有精確path都存在：昌平路二段 → 50之6巷 → 2弄 → 39號；每一步均unique exact primary CP950 label，未使用secondary ref、suffix alias、nearest或假missing-child。Actual c85380 EXIT0，共253674 IMG bytes／1411 FILE reads（全局上限2097152），每圖594 L4＋26 L5＋117 L6。Actual L5 group初始bit shift2／stride126，L6 stride68；完整raw spans及1476 observed records保留。

v2 path records805319491／1076295446／1342980390／1611333657；v3為805319491／1077917669／1342980390／1611333657。只L4 clone record ID不同，後段同原L5/L6。兩圖leaf ID720921／record1611333657，raw24同[1127428,5624276]；source摘要[1127428,5624288]差[0,-12]。Approx quantized-source距離26.11732968738901m；與原decimal source24.19197/120.6841351約26.881698534647068m。這是lookup後兩個已指定點的比較，未用距離選門牌。

所以不能把172188的39號當missing新增，也沒有same-source-coordinate match。來源floor/unit、官方alias、正式門牌／路由／install holds全部保持。Root另agent的21node floor partition研究與此普通existing-tree診斷分開；此scope沒有重讀source capture、PBF、groups／fullnodeledger或whole-v3 tree/house ledger，沒有nativeCPU、writer、firmware compile、IMG/DB修改／安裝／裝置／音訊。

普通reader從上一scope已pin的readonly AP code抽出到新namespace，唯一class差異是登记readonly handle供finally清理；原sealed source未import/執行或修改。兩圖header/FAT／120-byte DIR與parent按各實際4K/8K descriptor讀取。所有raw flags保持原bits，只以已證低3bits作childlevel；不修改unknownflags。所有source handles真closed、stats前後一致，destination只有新scope證據檔案。WholeIMG SHA繼承oldpins不重算。

新output independent bitloop audit核對全部1476記錄 significant bits、descriptor fields、CP950 label/ref對應、6個actual saved group spans與exact path一致。Source/record/label cache完整工程proof保留私密文件；供root報告的小scope-summary.json為3440B，≤8KiB。

Evidence：proof.json含full FILE journal／source stats／所有path rawfields／labelcache；observed-records-v2/v3.jsonl；6個selected child .bin rawspans；output-bit-label-audit.json；actual receipts、readonly reader source／dependency manifest／diff。所有claim flagsfalse，scope完成後hash-size-stat seal並停止。不叫搜尋UI／正式路由／v3道路修復／新街加入或install成功。
