# navigation-v2-one-family-lane-delta-plan-v1 HANDOFF

結果為sealed held/frontier，不是complete family plan。Source172188的完整prepared metadata與21 node IDs已由18867B saved capture真讀出；原literal為臺中市／北屯區／昌平路二段50之6巷2弄／39號，rawpoint['24.19197', '120.6841351']、native24[1127428, 5624288]。different_coordinate_nodes0、coordinate_selection_ready=true、embedded_floor_unit=false，但separate_floor_unit_nodes20，因此source floor gate未ready，不能挑一個node假當base39號。

Actual source check57b554 EXIT0。首次2dfd3c EXIT1只因我預設city台中市而原raw為臺中市，failedsource與receipt保存；新v2source保持臺原字，允許兩city寫法以核對literal，沒有替換street／house／city或nearest。Saved capture共兩次明示讀18867B，各解383921B；不是singlepass。原137MB source／PBF／fullnodeledger都0。

Actual普通FILE reader b8c780 EXIT0，共143664 IMG bytes／18 physical reads，小於2097152；無CPU／guest。每圖都真讀120B MDR DIR：v2 SHA2650321e2f1bcbb22234f9f2e8bb3f453c71e69bafd2eaa9abd681cdb1f9dfb0，v3 SHAc5bacd4c23165f2332e5122b42190ee6c23c4e3cf1d23a047a849ea01957e2a7。MDR actual v2 124255307B／v3 149220356B。完整six-level actual descriptors、120B raw與512B APheader保存，原stats在讀取前後一致，wholeIMG hash只繼承原seal不重算。

重要profile更正：current-v2與v3的L3都23-bit first-child／112-bit stride；原stock才22／111。舊parent任務誤把stock當current，已在新scope errata保存；沒有shrink或global width改動，也不把L4總數跨2^22當v3 bug原因。

原stock exact parent昌平路二段：info13188，record805319491／L3 ID13123。Actual v2/v3 labelref均24559、CP950 a9f7a5adb8f4a447ac71，raw flags均4；v2 L4 first2553254..2553847、v3 first4175477..4176070，count均594。整個112-bit parent record除first-child bits[20,43)外一致，沒有修改原bytes。

Source floor hold後，selected L4/L5/L6 traversal0，exact v3 same-coordinates39號house未查（unknown，不是absent），complete cloned subtree／remap／append bins／new IMG counts及整體容量均未完成。只給條件式root算術：若clone594 L4則新增9504B、L4 first3781595/count後3782188，23-bit ptr與12-bit count能表示；L5/L6 descendants及其wholebit shifts、FAT growth、finalIMG容量未知，不能由此放行。Currentv2 physical128356352B、whole4K declaration134217728B；原header／CHS／圖檔完全未寫。

原v3有58233巷弄house的complete native-tree普通FILE讀回證據已存在（existing-v3-format-proof-pin.json）；lossless sidecar不是尚無巷弄格式的證明或代替。後續writer若來源ready必clone完整family rawbits、保留labels/GMP、只patch已證first/count，current L5 stride126與2尾padding需wholebit splice／crossbyte，不能逐record padded串接。此scope沒有執行任何writer。

最小missing：需能保持per-node floor/house metadata的policy解除本group20 floor-unit nodes，不能lossy忽略之號／樓層或任選base節點；再查exact v3 full path／house label／raw24與完整594根child子樹，才可完成remap與容量。沒有擴來源或要求裝置。

所有source-release／family-plan／v3fix／install／App／backend-owner／STOP_DONE／phone／speaker／fullTaiwan flagsfalse。failed source、source proof／complete target、actual FILE journal／headers／DIR／parent proof、errata／frontier／receipts一併hash-size-stat封存；無chmod，不改oldseal。scope-proof.json是總結；proof.json只代表source-gate當時IMG0的phase，兩者不混淆。Seal後停止。
