此份宣告針對台灣 HWID1352、MAIN8.00，來自原指令與離線執行證據，並非 Garmin 官方 SDK。

`521E5E` 的五個參數依序是回呼、回呼參數、workspace要求bytes、priority索引、CP1252名稱指標。第五個參數不是泛用物件，必須可讀且以NUL結束。本輪原程式把 `Garmin Music` 轉為UTF-16LE，放入100-byte descriptor的offset60；只測過這個短名稱，沒有驗證一般長名稱、其他codepage或名稱生命週期。

原配置器建立100-byte descriptor與4248-byte workspace之後，原`358BF8`在workspace尾部建立108-byte TCB及52-byte compact context frame。原`2FBBBE`登記descriptor，原`521D7C`選取空適配槽；原create填入回呼、參數及TCB，再執行`2FCF44` POST，最後回傳64-byte適配record。

本輪分兩個接續範圍執行，不重跑已完成配置。第一個新增有效名稱輸入，僅重新執行最後兩條參數載入指令；第二個從POST前接續到原create完整返回。完整FILE核對1676個CPU store的地址和值、24個whole-zone快照、3403條原指令及7次helper完整ABI返回。原create的callee-saved registers、SP及CPSR mode亦保持。

新TCB由原核心程式建立，但「當前工作」仍是模型輸入。原POST把新TCB狀態改為ready，插在此current後面；priority索引0讀到240，所以沒有發生preemption。原root `521E44` 和使用者回呼尚未執行。MMU關閉、heap storage和tables仍由host提供，實機CPU及實機heap未知。沒有安裝此宣告或新的播放器，也沒有改寫MAIN或發出聲音。

`create_abi_v2.h`／`create_abi_check_v2.c`已通過ARM1176／Thumb／soft-float的C11編譯語法及offset檢查。完整priority索引界限、pool耗盡、OOM、堆疊大小上限、合法目前工作、取消／釋放及GUI所有權仍待研究，不宜直接呼叫未验证的實機地址。

下一步以原核心建立controller，再由原POST／WAIT／restore切入原root，核對同一個record回呼及參數，之後接回既有播放器與GUI工作生命週期。離線完成這些仍須透過實機診斷與載入測試確認。
