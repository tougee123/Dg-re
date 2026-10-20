# 激活门控 / 黑屏机制分析（静态反混淆 + 对抗验证）

> 问题：打开 App 什么都不显示（黑屏），只有正确输入激活码才进主界面；就算对了也要关一次再开才进真正页面。
> 方法：4 簇（门控/校验/机器码/服务器）各一个提取 agent + 一个对抗验证 agent。**下面严格区分「静态确认」与「推断/仅动态」。**

---

## 0. 一句话结论

黑屏**不是**"窗口没设根控制器"，而是 **`ViewController` 被加载了、但它的 `viewDidLoad` 同步什么 UI 都不建**——
把全部工作甩进一个后台 `dispatch_async` 计算块（反篡改 + 激活校验）。主界面（应用列表表格）要等这个
**异步门控通过后**才被"动态派发"出来渲染。校验是**服务器权威**的（不是本地比机器码），错误码走 `exit()` 退出。
"就算对也要关一次"= 成功那次把授权**写进 NSUserDefaults**，但渲染主界面的判定是在**下次启动读**持久化状态时才成立。

⚠️ 诚实边界：**"激活通过 → 渲染主界面"的那条确切分支边,是 CFF + 运行时动态派发,没能静态钉到单条指令。**
以下把能坐实的钉死，够不到的明确标注。

---

## 1. 黑屏的机械成因 ✅CONFIRMED（两 agent 反编译一致）

- `-[AppDelegate application:didFinishLaunchingWithOptions:]`(0x100283c20)→`sub_100283F64`→
  **`-[AppDelegate refreshUI]`**(0x100284430)：**无条件**建 `UIWindow → UINavigationController → ViewController`，
  `setRootViewController:`(0x100284558) + `makeKeyAndVisible`(0x100284584)。没有任何 license 分支。
- **`-[ViewController viewDidLoad]`(0x1002f1a80) 反编译=只做两件事**：
  1. `[super viewDidLoad]`(0x1002f1aa8)
  2. `dispatch_async(global_queue, block sub_1002F1B14)`(0x1002f1af8)
  **没有 `addSubview:`/`setBackgroundColor:`/建表格**。`-[ViewController viewDidAppear:]`(0x1002fddcc) 也只 `[super ...]`，
  同样不建 UI。→ 所以 `self.view` 停在裸的默认（黑）视图 = **黑屏**。
- 后台块 `sub_1002F1B14` 及其 worker（`sub_1006BFE40` 0x7364B、`sub_10089C148` 0x6170B、`sub_100573F5C`）：
  **全程 0 个 objc_msgSend / 0 个 dispatch / 0 个 selref**——纯整数运算，块捕获 `self` 当**裸指针**喂给运算
  → 判定为**反篡改/完整性校验**（对对象或类做哈希），不是 UI 构建器。
- **`-[ViewController stts]`(0x1002f7cdc) 是 `CLLocationManager` 后台保活**，不是激活检查：
  `setAllowsBackgroundLocationUpdates:YES`(0x1002f8364)、`requestAlwaysAuthorization`(0x1002f8d40)、
  `startUpdatingLocation`(0x1002f8ddc)、`kCLLocationAccuracyThreeKilometers`。⚠️**推翻**之前"stts=激活门控"的猜测。

## 2. 剪贴板激活码校验 ✅结构 CONFIRMED / ⚠分支方向未证

- **读剪贴板**在 `sub_10052A2F0`：`[UIPasteboard generalPasteboard]`(0x10052a6c8)→`.string`(0x10052a94c)→
  `stringByTrimmingCharactersInSet:`(0x10052a414)→`length`(0x10052aa04)。剪贴板即激活输入 ✅。
  （`copyBundleId:` 那个 `sub_100326654` 是"复制到剪贴板"的按钮=**写**剪贴板，不是读，已正确区分。）
- **长度/格式不透明谓词门**(0x10052aa24-78) 存布尔到 `[X19,#0xE8]` → 重载(0x10052ab7c)当派发索引 `BR X8`(0x10052ab90)
  → 一条分支落到 `MOV W0,#0 ; BL _exit`(0x10052ab9c，`_exit`@0x100b6aff8) = **格式不对就 `exit(0)` 退出** ✅（结构坐实）。
  ⚠️ **未证**：哪个 `[X19,#0xE8]` 值走 exit（不透明谓词方向没静态解出），所以"空剪贴板→退出"是合理假设非铁证。
- **服务器权威校验**（同簇 CFF 片段）：`NSURL URLWithString:`→`NSURLSession sharedSession`→
  `dataTaskWithURL:completionHandler:`(0x10052cf60)→`resume`。配 `scheduledTimerWithTimeInterval:`/
  `[NSThread sleepForTimeInterval:]` = 轮询/重试。**本地没有比机器码/token 的 `isEqualToString:`**——判定交给服务器 ✅。
- **成功写盘**：`[NSUserDefaults standardUserDefaults] setObject:forKey:`(0x10052c2c8)+`synchronize`。
  ⚠️ 写的 key/value 是 XOR 密文、未解出（不能 100% 断定就是把服务器授权写进 tz0111endtime，但方向一致）。
- ⚠️ **未证的关键边**：从启动块 `sub_1002F1B14` 到这个剪贴板簇 `sub_10052A2F0` 的调用边**没连起来**
  （两者 CFF 上下文/派发表不同：块用 X21 + 0x1015Bxxxx 表；剪贴板簇用 X19 + 0x10158baf0/0x1015decb0 表）。
  所以"启动→剪贴板→exit→黑屏"这条因果链**是推断**，不是静态实证。

## 3. 机器码 + license 存储 ⚠PARTIAL

- **MD5→32hex 原语** `sub_1000E0F78`：`CC_MD5`(0x1000e0f9c) 后格式化 32 字符 hex ✅。但**无直接调用 xref**（CFF 派发进入），
  **未证**其输入就是设备信息 → 不能坐实"machine_code = MD5(设备)"。
- **IDFV**：`sub_10051AD70` 装载 `identifierForVendor`(selref 0x100c4a608) ✅，但 **IDFV→MD5 的数据流未证**。
- **`tz0111endtime`**：明文 cstring@0x100ba2822 / CFString@0x100c42958。**只被读 2 次**（都 `objectForKey:`，在 `sub_1002E42B8` 内，
  @0x1002e4970 / 0x1002e5080）。**字面 key 无静态写入点**（写入用运行时构造的 key 或在服务器响应处理里）。
  存储走 `standardUserDefaults` → **`Library/Preferences/apple.allIDTDG.plist`**（⚠️**修正**旧说的 `com.apple.a<hex>.plist`——那不是这个 key 的落点）。
- `-520-22` / `520-22` 在 __cstring **明文不存在**（加密/运行时构造），machine_code 的确切拼接格式**未证**。
- `%@/520.plist` 路径由 `sub_10011E390` 构造（另一个文件，用途未定）。
- ⚠️ `sub_1002E42B8` 的**归属类未解**（CFF 合并片段，xref 是派发表槽 0x10150b348/0x10150c440/0x10150c458，不是干净的 method_t）——
  只能确认它**不是** stts、**不是** ViewController.viewDidLoad；它只是**读**到期时间的片段，真正的门控判定在别处。

## 4. 服务器 + 崩溃防护 ⚠PARTIAL（含一条漂亮的静态解密）

- **两个加密 URL 字符串对象**（isa 0x166f4b0）：OBJ 0x10154A3E0(len 21) 与 OBJ 0x10154B940(len 24)。
- **探测 vs 真实 已 xref 坐实**：
  - len-21 → `sub_10052D6D8`（`NSURL`+`NSURLSession`）= **连通性探测**。
  - len-24 → **`sub_100567AC0`（0x9dac/~40KB）= 真正的 license 验证网络函数**（建 `NSMutableURLRequest`、
    `setAllHTTPHeaderFields:`、`setHTTPBody:`、3× `dataWithJSONObject:options:error:` JSON 体）。
- **URL 解密已纯静态复现** ✅：解密器 `sub_10052D344` 读密文@0x10154A3A0(`66ceda4b419e8dcc…`)，
  逐字节变换（byte0 EOR 0x0E、byte1 EOR 0xBA、byte3 EOR 0x3B…）：`0x66^0x0E='h'`、`0xCE^0xBA='t'`、`0x4B^0x3B='p'`
  → **`https://www.baidu.com`**（len 21）= 那个诱饵探测地址。真实 /yz URL 在 `sub_100567AC0` 内就地解密（引用缓冲 0x10154B730）。
  ⚠️ **不需要**动态/CFF 全模拟——线性读解密器即可（提取 agent 高估了难度）。
- **内嵌 RSA-1024 私钥@0x100BA2911** ✅（`MIICXQIBAAKBgQ…` PKCS#1，812 字符 base64）。
- AES 选择子 `ACPDS:kaiv:`@0x100b9be89，18 处调用 ✅；但"AES-128-CBC key==iv"是**从选择子推断**，IMP 未证做 CCCrypt。
- token `520-5555494424dc2cb0c3de34e3ba319eccf46f4cb6`@0x1014df55c：明文、**0 xref**（未被引用，疑似残留/死数据）。
- 退出原语：`_exit`@0x100b6aff8、`_pthread_exit`@0x100b6b730 ✅。（`_atexit`@0x100b6ade8 只是**注册**退出处理器，不是退出触发，别混。）
- ⚠️ **`tz0111endtime` 的写入/持久化路径没找到**（字面 key 只有读）→"服务器返回到期 → 写 tz0111endtime → 下次启动放行"这个闭环**静态未证实**。
- **仅动态可知**（已正确标注，静态拿不到）：真实 IP `154.222.16.171`、baidu→IP 重定向、JSON 字段名、
  `machine_code=MD5+'-520-22'`、`username==password`、运行时 16 字符 AES key、state=`正常`/606、3 次重试、`com.apple.a676924c9f0.plist`。

---

## 5. 对你"做加固"的启示（这套门控设计值不值得学）

**值得学的点**：
- **UI 与授权解耦 + 后台异步门控**：`viewDidLoad` 不建 UI、甩后台块做完整性+授权，再动态派发渲染——
  让静态分析很难把"通过条件 → 渲染"这条边钉死（我这次就没钉到）。这是有效的**分析对抗**设计。
- **服务器权威校验**：本地不放"正确答案"（无本地 `isEqualToString` 比对），破解者拿不到离线判据。
- **诱饵地址**：真实 URL 加密、`https://www.baidu.com` 只做诱饵探测——误导抓包/静态。
- **完整性块喂 `self` 裸指针做哈希**：把反篡改和正常流程缠在一起。

**它做得不好的点**（你别学）：
- 内嵌 **RSA 私钥**（0x100BA2911）——私钥根本不该进客户端，一提就是完整密码学破防。
- 关键字符串只是**单层可逆 XOR / 逐字节变换**，线性读解密器即可还原（如 baidu URL），没有真正抬高成本。
- `exit(0)` 硬退出容易被 hook 短路。

**加固建议**：私钥留服务端、校验用**挑战-响应+签名**而非客户端存密钥；字符串用一次性/多层且与代码完整性绑定；
用"静默降级/假数据"替代 `exit()`（退出反而暴露判定点）。

---

## 6. 动态收口（frida 轻钩子实测，把静态够不到的边钉死）✅CONFIRMED

设备已激活，spawn 后用**只钩框架/libc 的安全集**（重钩子会被后台完整性哈希块检测→秒退）跑通，拿到：

### 6.1 渲染门控边（之前静态没钉到的那条）—— 现已实证
```
[RENDER] reloadData app-caller: DG:0x1003cfa44 <- DG:0x1002ca5c0
```
- `-[UITableView reloadData]` 的调用者 = **`sub_1003CF990`**（0x1003cf990–0x1003cfac4，ViewController 的表格渲染 CFF 片段）；
- 其上一层 = **`sub_1002C6FAC`**（0x1002c6fac–0x1002d4ff0，**57KB 的中央 license/调度大函数**，也是派发 `Reuid:`/`Resetsj:`/`clkcin2` 的同一个）。
- 时序：这条 RENDER 事件**紧跟在 `state=正常` 的 license 响应之后**触发 → 证实主列表渲染是 **license 校验通过的下游**。
- **完整门控链（合并静态+动态）**：`viewDidLoad`(0x1002f1a80) 甩后台块 → 反篡改+网络 license 校验（`sub_1002C6FAC`）→ 校验过 → `sub_1003CF990` → `reloadData` → 主 UI 出现；**没过就 exit/不渲染 = 黑屏**。静态之所以钉不到，正因 `sub_1002C6FAC` 是 57KB CFF + 计算跳转派发。

### 6.2 动态补齐的确切值（静态是推断/未找到的）
- **机器码全值** = `6d56b4abd06429e7d364b95185d4fb4f-520-22` → 坐实格式 `MD5(设备信息)[32hex] + "-520-22"`，且请求里 `username == password == machine_code`。首个请求用**全零** `00000000000000000000000000000000-520-22`（设备信息未就绪的兜底），随后才发真值。
- **`tz0111endtime` 写入点（静态只找到读、找不到写）实测到了**：`setObject:forKey:` 写 `tz0111endtime = 2026-07-27 09:31:34`（**NSDate**，= 服务器 `endtime=1785115894` unix）+ `ntt = 0`。→ 下次启动读它判定是否放行（印证"关一次再开"）。
- 服务器 `154.222.16.171` + `https://www.baidu.com/yz`，响应 `state=正常`、运行时 4 个 16 字节 AES key（`DrT8h0Fj70l522Ri` 主 / `ICmCIVMIKNQfFXuT` 机器码 / `X4Q97SvE2da9FaMA` 时间戳 / `W8emAZDGdcysx4R6` ss）全部复现。

### 6.4 全量字符串静态解密（Unicorn 批量模拟）—— 错误串 & 全 UI 已解 ✅
`dg_decrypt_all.py`：映射整个镜像→对每个加密串对象(isa 0x10166f4b0；flags 0x7c8=UTF-8 / 0x7d0=UTF-16LE)
定位其内联 MBA 解密器(xref 到 dataptr 的函数)→Unicorn 从函数入口模拟、**跟随 CFF 的 BR 派发**(不透明谓词全局量在镜像里，分支自动走对)、
以"dataptr 全部字节被写满"为停止条件→读出明文。1815 个对象恢复 1450 条净化明文(356 中文 + 1094 ASCII)。
产物 `STRING_INVENTORY.txt`。**之前"只在失败路径解密、动态抓不到"的错误串，纯静态全拿到了**：
- **`0x10154a380` = `复制的兑换码错误.充值卡错误`**（就是你在设备上见到的那条）
- `0x10154a360` `请复制兑换码.启动程序1`、`0x100c4b720` `请复制授权码.重新启动程序7`
- `0x10154d980` `授权错误5237\n请重启手机`、`0x10154ea50` `授权错误5231\n请重启手机`
- `0x10150e3b0` `网络错误`、`0x101511ae0` `应用ID错误`、`0x1015506b0` `程序错误5-2`、`0x10165fc90` `BA错误1.请重试`
- `0x10154fc50` `请检测网络连接.请复制兑换码.启动程序4-2\n请修复网络\n请切换网络`
顺带白得全 UI：`备份/恢复/修改系统版本号`、`结束持久化`、`请输入新的标识符`、`高级选项`、`APP列表`、国家选项(CN/HK/TW/US/JP/GB/KR) 等。
方法学要点：这套"每串独立 MBA 内联解密"对**动态**很硬(串只在用到时才解、用完可能再加密)，但对**静态 Unicorn 模拟**几乎透明——因为解密是确定性的、密钥烤在指令里、跟着 CFF 全局量走分支即可。

### 6.3 反 frida 检测点（加固可借鉴）
对照实验定位：`frida_light`（钩 connect/URL/body/JSON/setObject/AES）与 `frida_light2`（+ `reloadData`）**都能存活**；但加了 `NSUserDefaults objectForKey:` / `UIPasteboard string` / `UIAlertController` / libc `exit`/`abort` 钩子的版本**秒退**（且不走 libc exit，用 `abort_with_payload`/裸 syscall 自杀）。→ 该 App 的运行时反篡改**专门盯这几个 license/退出相关方法的 hook**。做加固时这是个可学点：**把完整性检查覆盖到"授权读取(objectForKey)、剪贴板、告警、退出"这些关键 API 的 prologue**，而不只是自身 __text。
