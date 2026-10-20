# 最小采集计划 rev2(离线修订;仅规格,未实现;待你确认才执行)

2026-10-19,新加坡华语。**本轮纯离线、只改计划**:没改脚本、没连设备、没启动 App。
**重要声明**:`evidence/capture.js` 与 `evidence/run_capture.py` **仍是旧版(rev0)**,本文档描述的是**目标规格(spec)**,**尚未实现、尚未验证**。待你确认本 spec 后,我才会给出「仅供审查、不执行」的脚本修改稿。

被审查旧脚本(完整路径,未改动):
- `/Users/tougee/Downloads/DG 管理器/work/dg239-authorized-min-capture-20261019/evidence/capture.js`(rev0)
- `/Users/tougee/Downloads/DG 管理器/work/dg239-authorized-min-capture-20261019/evidence/run_capture.py`(rev0)

---

## 零、离线新发现(决定整个模型)
样本里 **只引用 completion-block 版 API**(`dataTaskWithRequest:completionHandler:`、`dataTaskWithURL:completionHandler:`),**委托方法 `URLSession:dataTask:didReceiveData:` / `didCompleteWithError:` / `didReceiveResponse:` 全部 absent**,也无 NSURLConnection / 同步请求。
⇒ **响应经 completion block 的 `data` 参数返回,不走 `didReceiveData:`**(直接对应审阅第1/2点)。logind1 的 parse 站点就落在该 completion 巨函数 `0x1005bbe48` 内。整个采集模型据此重建。

---

## 一、completion-block 模式下如何安全、可验证地采响应对象(审阅#1)
- 在 `dataTaskWithRequest:completionHandler:` 与 `dataTaskWithURL:completionHandler:` 入口:记录 `request.URL` 末段+host、method、`HTTPBody` **长度(仅长度,见#4)**、以及 **completion block 指针**(arg 中的 block)及其 **invoke 指针**(block+0x10);同时记录该次 `NSURLSessionTask` 指针+`taskIdentifier`。
- 对每个被捕获到的 completion block 的 **invoke** 下读-only hook:onEnter 读 `arg1=data(NSData)`、`arg2=NSURLResponse`、`arg3=NSError`。
  - `NSURLResponse` 给出 **响应侧的 URL + HTTP 状态码** → 这才是 completion 模式下的**连接/请求身份**(比 taskID 更硬:响应对象自带它对应的 URL)。
  - `data` 即「**URLSession 交付的响应体**」(见#2 的措辞纪律)。
- **可验证性**:block 指针在 dataTask 创建时捕获 → 其 invoke 地址确定 → hook 命中即证明「这次响应交付经过了我们捕获的那个 completion」。
- **覆盖不了就标记**:若某接口本次**不经**可捕获的 completion(例如 block 被封装/转派到无法稳定定位的 invoke,或该接口本次根本没触发),该接口本次**判为"未覆盖"**,不硬凑。

## 二、措辞纪律:不叫"wire 原字节"(审阅#2)
- completion 的 `data` 一律称 **「URLSession 交付的响应体 D」**,**不**称 wire 原字节——因为它已在 OS 网络栈(含 TLS 解密)之后,本计划**没有**在 socket/TLS 之前设点。
- 只有当能证明「采集点位于 App **自身**对该 data 的第一步转换**之前**」时,才可称其为「App 看到的原始响应」;证明方式=按执行顺序,block-invoke 读 D 在前、App 的首个转换(ACPDS/AES/base64)在后,且 D 的 sha 作为转换链起点。否则只写「URLSession 交付层」。
- **不声称**拿到了线上 TLS 明文之外的任何"更原始"层。

## 三、因果链:不靠 task ID / 指针相等(审阅#3)
一个事务要串成「闭合」,须同时具备下列**身份与内容版本**,缺一即标「未证」:
1. **session/task 身份**:dataTask 创建点的 `session` 指针 + `task` 指针 + `taskIdentifier` + `request.URL`。
2. **回调身份**:该 task 对应的 **completion block 指针 + invoke 指针**;invoke 命中时的 `NSURLResponse.URL` 必须与创建点 `request.URL` **同接口**。
3. **内容版本链(关键,防地址复用)**:对 `D →(App 转换序列)→ P` 每一步都记 **sha**;串链**以 sha 连续性为准,不以指针相等为准**。即使对象指针相同,也必须 sha 能接上;sha 接不上即「转换未证」。
4. **对象寿命 / 地址复用处理**:对关键对象记录 **retain/release 或 alloc 时刻**(可用 objc runtime 的 retainCount 观察,只读),并要求「同一指针在被观察区间内未经历 dealloc→realloc」;无法确证寿命连续时,**退回到纯 sha 内容链**,并显式标注「指针身份未证、仅内容链」。
5. **分块/复制/转换对象**:若 App 把 D 追加进 NSMutableData 或复制/切片,记录每个中间对象的指针+sha;链上任何一跳缺 sha 对应,即整条标「未证」。
> 判据:**只有 sha 内容链连通 + 回调身份一致 + URL 同接口,才算因果连通;纯 tid/时间/指针相等一律判"未关联"。**

## 四、删除请求 HTTPBody 原文采集(审阅#4)
- **彻底移除** body 原文/原始字节采集(它可能含激活码)。**只记 `HTTPBody.length`**(一个整数),不记内容、不记内容 sha、不落 body 原文。
- 全程**不读取、不输出激活码**;激活码、设备标识、密钥一律不进采集与聊天。

## 五、接受/拒绝走向、缓存写后读——**本次不能验证**(审阅#5)
这两项**当前没有经静态证据确认的观测点**,因此**列为"本次采集不能验证"**,不写成能证明:
- **接受/拒绝分支**:已知 `subs w8,#0x101`(257)在 `0x1005cdca4/ce2cc/d05c4/0x10060b260` 仅是**指令存在**,其输入来自 frame[0x2d74](写者 CFF 未解析);**尚未定位**「从解析字段 → 接受/拒绝分支 → 后续动作」的确切调用点与失败判据。**先决条件**:离线定位该分支的输入写者与两条出口(接受/拒绝)的动作点;未定位前不设观测、不声称可证。
- **缓存写后读**:旧脚本钩 `NSData writeToFile:` 很可能钩错(plist 多走 CFPreferences/NSUserDefaults);**尚未定位**三缓存的确切写/读调用点与对象。**先决条件**:离线定位缓存写入/读回的确切 API 与路径构造点;未定位前列为不能验证。
- 在这两项的观测点被静态坐实之前,采集**不包含**它们,结论里它们保持**开放**。

## 六、安装门控(规格;审阅#6)——超时 + 完整探针清单 + 身份校验 + 失败不恢复
runner(spawn-only)按下述**可验证流程**,全部为 spec,尚未实现:
1. `spawn` 得到**挂起**的 pid(绝不 attach 已运行 App,避免漏早期与半插桩)。
2. 加载脚本;脚本先做**二进制身份校验**:模块名=DGAssistant、`IMG.size` 与预期一致、**逐 parse 站点锚字节**(0x8496AC/0x5D08A8/0x37C868 = `00013fd6`)校验,失配即 `throw`。
3. 脚本按**固定探针清单**逐个安装并计数,最后发 `install-report {expected, installed, failures[]}`(清单见下)。
4. runner **带超时**等待 `install-report`:
   - 若 **超时(如 10s)未收到**、或 `installed≠expected`、或 `failures 非空` → **不 resume**,`dev.kill(pid)`,退出并报错;
   - 仅当 `installed==expected 且 failures==[] 且身份校验通过` → 才 `dev.resume(pid)`。
5. 结束/Ctrl-C/异常 → `script.unload()`+`session.detach()`;本次 spawn 的 pid 一律 `kill`(不留插桩/挂起进程)。
6. **去重**:脚本内全局 Set 记已 hook 的地址/block-invoke,重复则计入 failures(门控即失败)。

**固定探针清单(expected)**:
- `dataTaskWithRequest:completionHandler:`、`dataTaskWithURL:completionHandler:`(请求创建+block 捕获)
- 每个被捕获 completion block 的 invoke(动态数量 → 用「已捕获 block 数==已 hook invoke 数」作一致性校验,而非固定数)
- 三 parse 站点 0x8496AC/0x5D08A8/0x37C868(输入 P;结果在站点+4 的 `str x0` 处单独读,修旧版 onLeave 不可靠)
- App 转换点(ACPDS 解密等,地址待离线定位;**定位前该探针不列入 expected,相关转换链标"未设点"**)

---

## 七、一次运行实际覆盖哪些接口 / 未触发如何报告 / 哪些开放
- **覆盖范围**:仅你本次主动的**一次合法使用**所真正触发的接口。首次激活那次,通常触发 recharged(兑换)+ 可能的 logind0/logind1;「已授权启动」那次通常只有启动复验路径,未必打三接口。**一次运行≠三接口全覆盖。**
- **未触发的接口**:报告里显式写 `interface=<X>: not-triggered-this-run`,**列为本次未覆盖**,不推断、不复用他次数据填充。
- **始终开放(本次不论如何都不能证明)**:失败分支(错码/过期/错设备/解密失败/字段缺失)、data3 空输入、百度省略等价、跨输入/密钥版本/系统构建推广、以及第五节两项(未定位观测点前)。

## 八、这次采集**能**验证的命题(须满足第三节因果判据)
对本次**实际触发**到的每个接口,各至少一个事务:
- P-REQ:请求 URL 末段/host/method + `HTTPBody.length`(仅长度)+ task/taskIdentifier。
- P-RESP:completion 的 `NSURLResponse.URL`(确认同接口)+ HTTP 状态 + `D`(len+sha)。
- P-XFORM:`D →…→ P` 的 sha 转换链(相等=无转换;否则须由已设点的转换序列接上,接不上标"未证")。
- P-PARSE:解析输入 `P`(len+sha)+ 解析结果字段类型(class/length,不取值)。
- **验收**:上述由「回调身份一致 + URL 同接口 + sha 内容链连通 + 对象寿命连续(或退回纯内容链并标注)」连成同一事务,才判该接口本次「关联闭合」;否则判「未关联」。接受/拒绝与缓存**不在本次可证范围**。

## 九、边界与下一步
- 全程只读观测你自己的一次合法使用;不读/不输出激活码、不重新兑换、不改授权、不改响应、不绕校验;raw(仅 D/P/转换中间)落本地 0600,聊天只脱敏摘要+证据路径。
- **不承诺"一次补采=完整 SDK"**:一次运行只闭合本次触发到的事务,其余开放。
- 下一步:请你审本 rev2 spec;**你明确确认后**,我离线定位第五/六节待定观测点(接受拒绝分支、缓存 API、转换点),再给「仅供审查、不执行」的脚本修改稿;**未经你确认不执行任何采集**。
