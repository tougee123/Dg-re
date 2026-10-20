# DGAssistant 动态分析 Frida 脚本实战指南（给 AI/协作者）

> 目标:在越狱 iOS 设备上对 `apple.allIDTDG`(DGAssistant)做动态分析,抓激活协议/AES 密钥/字符串/文件操作。
> 本指南自洽:照做即可复现。**先读 §1 环境前置和 §2 铁律**——不满足这两条,任何脚本都会秒退或抓不到东西。

---

## 1. 环境前置（硬要求,缺一不可）

1. **设备**:越狱 iOS(本项目是 arm64e / Dopamine·roothide),装了 DGAssistant(bundle `apple.allIDTDG`,经 TrollStore)。
2. **frida-server** 跑在设备上,**端口 18923**(非默认 27042,是改过的)。
3. **设备必须解锁**(屏幕解锁态)才能 `spawn`,否则报 "device not unlocked / Unable to launch"。
4. **roothide 管理器里给 `apple.allIDTDG` 拉黑(关闭注入)** —— 否则 roothide 的 `libinjector.dylib`/`filter_dylib` 会在启动 init 阶段 `abort_with_payload` 掉 frida-agent,脚本根本加载不了。**这是能让 frida 进去的前提。**
5. **主机**:macOS,`pip install frida==17.15.3`,Node + `frida-compile` + `frida-objc-bridge`(`package.json` 已有 `frida-objc-bridge ^8.0.6`)。
6. **设备 IP 会变**,每次用前确认(本项目见过 `192.168.3.104` / `172.18.2.154`);端口 18923 固定。

## 2. 铁律（反 frida 规避,违反必秒退）

该 App 启动时跑一个**后台完整性/反篡改块 + 运行时反 frida**(检测到就 `abort_with_payload`,非 libc exit)。规避规则:

- ✅ **只钩框架/libc 的导出和 ObjC IMP**(NSURL/NSUserDefaults/NSData/UIKit、`connect`/`ptrace`/`getenv`)。这些在 dyld 共享缓存里,App 的自哈希看不见。
- ❌ **绝不 patch app 自身 `__text`**(即不要 `Interceptor.attach` 到 `DGAssistant` 模块内的地址,也不要 hook `-[ViewController ...]` 等 app 自己的方法)——会被完整性哈希抓到,**秒退**。
- ❌ **这几个"检测点"方法不要钩**(实测钩任一即秒退):`-[NSUserDefaults objectForKey:]`、`-[UIPasteboard string]`、`UIAlertController`、libc `exit`/`abort`(只读 backtrace 都不行)。
- ✅ **安全集**(实测存活):`connect`、`ptrace`(replace 返 0)、`getenv`(过滤 DYLD/FRIDA)、`+[NSURL URLWithString:]`、`-[NSMutableURLRequest setHTTPBody:/setAllHTTPHeaderFields:]`、`+[NSJSONSerialization dataWithJSONObject:/JSONObjectWithData:]`、`-[NSUserDefaults setObject:forKey:]`(**只 set 不 get**)、`-[NSData AES128DecryptWithKey:iv:/AES128Operation:key:iv:]`、`-[* ACPDS:kaiv:]`(ApiResolver 单次)、`-[UITableView reloadData]`。
- ✅ **纯只读内存扫描安全**(不 hook 任何方法,只 `Memory.read`)——但见 §6 的 PAC / Module.size 坑。
- 启动期反 frida 有**概率性**:有时干净启动、有时秒退。**秒退就直接重试**同一命令 1-3 次。
- CLAUDE.md 规则:**不要用 `--no-pause`**;runner 用 `dev.spawn` + `dev.resume`,`-f` spawn 会自动 resume。

## 3. 编译与运行

### 3.1 编译(必须,Frida 17 移除了 ObjC 全局)
每个 `*.js` 源要先编译成 `*.compiled.js`(把 `frida-objc-bridge` 打包进去):
```bash
cd "/Users/tougee/Downloads/DG 管理器"
npx frida-compile frida_xxx.js -o frida_xxx.compiled.js
# 或 ./node_modules/.bin/frida-compile ...
```
源码里必须 `import ObjC from 'frida-objc-bridge';`(Frida 17 没有全局 `ObjC`)。

### 3.2 通用 runner（推荐）
`frida_gate_run.py` —— spawn 模式,参数化 IP/脚本/时长:
```bash
python3 frida_gate_run.py <设备IP>[:端口] [脚本.compiled.js] [时长秒]
# 端口默认 18923;脚本默认 frida_gate.compiled.js;时长默认 3600
# 例:
python3 frida_gate_run.py 192.168.3.104 frida_light2.compiled.js 40
```
它做的事:`add_remote_device(ip:port)` → `spawn([bundle])` → `attach` → `create_script` → `load` → `resume` → 循环收 `send()` 消息打印(`[标签] 内容`),直到时长到或 Ctrl+C。脚本里 `send('[tag] msg')` 的输出会实时打到终端。

### 3.3 脚本内收发约定
- 脚本用 `send('[TAG] ...')` 往主机发日志;runner 按 `时:分:秒 [TAG] 内容` 打印。
- `[SCRIPT-ERROR]`/`[DETACHED] process-terminated` = 脚本报错 / App 被反 frida 干掉(秒退)。
- `[hb]`/`[tick]` = 心跳,证明还活着。

## 4. 关键脚本（按用途,只列有用的最终版)

> 这些是经过多轮迭代后**能存活且有产出**的。源码都在项目根目录,改了要重新 `frida-compile`。

### 4.1 网络/激活协议 + AES 密钥 —— `frida_light.js`
钩安全集,抓:`CONNECT <真实IP>`、`URL`、`BODY`(请求体)、`HDR`、`JSON-req`(请求 JSON)、`JSON-resp`(响应 JSON)、`UDEF`(写 NSUserDefaults 的 license)、`AESdec`(`key=... -> 明文`,**运行时 AES 密钥就从这里抓**)、`ACPDS`。
```bash
python3 frida_gate_run.py <IP> frida_light.compiled.js 30
```
看点:`[CONNECT] 154.222.16.171`(真实服务器)、`[AESdec] key=DrT8h0Fj70l522Ri -> {license JSON}`、`[UDEF] tz0111endtime = ...`。

### 4.2 渲染门控边 + 安全基线 —— `frida_light2.js`
= frida_light 安全集 + **只加 `-[UITableView reloadData]` 回溯**(`dgbt` 把栈里 DGAssistant 帧映射成 `DG:0x<静态VA>`)。用来定位"激活通过→渲染主界面"那条边。
```bash
python3 frida_gate_run.py <IP> frida_light2.compiled.js 40
```
看点:`[RENDER] reloadData app-caller: DG:0x1003cfa44 <- DG:0x1002ca5c0`(= `sub_1003CF990` ← `sub_1002C6FAC`)。

### 4.3 全量字符串只读 dump —— `frida_dumpstr.js`
**不 hook 任何方法**,纯扫描 `__data` 里加密串类对象(flags `0x7c8`),读已解密的 dataptr,输出 `CJK`(中文)/`STR`(ASCII)。安全。
```bash
python3 frida_gate_run.py <IP> frida_dumpstr.compiled.js 35
```
坑(见 §6):dataptr 上界不能用 `Module.size`(只报 __TEXT),要用 `base+0x1700000`;按 flags `0x7c8`(+8 偏移)匹配,**别**按 isa(arm64e PAC)。

### 4.4 快速抓瞬时中文(失败路径错误串)—— `frida_dumperr.js`
只扫高 `__data`、每 0.5s 一次、只记 ≥2 个中文字的串。配合 §4.6 触发失败路径用。

### 4.5 诊断对象布局 —— `frida_probe.js`
读几个已知对象结构(如 URL 对象 `0x10154A3E0`),打印 base/size/32 字节/flags/dptr/len/明文。**定位扫描失效时先跑这个**(确认 slide/flags/PAC)。

### 4.6 逼服务器拒绝 + 抓错误串 —— `frida_forceerr.js`
在 `+[NSJSONSerialization dataWithJSONObject:]` 把请求 dict 里 `machine_code/username/password` 改成假值(格式对但没注册)→ 服务器回 `code=601/606` → 走失败路径;同时拦 `exit/abort`(sleep 住,进程不死)+ 全 `__data` 扫中文。
```bash
python3 frida_gate_run.py <IP> frida_forceerr.compiled.js 40
```
看点:`[SPOOF]`→`[REQ](ffff…)`→`[RESP] code=606`→`[EXITHOLD]`→`[CJK]`。注意:绑定设备上 machine_code 路径只到 `606→退出`,**不弹**"兑换码错误"UI(那条在手动兑换流程)——所以这些错误串最终是**静态**(`dg_decrypt_all.py`)解出来的,不是动态。

### 4.7 清理功能文件操作追踪 —— `frida_cleanup.js`
钩 `NSFileManager removeItem/contentsOfDirectory`、`NSData/NSDictionary writeToFile`、native `unlink/rename/rmdir`、`sqlite3_*`、`SecItemDelete`、`cleanFolderAtURL:`、`posix_spawn`(argv 在 index 4)。点击 App 的清理功能时跑,看实际删/改路径。

### 4.8 隐藏/恢复观察 —— `frida_hidewatch.js` / `frida_findbackup2.js` / `frida_readplist.js`
- `frida_hidewatch.js`:钩 `posix_spawn` 记隐藏/恢复命令 argv,并在操作后 dump 越狱 App 的 Info.plist 状态(bundleID/URL schemes)。
- `frida_readplist.js`:延迟(`setTimeout` 3s,**启动即读会崩**)读已装 JB App 的 Info.plist。
- `frida_findbackup2.js`:搜容器找备份文件。⚠️注意它**跳过 `.app` 目录**(`if(!/\.app$/.test(nm))`),而真正的 `Info.plist.bak` 恰在 `.app` 里——这是当初漏掉的坑。

### 4.9 父进程 spawn 上下文 —— `frida_parentenv.js` + `frida_childspawn.py`
`frida_parentenv.js` 钩 `posix_spawn` dump 父进程给 root 子进程的完整 argv+envp+file_actions+attr。`frida_childspawn.py` 直接 spawn 子进程(但子进程缺父进程的 spawnattr 会被 jetsam 秒杀,仅供参考)。

### 4.10 AES 密钥捕获 —— `frida_keygen.js`（及 keygen2..13 是迭代)
专门钩 AES/CCCrypt 层 dump `key/iv/明文/密文`。`frida_keygen.js` 是基础版;`keygen2`~`keygen13` 是不同抓法迭代(抓齐 9 个运行时 key 的过程)。要最新最全的用编号最大的那个源码参考。

## 5. 典型工作流（复现激活协议抓取)

```
1. 设备解锁 + frida-server:18923 跑着 + roothide 里 apple.allIDTDG 已拉黑
2. 确认当前设备 IP
3. 编译脚本:  npx frida-compile frida_light.js -o frida_light.compiled.js
4. 跑:        python3 frida_gate_run.py <IP> frida_light.compiled.js 30
   → 秒退就重试 2-3 次(启动期反 frida 概率性)
5. 读输出:    [CONNECT] 真实IP / [JSON-req][JSON-resp] 协议 / [AESdec] 运行时密钥 / [UDEF] 本地落地
验证:    [AESdec] key=DrT8h0Fj70l522Ri -> {"state":"正常",...} 即抓到一次完整激活
```

## 6. 血泪坑速查（AI 必读）

| 现象 | 原因 | 解法 |
|---|---|---|
| init 后 ~1s 秒退、无 EXIT 日志 | 反 frida(abort_with_payload)或 roothide 注入拦截 | 确认 roothide 拉黑了该 App;只用安全集;重试几次(概率性) |
| 钩了方法就秒退 | 钩到检测点(objectForKey:/UIPasteboard/exit/abort)或 patch 了 app __text | 换只读/安全集框架 hook;别碰 app 自身方法 |
| 内存扫描 0 命中(isa 匹配) | arm64e 的 isa 带 **PAC 签名位**,`equals(class_ptr)` 不中 | 改按 flags 字段(对象 +8 == `0x7c8`)匹配 |
| dataptr 被判越界、扫不到 | `Module.size` 只报 __TEXT(~0xc1c000),非完整 ~23MB 镜像 | 指针上界用 `base + 0x1700000` |
| `ObjC is not defined` | Frida 17 移除全局 ObjC | 源码 `import ObjC from 'frida-objc-bridge'` + frida-compile |
| `Module.findExportByName not a function` | Frida 17 改了 API | 用 `Module.findGlobalExportByName` |
| 栈回溯 fp 取错 | arm64 帧指针是 `this.context.fp`(非 x29) | 用 `this.context.fp` |
| 子进程 spawn 秒杀 | 缺父进程 posix_spawnattr(persona/proc-type) | 不能独立 spawn root 子进程;只能钩父进程的 posix_spawn |
| `posix_spawn` argv 读成 `["\x02"]` | argv 是第 5 个参数(index 4),不是 index 3 | `a[4]` 读 argv |
| 中文串动态扫不到 | 错误串只在**手动兑换失败**路径解密,绑定设备触发不到 | 用静态 `dg_decrypt_all.py` 全量解 |

## 7. 文件清单(frida 相关)
- 通用 runner:`frida_gate_run.py <ip> <script> <sec>`;旧版硬编码:`frida_run.py`。
- 网络/密钥:`frida_light.js`、`frida_keygen*.js`。
- 渲染边:`frida_light2.js`。
- 字符串:`frida_dumpstr.js`(全量只读)、`frida_dumperr.js`(快中文)、`frida_probe.js`(诊断)。
- 失败路径:`frida_forceerr.js`。
- 清理:`frida_cleanup.js`。
- 隐藏:`frida_hidewatch.js`、`frida_findbackup2.js`、`frida_readplist.js`、`frida_bakcheck.js`。
- spawn:`frida_parentenv.js`、`frida_childspawn.py`。
- 每个 `.js` 对应一个 `.compiled.js`(编译产物),跑的是 `.compiled.js`。

> 配套静态侧:`dg_decrypt_all.py`(Unicorn 全量串解密)、`uni_decrypt2.py`(单串)、`macho.py`(段表)。动态抓不到的(每串 MBA、谓词全局量)全靠静态。
