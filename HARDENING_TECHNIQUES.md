# DGAssistant 加固手法拆解（用于给自己的 App 做加固）

> 目的：这个 App 的加固确实做得比较全，逐层拆解"它怎么做的 + 你怎么复刻 + 哪些是坑（别学）"。
> 我在分析中把每一层都攻破了，所以下面既讲"强在哪"也讲"弱在哪"。

## 加固层（从强到弱排序）

### ① 控制流平坦化 CFF + MBA 不透明谓词  ★★★★★（最有效）
- 每个函数被打散成 dispatcher（`BR X8/X9/X10` + 派发表），用 MBA（混合布尔算术）不透明谓词算索引。
- 谓词用全局变量（如 dword_100C50260…）做 `ORR/EOR/MADD/BIC/CSET` 恒等式，结果恒为常数索引。
- **效果**：IDA/Hex-Rays 反编译出 goto 汤，静态分析极慢；这是它最值钱的一层。
- **复刻**：用 OLLVM / Hikari / 商业壳（如 Ipa Guard、几款国产壳）的 fla + bcf + sub。
- **它的弱点**：谓词全局变量是**固定常数**，Unicorn 模拟（预置这些全局值）能跟着 `br` 走，完整还原。
  → 加固时谓词应依赖**运行时/输入相关**的值，别用固定常量。

### ② 字符串加密（双层）  ★★★★
- **逐字节 XOR/MBA（就地解密）**：CFString 自引用布局（结构体在 V，明文缓冲 str_ptr=V-0x20，密钥表=V-0x40），
  每字节一套 MBA 变换。**它的弱点**：所有 MBA 变换都可化简为单字节 XOR，模拟一跑就出。
- **AES-128-CBC（key==iv）**：`Base64 → AES128Decrypt(key,iv=key) → UTF8`，敏感串走这层。
- **复刻**：字符串加密是标配；但**别用 key==iv**、**别把 AES 密钥硬编码在二进制里**（见弱点）。

### ③ 动态 API 解析（隐藏敏感调用）  ★★★★
- CommonCrypto/CCCrypt、部分 syscall **不出现在导入表**，用 `dlsym` + **XOR 解密的函数名**运行时解析。
- **效果**：静态看不到 `CCCrypt`/crypto 调用，增加分析难度。**很值得学。**

### ④ 反调试 / 反注入  ★★★★
- `ptrace(PT_DENY_ATTACH)`、`sysctl` 查 `P_TRACED`（还有**裸 svc 系统调用变体**绕过 libc hook）。
- 反 frida：枚举已加载 dylib + **枚举全部 ObjC 类/方法**找注入痕迹，命中就 `abort_with_payload`。
- 越狱环境联动：借 roothide 的 `libinjector.dylib`/`filter_dylib` + `jbclient_trust_library` 在启动 init 阶段
  检测 frida-agent 注入并 abort（这层最难绕，我最后靠"在 roothide 里拉黑该 App"才让 frida 跟上）。
- **复刻**：ptrace+sysctl+裸 svc 是基础；ObjC 类枚举查 hook 很实用；
  但**别只依赖越狱注入器的检测**（换个注入方式/关掉注入就废）。

### ⑤ 网络地址伪装（诱饵域名 + 设备侧 DNS 劫持）  ★★★★（思路巧）
- 二进制里**硬编码 `https://www.baidu.com/yz`** 当诱饵，静态分析只能看到 baidu。
- **真实服务器 `154.222.16.171`（香港 VPS）不在二进制里** —— 靠**设备的 DNS/hosts 把 www.baidu.com 劫持过去**。
- **效果**：逆向者静态永远找不到真实地址。**很聪明。**
- **它的弱点**：设备上 `connect()`/`getaddrinfo` 一 hook 就看到真实目标 IP（动态一抓就穿）。

### ⑥ 隐蔽持久化（伪装成 Apple 系统文件）  ★★★
- 授权存 `NSUserDefaults` 的 `com.apple.a676924c9f0.plist`（伪装成苹果系统偏好）。
- 落地文件伪装：`com.apple.ayzuid%@.png`、`com.apple.a%@%@.plist`。
- **复刻**：混淆存储名/位置有一定效果；但用户/取证一 dump plist 就现形。

### ⑦ 防篡改 + 二段式授权  ★★★
- 完整性/环境校验失败 → 解密串 `"Fatal error, exiting app"` 直接退出（~40 处 gate）。
- 授权二段式：服务器验证 → 存本地授权 → **必须重启一次**读本地授权才进真实页面（降低被 hook 一次拿全流程的概率）。

---

## ⚠️ 反面教材（这些别学，是它的致命弱点）

1. **内嵌 RSA-1024 私钥（明文 base64 在 __cstring）** —— 灾难级。客户端里放私钥 = 直接被提取，
   可解密/伪造一切。正确做法：客户端只放**公钥**做验签/pin，服务端持私钥；且 RSA 至少 2048，优先 ECC。
2. **AES 密钥硬编码在二进制**（找到 7 个）—— 可提取，加密形同虚设。密钥应服务器下发/设备绑定派生。
3. **XOR/MBA 串加密可化简为单字节 XOR** —— 用 Unicorn 模拟批量还原。加密要真正引入运行时依赖。
4. **CFF 谓词用固定全局常量** —— 模拟器能跟。谓词要绑运行时状态。
5. **真实地址靠设备 DNS 劫持** —— 动态抓包（connect/DNS hook）一穿。敏感 host 应服务端动态下发 + 证书 pinning。
6. **反 frida 依赖越狱注入器（roothide filter_dylib）** —— 在越狱管理器里给 App 关注入即绕过。
   自检应在 App 自身（校验自身代码段哈希、检测 Interceptor trampoline、inline hook 检测）。

## 给你的 App 加固的建议优先级
1. 商业壳/OLLVM 做 CFF+字符串加密（性价比最高）
2. 证书 pinning + 服务端下发密钥/host（别硬编码）
3. 自身完整性校验（代码段哈希）+ inline-hook 检测（查函数头是否被改）
4. 反调试 ptrace+sysctl+裸 svc；反注入用 ObjC 类枚举/dyld 镜像校验（但要在 App 自身做，别依赖越狱环境）
5. 敏感逻辑上服务端（客户端只做展示），客户端拿不到的东西才是真安全
