# DGAssistant 验证协议 —— 完整深度拆解（动态抓取）

> 用有效激活的设备、极简 frida hook（不惊动运行时反调试）抓到的完整验证流程。
> 真实服务器 `154.222.16.171`（www.baidu.com 被设备 DNS 劫持过去），POST，JSON。

## 一、整体流程

```
启动 → 采集设备信息(MobileGestalt: ProductType/Version…) → CC_MD5 算设备指纹
     → machine_code = md5(设备信息) + "-520-22"
     → 组 JSON 请求，AES 加密请求体 → POST 154.222.16.171
     → 收 AES 加密响应 → 解密得 license JSON
     → 取 endtime → 存 NSUserDefaults「tz0111endtime」(伪装 plist)
     → 二次启动读 tz0111endtime 与当前时间比 → 放行/拒绝
```

## 二、请求（多个，握手式）

```json
// 设备指纹认证请求
{ "machine_code":"6d56b4abd06429e7d364b95185d4fb4f-520-22",
  "machine_codee":5426174, "machine_codeee":1785029818,
  "machine_codeeee":4478985216705214, "machine_codeeeee":10852446,
  "username":"…同 machine_code…", "password":"…同 machine_code…" }
// 带 nonce 的加密请求
{ "code":9816549494765052, "data":"eGEWJTQ5RClEJyYlEBUiKQ==" }   // data = AES 密文
// 大块加密请求
{ "data25":"<很长的 hex 密文>" }
```
- `machine_code` = **MD5(设备信息) + "-520-22"**（-520 产品号，-22 版本）
- `username == password == machine_code` —— 纯设备指纹当账号密码（无盐无独立密码）
- `code` = 每次请求的 nonce/时间戳；`data`/`data25` = AES 加密的实际载荷

## 三、响应（AES 加密的 JSON）

服务器返回的 `data`(hex)/`code2`/`data5` 都是密文；App 用 **`AES128DecryptWithKey:iv:`** 解密得到明文 license：

```json
{ "state":"正常",                // 激活状态（未激活时 code:606）
  "endtime":"1785115894",        // 授权到期 = 2026-07-27 09:31:34（关键！）
  "sign":1803563601,             // 签名/校验
  "udid":"6d56b4abd06429e7d364b95185d4fb4f-520-22",
  "stt":1785029819, "ss":"9266891", "ss5":18534039, "sss":"…","ssss":…,
  "token":"98", "tk":"1", "point":"0", "gg":"",   // gg=公告
  "data":"MDU2NTYxODMwNTAzNDU2Mw==",   // base64 -> "0565618305034563"（订单/序列号）
  "data2":"umRlagAAAAD…",  "data3":2, "data4":"umRlagAAAAD…" }  // 嵌套的二次 AES 密文
```

## 四、加密体系（关键，加固重点）

**多层 + 运行时密钥**，这也是为什么静态提取的 7 个 AES key 解不开响应：
- 传输层：整个请求/响应体 AES 加密（CBC，key==iv）
- license 层：响应 JSON 本身也是 AES 密文，用 **`AES128DecryptWithKey:iv:`** 解
- 字段层：`data2`/`data4` 再套一层 AES（每字段独立），头部 `ba 64 65 6a 00 00 00 00` 是自定义封装
- **运行时 AES 密钥是 16 位可打印 ASCII，且分用途**（动态抓到的）：
  - `DrT8h0Fj70l522Ri` —— 解主 license JSON
  - `ICmCIVMIKNQfFXuT` —— 解 machine_code
  - `W8emAZDGdcysx4R6` —— 解 ss 等编号
  - `X4Q97SvE2da9FaMA` —— 解时间戳(stt/endtime)
  → 这些**不是**二进制里硬编码的 7 个 key，是运行时/服务器相关派生的 → **静态逆向拿不到**（这点做得好）

## 五、本地落地（伪装持久化）

抓到 App 写本地授权：
```
[UDEF] tz0111endtime = 2026-07-27 09:31:34   // = endtime 1785115894，NSDate
[UDEF] ntt = 0
```
- 存在 **`/var/mobile/Library/Caches/com.apple.a676924c9f0.plist`**（NSUserDefaults suite，伪装成苹果系统偏好）
- 二次启动读 `tz0111endtime` 与当前时间比较 → 决定是否进主界面

## 六、这套设计的加固评价（给你参考）

**做得好的**：
1. 传输/license/字段 **三层 AES**，且**关键密钥运行时派生**（静态逆向拿不到明文授权）
2. 真实 host 靠**设备 DNS 劫持 + baidu 诱饵**，二进制里查不到
3. 授权绑设备指纹，卡密服务端核销
4. 本地授权**伪装成 com.apple.* 系统偏好**，路径隐蔽
5. 运行时反 frida（检测到就黑屏优雅退出，不崩溃）

**弱点（别学）**：
1. machine_code = MD5(可读设备信息)，**可预测/可伪造**，无盐
2. username=password=machine_code，**无质询-响应/无请求签名**，易重放
3. 授权最终落地成**明文 NSDate `tz0111endtime`** —— 直接改这个 plist 值即可本地续期（本地校验太轻）
4. 运行时反 frida 只是"检测到就退"，**极简 hook（不触发它检测点）就能跟**（本次就是这么抓到的）
5. endtime 是纯时间戳、本地比对 —— 应加**服务端定期回连 + 授权签名验签**，别只信本地时间

## 七、给你自己 App 的加固建议（基于以上）
- 传输/授权多层加密 + **密钥运行时协商**（照抄这个思路，别硬编码）
- 请求加**质询-响应 + HMAC 签名 + 时间窗**，防重放
- 本地授权别落明文时间戳；用**服务端签名的授权 token + 定期回连**，本地只做展示
- 反调试/反注入要**在 App 自身**做（校验代码段、检测 inline hook），别只靠"检测到就退"
