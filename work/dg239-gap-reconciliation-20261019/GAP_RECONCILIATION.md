# 三接口缺口核对表(只离线;纠正「未采集」误解)

2026-10-19。这轮只做离线核查:没连手机、没启动 DG、没读激活码、没兑换、没改授权、没绕校验。敏感原文只留本地。
复现:`python3 -I evidence/gap.py`(exit 0)。数据底稿:`evidence/gap.result.json`、`evidence/per_interface_obs.json`。

## 先讲清楚一件事
之前文档讲「还没做过合法激活采集/离线已到终点」,**讲错了**。实际上已经做过几轮真实采集了——合法激活(手机显示「充值成功」后 App 自动退出,这是首次激活的正常逻辑)、清剪贴板关掉 DG 后的「已有授权正常启动」进管理主界面、还有 ACPDS 返回/消费者/源槽写入/清理/block 异步交接的局部采集(中间有探针重叠、附加失败这些干扰)。
**所以多数缺口的性质是「已有记录,但缺事务/对象关联」,不是「没采集过」。** 这份表就是把四种缺口分清楚,不混成一句「没采集」。

缺口四分类:① 未记录 ② 记录截断 ③ 尚未找到 ④ 已有记录但缺事务/对象关联。

## 这轮的离线推进点(新)
真实采集里有 **30 条 live JSON-resp 观测**(两次独立运行)。之前的事件账本因为只用「时序/线程」判接口,结果 `endpoint=None`。这轮改用 **caller(parse 站点的返回地址)做静态归属**——这比时序/线程强,因为 caller 直接指明是哪个 parse 站点:
- `0x1008496B0` → logind0 parse(`0x1008496AC`)
- `0x1005D08AC` → logind1 parse(`0x1005D08A8`)
- `0x10037C86C` → recharged parse(`0x10037C868`)

据此归属到的真实 parse 观测(两次运行大小一致,支持归属稳健,但不等于证明):

| 接口 | caller | 真实观测数 | 解析对象 description 大小 |
|---|---|---|---|
| logind0 | 0x1008496B0 | 2 | 4560 / 4560 |
| logind1 | 0x1005D08AC | 2 | 3708 / 3692 |
| recharged | 0x10037C86C | 4 | 1675 ×4 |

> 注意:description 是解析**对象的描述**,不是服务器原始 wire 字节;caller 归属还须确认该 parse 站点是不是**单接口专用**(函数内是否只有该接口路径能到)——这点本轮未证,列入离线下一步。

---

## 逐接口逐环节(环节 / 已有证据 / 缺口分类)

### logind1
| 环节 | 已有证据 | 缺口分类 |
|---|---|---|
| 请求构造 | fixture 请求头+分离 body;历史 URL 与 fixture 目标摘要对应(PROTOCOL_REVIEW §3.1 / interface-matrix) | ④ 已有记录;通用封装与动态字段类型未证 |
| 实际发送 | fixture 头;`send_result_verified=false` | ② 记录截断/未证发送成功 |
| 最终响应 | **2 条真实 parse 观测**(caller 0x1005D08AC,desc 3708/3692,sha 见底稿) | ④ 已有记录但缺事务/对象关联 + description 非 wire 原字节 |
| 解码输入输出 | parse 输入/结果指针、options=1、err=0 已记录 | ④ 输入为 description 级;parse 之后的解码链未绑定 |
| 校验(sign/udid/endtime) | ACPDS/intValue/时间比较局部采集 | ④ 缺同事务绑定 |
| 落盘(缓存) | endtime→tz0111ct setter、ct getter→ACPDS、24B014 事件 | ④ 缺磁盘域/写后读回/同事务绑定 |
| 启动读回 | 已有授权正常启动进主界面(用户确认)+24B014 | ④ 逐校验谓词到入口的同状态可达未证 |

### logind0
| 环节 | 已有证据 | 缺口分类 |
|---|---|---|
| 请求构造 | **完整 2456B 构造正文**(gz `5908d5af…`,事件 `/events/19374/args/1..19384`;body sha `fcf2cbae…`) | ④ 已有记录(构造);通用封装未证 |
| 实际发送 | 该记录请求头 174B、声明 body=2456,但该 socket 缓冲**无正文** | ② 记录截断(缓冲无正文)/未证发送 |
| 最终响应 | **2 条真实 parse 观测**(caller 0x1008496B0,desc 4560×2) | ④ 已有记录但缺关联 + description 非 wire;receive-buffer→parser 桥未闭(见 dg239-logind0-receive-parser-bridge) |
| 解码输入输出 | parse 站点与参数已记录;parser 输入 = `*(alloca scratch frame[0x1160])` | ④ 缺关联;buffer 代次与装填未证 |
| 校验 | 同 logind1(ACPDS 链) | ④ 缺同事务绑定 |
| 落盘 / 启动读回 | 同上(三缓存局部 + 24B014) | ④ 缺磁盘域/读回/同事务 |

### recharged
| 环节 | 已有证据 | 缺口分类 |
|---|---|---|
| 请求构造 | fixture body 374B(gz `946560b2…`,事件 `/events/672,734,1947`);内层 `username,recharge_card`、`data3` | ④ 已有记录(构造);通用变换未证 |
| 实际发送 | fixture 527B(头 153+body 374) | ② 未证发送成功 |
| 最终响应 | **4 条真实 parse 观测**(caller 0x10037C86C,desc 1675×4,跨两运行一致) | ④ 已有记录但缺关联 + description 非 wire |
| 解码输入输出 | parse 输入=`[x29,#-0xD8]`、options=1、err=0 已记录 | ④ 缺关联 |
| 校验 / 落盘 / 启动读回 | 303/304/305/306 为 containsString-on-description(DRAFT §659);缓存链同上 | ④/③ 响应码描述串原字节位置尚未找到;缓存缺同事务绑定 |

---

## 步骤1 结果:三 parse 站点是否单接口专用?(坐实 caller 归属)
见 `evidence/parse_site_single_interface.py`(exit 0)/ `evidence/parse_site_single_interface.result.json`。
- **recharged** `0x10037C868`:落在**自有小函数** `[0x10037c73c, 0x10037ce2c)`,函数内**仅此一个** parse 站点 → caller 归属**稳固**。
- **logind0** `0x1008496AC`:落在 `[0x10080b9cc, 0x10085856c)`,函数内**仅此一个** parse 站点 → caller 归属**稳固**。
- **logind1** `0x1005D08A8`:落在 **`[0x1005bbe48, 0x10060d058)`——即百度 /yz dataTask completion 巨函数**(0x1005bbe48 = 前几轮认定的 completion invoke),该函数内**含 3 个 parse 站点**(logind1 + 两个 other)→ 站点位置精确,但**函数非单接口**;logind1 站点是否单接口可达,仍需该巨函数内 CFF 分派分析(开放)。
- **跨接口发现**:logind1 的响应解析与**百度 completion 同函数共处**。这支持「百度前置与真实授权相关」作为**调查线索**(用户长期直觉),但**不作结论**——co-located ≠ 同事务 ≠ 不可省略。

## ④ 结果:这两份 live 日志有没有 wire 原字节?——没有(记录截断)
查 `dg-correlated-start-once` 里 logind0 parse(124 行/call35/tid19971)与 recharged parse(127 行/call36)前后同线程事件:只有 `JSON-resp`(值是 `{…}` **描述字符串**,长度 4560/1675),相邻的 `call-enter/return`、`FILE-read` 都不带 hex 原字节。
⇒ **这两份 live 日志只保留了「解析后对象 description」,没保留 pre-parse 的 wire 原字节**。所以「最终响应 wire 原字节」在这两份记录里属 **② 记录截断**(探针钩的是 parse 结果描述,不是收到的原始 data)。
含 socket `_recv` hex 原字节的记录(gz 响应 fixture)则全是**合成/MODEL**,不是真实服务器响应。

**步骤3 全局确认(corpus-inventory,193 份文件)**:聚合全部事件类型,**没有任何 `_recv`/socket-recv 原字节事件**;真实采集只记了 `JSON-resp`(描述)、`acpds-enter/return`、`consumer-source/retained/after`、`BODY`(请求侧 setHTTPBody,空)、`FILE-read`(缓存)、`AESdec` 等——**全库都没有钩「收到的原始网络响应字节」**。唯一带 raw socket recv 的是 gz 里的 **modeled** socket_effects(账本标注非 live)。
⇒ **「三接口最终响应的 wire 原字节」在全部既有记录里确实不存在,性质=② 记录截断**(真实运行时探针钩的是解析结果/ACPDS/消费者,没钩 raw received data)。
⇒ 这项无法从既有记录离线恢复;**唯一补法**=将来获授权时做**针对性最小补采**:只在三 parse 站点的**输入对象**加落 raw 字节 + 连接身份(不是笼统再激活)。历史采集不够的原因就在此:它们钩在解析后与消费侧,漏了 pre-parse 的原始响应字节。

## 步骤2 结果:跨运行 description 比对(支持真实性)
见 `evidence/step2_logind1.py`(exit 0)。同接口 description **大小稳定、SHA 各异**:logind0(2 次运行,size 4560,2 个不同 SHA)、recharged(4 次调用,size 1675,4 个不同 SHA)、logind1(size 3692/3708,2 个不同 SHA)。
⇒ 各次响应**内容不同**(非固定 fixture 回放)→ 支持这些是**真实逐事务响应**;缺口纯粹是 wire 原字节/关联,**不是真实性**。但 description 仍非 wire 原字节。

## logind1 站点细化
百度 completion 巨函数内 3 个 parse 站点用**各自不同的输入帧槽**:logind1=`frame[0x3768]`、otherA=`frame[0x32d0]`、otherB=`frame[0x3400]`。
⇒ logind1 站点是**独立解析操作**;其「单接口可达」归结为「谁填 `frame[0x3768]`」——与 logind0 的 receive→parser 桥同类缺口(开放)。

## 三个被点名离线项的终点(本轮逐一做到底)
1. **logind1 `frame[0x3768]` 写者**(已做):单写者 `0x1005c9d18`,**VLA/alloca 模式**(`subs x0,x11,x12; mov sp,x0; str x0,[x19,#0x3768]`),12 readers。⇒ logind1 parser 输入 = `*(alloca scratch)`,与 logind0 `frame[0x1160]` **同构**;实际 NSData 填充=同一 receive→parser 桥(开放,需 wire 原字节绑定)。**三接口的 parser-输入桥至此统一**。见 `evidence/step2_logind1.py`。
2. **data3 空输入**(终点,引 PROTOCOL_REVIEW §4 + `dg239-logind0-receive-parser-bridge-20261019/evidence/v3`):短臂比的是**密钥对象长度**(门 `0x1003C38D8`)非正文长度;data3 函数内 **0 个 cbz/cbnz**,空输入走向经 CFF 分派未闭;局部算术≠整函数返回测试。⇒ **空正文/空key/key长1/nil/空字典 的最终返回离线未证**,不能实现为「一律返回空串」。性质=④(有局部字节,缺整函数可达)。
3. **缓存磁盘域**(终点,引 PROTOCOL_REVIEW §6):已有 server endtime→加密→tz0111ct setter、ct getter→ACPDS→signed32 intValue→double→时间比较、24B014 事件存在。⇒ **三缓存准确磁盘域/完整序列化/写后读回/失败回退、以及 sign·udid·endtime 接受拒绝链 的同次状态绑定离线未证**。性质=④(有局部,缺同事务绑定)。tz0111endtime 展示值/文件存在/非 nil/code=257 都不单独授予权限。

## 能否先离线补(不急着再采集)
- **能离线推进**:① caller 静态归属(本轮已做);② 确认三 parse 站点是否单接口专用(反汇编函数可达性)——下一步;③ 用 `description_sha256` 跨两次运行比对、与 request body 关联;④ 在 corpus 里找**是否有保留 wire 原字节(而非 description)的采集字段**——若有,最终响应就能从既有记录闭合,不需新采集。
- **可能确实缺的**(确认后才谈补采,且针对具体缺口、解释历史为何不够):若全库采集都只留了 description、没留 wire 原字节,那「wire JSON 标量类型」这一项就是「记录截断」;要补就只补「在同一次运行里,对这三个 parse 站点的输入对象额外落 raw 字节+连接身份」——而不是笼统再激活一次(一次运行未必触发三接口、也不证失败分支/data3 空输入/百度等价)。

## 边界
这轮把缺口按四类分清、并用 caller 把真实 parse 观测归属到三接口(离线推进);**没有**宣称响应解码闭合、同事务绑定成立或兼容可交付。冻结包、共享报告、启动契约都没动。下一步按上面「能离线补」的 ②③④ 继续离线,不新增采集。
