# logind0 接收对象 → parser 因果桥(接手第一轮 P0)

2026-10-19 接手执行。离线只读:仅本地样本原字节 + 既有记录 + 离线 chained-fixup 绑定;未连手机/服务器/Frida,未启动 DG,未改 IDB/授权。样本 SHA `3841f080…e5cf78`。地址为未滑移 VA,按 Mach-O 段映射读取。敏感正文不输出。复现:`python3 -I evidence/bridge.py`(exit 0)。

## 结论(一句话,已诚实校正)
原字节已定位:logind0 的 parser 输入 `x2 = *(alloca scratch frame[0x1160])`;该 scratch 的一枚**候选内容写**(0x100834BEC)放入的是一枚**新 `objc_alloc` 的 NSMutableData**(类经离线 chained-fixup 绑定确认)。但 **buffer 代次、该实例是否被响应字节装填、同事务接收绑定三者离线未闭合** ⇒ **不能断定 parser 读到的就是已装填响应的接收累积对象**。实质推进=把这条桥的结构、候选对象类型与**为何离线不能闭合**精确定位到位(与 handoff 告警一致),而非虚构闭合。

> 校正说明:上一版曾把帧槽链表述为「parser 输入对象 = NSMutableData 接收累积缓冲」,过度断言。实测 frame[0x6f8] 在外层函数仅 2 处访问(alloc 写 + bridge 读)、**无 appendData/无 ivar-store**,且 `frame[0x1160]` 是有 3 个地址写者的 alloca scratch ⇒ 该候选对象是否被响应字节装填、以及 parser 是否恰好读到该代次,离线均未证。本节以校正为准。

## 一、已证边(原字节 + 离线绑定,见 `evidence/bridge.result.json`)

外层函数 `0x10080B9CC`;JSON 解析调用 `0x1008496AC`。

| 边 | 原字节 | 含义 |
|---|---|---|
| parse 站点 | `0x100849694 ldr x9,[x19,#0x1160]` / `0x1008496A0 ldr x2,[x9]` / `x3=1` / `x4=0` / `0x1008496AC blr x8` / `→str [x19,#0xf78]` | parser 输入 `x2 = *(frame[0x1160] 缓冲)`;options=1,error=NULL;结果存 frame+0xf78 |
| buffer 内容写 | `0x100834BE8 ldr x0,[x19,#0x1158]` / `0x100834BE4 ldr x9,[x19,#0x1160]` / `0x100834BEC str x0,[x9]` | `*(buffer) = frame[0x1158]` |
| frame[0x1158] | **单写者** `0x100841FF8`;`0x100841FF0 ldr x0,[x19,#0x6f8]` / `0x100841FF4 bl 0x1008965C8`(retain 包装, 体内 `blr *(0x100b942b8)`) / `str [x19,#0x1158]` / `0x100841FFC b 0x100834BE0` | `frame[0x1158] = retain(frame[0x6f8])`,随后**直接分支**到 buffer 写块 ⇒ 写序已证 |
| 分配 | `0x100842618 ldr x0,[x19,#0x9f0]` / `0x10084261C bl 0x100AE00A8`(=`_objc_alloc`) / `str [x19,#0x6f8]` | `frame[0x6f8] = objc_alloc(frame[0x9f0])` |
| 累积类 | classref `*(0x100bc28f8)`;离线 chained-fixup 绑定 = **`_OBJC_CLASS_$_NSMutableData`** | 累积对象类型 = NSMutableData |

**帧槽生命周期(全链)**:
`frame[0x9f0]=NSMutableData 类` → `frame[0x6f8]=objc_alloc(类)` → `(retain 0x1008965C8)` `frame[0x1158]` → `*(buffer frame[0x1160])`@0x100834BEC → `parser x2`@0x1008496A0。

**负测试**:改 `0x100834BE8` 读取指令 imm 字节 ⇒ 目的槽号改变(识别来自字节);frame[0x1158] 单写者计数实测 =1。

> 说明:NSMutableData + 后续 `appendData:`/`appendBytes:length:`(两选择子字符串均在,fileoff 0xb11ae7 / 0xb11ad3)是 URLSession `didReceiveData:` 累积接收数据的标准形态——因此**实际接收字节经对象指针 append 进入,不出现在帧槽拷贝链里**,这解释了为何“构造正文记录里 socket 缓冲无正文”。

## 二、明确未闭合边(精确到位置/缺什么)

1. **appendData 源 → 本实例绑定**(离线已推进,边界明确):`appendData:` selref `0x100bc25c0`、`appendBytes:length:` selref `0x100bc1aa8` 的代码 xref **全部在 logind0 外层函数(0x10080B9CC..)之外**——appendData 在 `0x100386e3c / 0x10038d644 / 0x100391994 / 0x100394004`,appendBytes 在 `0x1000bdf6c / 0x1000bf158 / 0x10038ed50 / 0x1003917ec / 0x100393754 / 0x1003c75ac / 0x1003cfa40`。⇒ **累积写发生在独立函数(didReceiveData: 类委托),NSMutableData 经对象字段(ivar/属性)跨函数共享,不经本函数帧槽**。闭合需把 alloc 实例(frame[0x6f8])存入的 ivar 与委托 append 的 receiver ivar 对齐——跨函数 + CFF 别名,离线难闭合;最小动态三点观测可直接绑定(见下)。
2. **buffer 代次**:`frame[0x1160]` 有 **3 个写者**(`0x10080D0C0` / `0x100810F24` / `0x10084D8B8` alloca)。parse 读取的 buffer 代次与内容写(0x100834BEC)代次在 `br x8` 分派下**未证相等**。frame[0x1158] 单写者使**对象身份稳定**,但 buffer 代次本身未闭合。
3. **同事务接收绑定**:该 NSMutableData 累积的是 logind0 **服务器响应**(而非请求回显/他连接),需把 append 源绑定到 logind0 连接的 `didReceiveData:` 接收回调(连接代次/事务身份)——即 handoff 的接收登记(选项 10001/20011)核心开放边。

(上述与 handoff §六.B 的告警一致:frame+0x1160 存的是分配栈地址而非响应正文写;登记保存对象值而非响应 cell 地址;`0x100850BE8 CSET LS` 非恒定分支——本轮未依赖该常量化。)

## 三、最小补证方案(先离线,动态需用户授权)

- **离线可做(无需授权)**:
  (a) 对 `appendData:`/`appendBytes:length:` 两 selref 做 xref,筛出 receiver 可追到 frame[0x6f8]/该 NSMutableData 的调用点,尝试闭合边1;
  (b) 解析 `frame[0x1160]` 三写者的 CFF 分派前驱,判断 parse 块与内容写块是否同一分派代次,收窄边2。
- **最小动态(需用户明确授权,属 §二 新增采集)**:在**一次合法运行**中,仅在 `0x100841FF8`(frame[0x1158] 写)、`0x100834BEC`(buffer 写)、`0x1008496A0`(parser 读)三点各记录**对象指针值 + 其 class + length + 首字节哈希**(不输出明文)。三点同指针+同 length 即可把“接收累积对象 == parser 输入”与“同事务”一次性绑定,闭合边1/2/3。这是最小必要观测,替代无界静态别名求解。

## 四、边界
结构桥已定位到接收累积对象(NSMutableData)并给出完整帧槽生命周期与一段已证写序;**未声称** logind0 响应解码闭合、同事务接收已绑定或授权成立。保持所有历史冻结包不动。下一步按用户选择:继续离线 (a)/(b),或授权最小三点观测。
