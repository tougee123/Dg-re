## 2.3.9 第二轮：Update字节状态机、CF活跃绑定与六unpad同状态链（2026-10-17）

本节优先于历史摘要；证据在 `work/dgassistant-239-byte-live-closure/`。复用 GUI PID 56134 / MCP 13338 / session `ae41be7e`，仅做只读静态读取和本机有限检查；未连接手机、SSH、Frida 或 debugserver，未执行/仿真目标或库，未修改 IDB、授权或兑换状态，未选择成功值/正常值/key/cache/class/IMP/clock。六个共享报告仍保持已发布字节，本轮候选尚未发布。

- **Update 的 14 个 arm 是源分支清单，不是可执行转换证书。** `UPD-A01..A14` 已记录实际指令段、读写宽度、guard、前后 memory version 和逐段 SHA256，账本共 38 行：14 个 byte_source closed、8 个 condition closed / 2 个 open、4 个 same-state closed / 2 个 open、1 个 certificate closed / 6 个 open / 1 个 blocked。所有 arm 均标记 `source_branch_only`，`executable_transition_certified=false`、`arm_graph_closed=false`；字节覆盖不等于分支执行、可达性或任意长度 native 等价。
- **SimpleUpdate 使用同一个验收函数处理正向与变异结果。** 成功返回值、moved 单元、已处理字节计数、output 单元和 capacity 单元分别通过单独的 violation 查询；五项 violations 的析取为 UNSAT。对 `normal_return_W0`、`moved_cell`、`bytes_processed`、`output_cell`、`capacity_cell` 分别施加变异后，同一个 `_simple_update_accepts` 验收谓词对每项变异的断言均为 UNSAT，而不只是比较人工写入值与 expected。回调返回值与其内存效应仍是 supplied source，不是活跃运行值。
- **前导栈与 M3 epoch 已按指令顺序拆开。** `5B14` 调整 SP；七条 `STP` 共写 112 字节，`sp+0x00..0x07` 与 `sp+0x18..0x1F` 未被该前导写入。`5B50` 的 cryptor[0] 读取发生在这组栈写之后，必须从统一的 post-prologue `M1` 读取；在未证明实际 cryptor 范围与任一 STP 落点分离时，不能简化为 `M0`。通用抽象反例允许 8 字节 cryptor 读取与任一 16 字节 STP 落点发生任意字节重叠，并证明旧 `M0` 读与 `M1` 读可不同；该 witness 不选择实际地址或数据。getter1 调用在 `5B7C`；`5B90/5B98/5B9C` 的 pending/table 读取及其后的 `5BA0/5BAC/5BB0` 重读都早于 padlen 调用 `5BBC`。因此 getter1 后为 `M3A`，padlen 参数读取为 `M3B`，padlen 后为 `M3C`；跳过 padlen 的分支出口为 `M3A|M3C`。不能让 padlen 的后效应回填它之前的读取。
- **`5E34` 不能写成 64 位 `pending-sent`。** 原指令为 `0203174b sub w2,w24,w23`，随后 `621600f9 str x2,[x19,#0x28]`，实际是 32 位差再零扩展；本机检查给出了与 64 位差不同的 witness。7 个 pending load（P0..P6）是 `state+0x28` 的不同读取版本，reserve/getter/callback 不共享一个冻结值。
- **copy/alias 与批量 IV 写保留真实发生顺序。** `5CF8`/`5DC0` 经 copy stub `064C`、`5E48` 经 stub `065C`；有限 byte-array 模型在复制前保留 source snapshot，并让通过 alias 的 store 对下一次真实读取可见。`__platform_memmove` 的 `0x400` 字节窗口已新增，包含 forward/backward、SIMD、non-temporal 和 scalar 分支，但 `n>=64` 的可执行转换及所有 overlap 效应仍 open。多块 CBC 的 16/8/4/1 批、批间重读和 `25E8` 单次最终 IV store 已做有限检查；实际 count 域、ISA/ABI 和任意长度等价未闭合。
- **Create/state bridge 与 one-shot 调用点只有源码事实。** `CCCryptorCreateWithMode` 的字节中包含 `+0x78/+0x40/+0x48/+0x28/+0x30/+0x38/+0x60/+0x50/+0x68` 等字段 store，`CCCryptorUpdate`/`ccSimpleUpdate` 读取对应偏移；`CCCrypt` 包含 CreateWithMode -> GetOutputLength -> Update -> Final -> Release 的调用序列。活跃对象实例、实际路径、状态传递和成功结果仍未证明。
- **回调 producer 入口纠正仍然成立。** `0x10080B9CC` 是 IDA `get_func` 的真实函数起点，具有 27448 字节 IDA chunk 且 raw/IDA 字节匹配；旧写法 `0x10080B008` 不是入口，而是 `sub_1008079CC`（起点 `0x1008079CC`，15944 字节）内部地址。原先按 314272 字节/2051 块描述的范围是可达 chunk 区域，不是单一连续函数。
- **CF/IMP 锁地址已纠正。** 正确锁字是 `0x1DD2C883C`。getter 的 ADRP/ADD 在 `0x1800BDE2C/0x1800BDE30`，setter 在 `0x1800D4DB0/0x1800D4DB4`，两处都解析为 `0x1DD2C8000 + 0x83C = 0x1DD2C883C`。getter 与 setter 使用同一锁字但属于两个独立 acquisition 窗口；DG 的 `FD74 str x0,[x9,#0x3e0]` 在两个窗口之外，不能合并成一次 saved-and-install 原子操作。tag0/tag2 getter 路径不加锁，而 setter 始终加锁。
- **savedIMP 与 CF 槽仍不能升级为活跃绑定。** `FD68` getter 的 X0 在 `FD74` 写入 `1015EC3E0`；`FD64` 与 `FD78` 是两次独立 Method 读取；wrapper 在 `37C3F0` 捕获该 cell，在 `37C520` 用捕获值 `blr`。Method 同一性、两侧 map version、实际活跃 IMP、type7/type20 的 live class 和 future adoption 时序仍 open/blocked。字节中的槽地址和 selector 不能替代活跃数值。
- **六个 unpad 调用点仍落在同一 Objective-C 方法。** `66734C/64B198/6642CC/669A88/66317C/65C494` 经 16 字节 thunk 到 selector `ACPDS:kaiv:`，方法入口 `0x100BBD1F8`，IMP `0x100016380`；不是 UTF8 构造器，也不是 `ACPDS:key:iv:`。
- **两个方法体 arm 已纠正，但没有形成六个 closed return。** Arm A 在 `165A4..165FC` 构造 base64 NSData、调用 decrypt、再调用 `initWithData:encoding:`，`X2=X22`；Arm B 在 `16658..166B0` 构造 base64 NSData、调用 decrypt，并在 `166B0` 用 `X2=X23` 调用同一 selector，`166B4` 将 X0 存入 X21。`16658` 是第二个 base64 NSData arm，不是 NSString 初始化；`166B0` 才是该 arm 的字符串初始化调用。六个 `B-SSB-*` 是 open 的 arm-local conditional/source relation，不是 closed method-return binding；实际 branch/arm、selector dispatch、ownership、release epoch 和 caller 内存版本未绑定。观察到 `objc_release` 也不证明 ownership 或无 use-after-free。
- **六个 caller 的输入仍是真实缺口。** receiver、ciphertext、key/IV 槽是 caller 上下文 `X19` 的字段；其 live object identity、调用时 memory epoch，以及它们与 DG Final/Release 输出之间的同状态边未证明。`0x1014CB660`、`0x1014CB5E0` 等常量只是原文件中的来源字节，不是选定的实际 key/IV。
- **`24B608` 只有直接 BL 源事实。** `0x10024B5DC/5E0` 构造 block 值 `0x10024B8F4`，`0x10024B608` 是 `BL sub_10080B9CC`。这证明局部 branch encoding 和目标，不证明从 `24B014` 入口可达该指令，也不证明 block/token 生命周期。`80B9CC` 的 27448 字节线性清单有 5674 个 head、唯一终端 `0x100812500 BR X8`，没有直接命名 `_CCCrypt` 的 BL/BLR；到具体 DG consumer 的间接边 open，主线程 UI presentation blocked。
- **23 项原义务仍未关闭。** 六个 caller 对应的 647/648、656/657、664/665、673/674、764/765、773/774 仍缺 caller-level 输入与真实验证状态；其余 591/603/604/614/617/618/685/702/735/743/744 保持原来源/算法义务。本轮 23 项关闭 0 项，`actual_unpad_equalities=0`，没有继承旧轮 closure。
- **仍然缺的边必须保留。** Update copy body `n>=64`、活跃 getter/padlen/reserve/callback identity、`80B9CC` 到具体 DG `_CCCrypt` consumer 的间接边、完整 byte-valued Update relation 与任意长度 native 等价；bindings 的 live receiver/cipher/key 对象和 Final/Release memory epoch；dispatch 的 Method identity、map generation、future class 采纳时序；以及 UI presentation。函数名、常量、有限算术或局部 PASS 都不能填充这些边。
- **验收边界不变。** 本节的 PASS 只表示证据文件、schema、哈希、有限局部算术和已声明 source/register 关系的完整性；不是 `AuthVerified`、`ActiveBindingVerified` 或 `UIReady`，也不是全链可达/不可达证书。六个共享报告未由本轮修改或发布。
### 新App启动契约增补：字节状态、分派窗口与本地解密边界

1. **Update 分层验收。** `SourceVerified` 只表示 arm/read/write/guard 的原字节来源已记录；`ConditionalValueChecked` 只表示有限表达式、局部算术或已声明 source relation 成立。14 个 arm 的字节行不构成可执行转换证书，也不证明任意长度、任意别名或 native 机器等价；`copy n>=64`、活跃 callee 和完整 byte relation 仍须单独兑现。
2. **保留真实状态版本与 epoch 顺序。** pending/reserve/getter/callback 各自读取自己的 `state+0x28` 版本；`5E34` 的 `SUB W2` 必须按 32 位差零扩展建模，不能替换成 64 位 `pending-sent`。前导 `5B14` 与七条 `STP` 之后，`5B50` 的 cryptor[0] 读取统一从 post-prologue `M1` 取值；只有显式证明该指针的 8 字节读范围与所有 STP 写范围不重叠时，才可以简化到 `M0`。抽象 overlap witness 已证明这种简化可能出错。`5B7C` getter1、`5B90/5B98/5B9C` 读取、`5BBC` padlen 调用必须按程序顺序保留；不能让 padlen 的后效应回填其之前的读取。多块输入按 16/8/4/1 批处理，批间重新读取，IV 只在已证位置执行一次最终 store；复制/alias 后的读取不得使用旧快照。
3. **Create/Update/Final 的边界保持显式。** 若新 App 对接自己的密码库，应分别记录 Create 字段、Update 输入/输出/计数、Final 的 moved 写入、复制目标与 Release 后状态；不能用 Final status 0、非 nil 字符串或 one-shot 库调用路径直接推出授权成功。真实 `_CCCrypt` consumer 的间接分派仍需在自有调用图中明确绑定。
4. **CF/IMP 不能按一次读或一次锁窗口设计。** 正确锁字是 `0x1DD2C883C`。getter 与 setter 使用同一锁字但不同窗口，DG 的 saved cell 发布在窗口之外；tag0/tag2 getter 可能不加锁，setter 总是加锁。新 App 不应把“getter 返回的 IMP”“setter 旧 IMP”“RO metadata”或 `saved3E0` 当成同一个当前实现；如实现兼容层，应记录实际 Method 样本、map generation、锁窗口和运行期 class/IMP 采样。
5. **六个 ACPDS 方法体关系不是六个授权结果。** 两个方法体 arm 的 base64/AES/PKCS7/字符串构造寄存器关系可以按 arm 条件记录，但 `B-SSB-*` 仍为 open：所选 arm、active method/IMP、selector dispatch、object ownership、release epoch 和 caller 输入都未闭合。`16658` 是第二个 base64 NSData arm，`166B0` 才是其字符串初始化调用；观察到的 `objc_release` 不证明 ownership 或无 use-after-free。本地 arm relation 不能替代六次 caller-level actual return，也不能把常量 key/IV 当成实际选定值。
6. **24B014 与 UI 分层。** `0x10024B608 -> 0x10080B9CC` 的直接 BL 源事实不等于从 `24B014` 入口可达，也不等于 block/token 生命周期已绑定。只有在同一次真实解密/校验、设备/时间检查、完成参数和 block/token 生命周期均关联后，才能进入后续链；`UIReady` 必须由实际同状态 presentation 或代码路径证明，不能由 selector 存在替代。`80B9CC` 到具体 `_CCCrypt` consumer 和主线程 UI handoff 仍 open/blocked。
7. **23 项义务独立保留。** 新 App 可以按自己的显式验证流水线实现，但不得把本节新增的局部关系计入旧 23 项 closure。状态应分别保存 `SourceVerified`、`ConditionalValueChecked`、`ActiveBindingVerified`、`AuthVerified` 和 `UIReady`；本轮 23 项 closed=0，未知、失败和未绑定都不能升级为成功。
## 本轮多块CBC、Final复制与真实IMP映射纠正（2026-10-17）

本节优先于历史摘要；证据在`work/dgassistant-239-stream-closure/`。复用GUI PID56134/MCP13338/session ae41be7e，三路只读静态，未连接手机、运行/仿真目标或库、改授权/IDB、兑换或选择实际成功值。

- **多块不等于逐次调用旧单块组件**：原CBC按16/8/4/1批处理。每批的密文/密钥读取在该批首输出写之前；后批从前批输出后的内存重读，不能冻结为入口快照。Q31只在寄存器传递，IV内存仅最后25E8写一次；逐块串联旧cbc1会错误增加IV写入并改变有别名的未来输入。已给实际batch值表达式和有明确Array递归定义的count参数组件，非新crypto返回UF；控制对应依赖原mode byteCount/16的真实宽度域、A0分支及正常ISA/内存条件，不以任意host长度上限替实际输入。
- **CBC零块与key schedule真实返回**：2154的count0走2158直接RET，不读F0、不保存栈、不写IV，X0仍原keyctx，不能填成功0。原30C50 AES128 keygen已按实际memory逐次读50个Sbox/Rcon字节并产生11槽；F0先写A0后读key，保留表/输入/context别名。30E84从key写后的实际栈重读ctx/Nr，不能自动沿用写前保存值；9次inverse-mix仅在真实重读Nr=10等域下适用。没有把原文件表或getCString入口快照代为实际采样。
- **Update的真实跨调用版本**：原保留量依赖实际pending/input/reserve/blocksize及u64环绕，不选pending0/reserve16。reserve调用前保存的pending与5CC8活读、flush前数量与5D54读回分开。5E34的SUB W2是32位差再零扩展，不得改成64位pending-sent。逐臂transfer/source schema与实值组件须区分；未展开的copy、callback、Create和活跃分派仍不能用成功摘要代替。
- **Final status0不等于写出有效数据**：原cryptorNULL在正常canary/返回域可直接返回0，却没有走moved初始化。outputNULL还可跳过moved写入。解密75DC先读N0查capacity，75F4真实目标为`__platform_memmove`；75F8重新读N1后7600才写moved。若复制目标覆盖计数，N1可不同于N0；不能合并读或拿N0直接当返回长度。6794 Release之后，外层14CD0仍要从实际后状态读取。
- **复制与Release来源已落到真实目标**：原auth-slot/PAC跳板分别定位Final复制的memmove、Release的free及clear/memset_s；这不是活跃PAC执行证书。memmove的逐字节关系、count重读和释放前后效果必须按原顺序连接；allocator/free、别名、重入/并发及有效对象寿命不可抹成无副作用。
- **CF/IMP不能只看RO metadata**：small-method的真实IMP getter先算签名RO候选，再查`1DD2C8730` DenseMap，实际remapped返回非零时优先；setter把实际新IMP写bucket+8，可能不改RO method entry。DG先FD74发布getter返回到saved3E0，再FD78重读Method、FD84调用setter，二者锁窗口不同，非原子“保存原实现并安装”。37C3F0捕获与37C520调用也不等同当前全局重读。原CF type7/type20的专门注册、done门顺序与两次独立类槽采样已有实际源；不把原metadata相等或done置位冒充活跃class/IMP已绑定。
- **六个unpad/23项/24B014的验收边界**：新增是完整原源分支账、实际值组件及更精确read-from条件，不是六次真实库返回均已绑定。仍保留六调用独立输入/状态、各轮guard、23逐式义务、CF编码转换/allocator/tail版本、callback root及主界面交接。没有新完整联合查询，没有重复旧超时；未闭边不填成功、也不报全链可达或不可达。

详见`work/dgassistant-239-stream-closure/STREAM_AND_DISPATCH_2.3.9.md`及三路/父层FINDINGS。完整性PASS不表示AuthVerified或UIReady。

### 新App启动契约增补：流式输出、释放与分派版本

1. 将解密状态、输出有效性分开：至少记录实际Create/Update/Final status、moved是否真的被写、复制前后各次长度、容量、累计长度和输出所有权。不能以Final status0或非nil字符串单独触发授权通过；NULL、空输入、空串、partial output与未写moved均是独立分支。
2. 多块组件必须保留批内快照/批间重新读取和单次最终IV写入。若新App只支持不重叠缓冲，明确建立并校验该自有接口前提，不把它追认成旧App已证事实；输入/输出/计数单元重叠时不能默认长度不变或逐块CBC可替整批。
3. 结果读取必须发生在已确认的有效寿命内；Release之后的读需要真实后状态及不覆盖/不释放相关对象的证明，不能把释放前缓存值直接充当旧App读回。新实现宜交付独立拥有、长度确定的不可变结果，不能复用失效的no-copy指针。
4. 不将静态RO method表、CF init done、某次saved IMP或延迟安装注册当作“当前验证函数”。兼容层必须明确实际receiver/class/selector、IMP采样和版本；NS encoding到CF编码及allocator/转换/tail内存桥不得省略。新App可实现自己的显式验证流水线，无需仿制旧全局runtime替换层。
5. 只有同次真实字节解密/验签、udid和endtime/ct检查及真实完成参数已关联，才能从验证状态转入24B014对应的完成/主线程UI交接。`SourceVerified`/`ConditionalValueChecked`不能自动升级成`ActiveBindingVerified`、`AuthVerified`、`UIReady`。本轮不改变实际授权状态，不兑换或注入成功。

## 本轮真实值组件、NSData 字段与 release 字节纠正（2026-10-17）

本节优先于历史摘要；证据在 `work/dgassistant-239-native-values/`。复用 GUI PID56134 / MCP13338 / session ae41be7e，只做静态读取和本机表达式检查；未连接手机、运行或仿真目标/库、改授权/IDB、兑换或选成功输入。

- **真实 CBC 值，不再只是函数名/来源 DAG**：原单块 `1D5132150` 路径的实际 ctx+F0 读取、11 个密钥槽、9 对 AESD/AESIMC、末轮与 IV 异或已形成有限 BV/Array 表达式。`25D8` 先写输出，`25E8` 再写原密文到 IV；保留重叠影响。父层以原 V8..V15 组成 128 字节保存写入，消除了独立“保存后内存”参数；同一 state 绑定 IV 与 state+16 密钥上下文，FinalSP+8 绑定输出，原 -32/-64 栈差绑定 CBC 入口 SP。仅在实际单块、A0、blocksize16、pending16..31 及原实现/ABI/内存域下适用，未替实际调用断言这些前提。
- **Final 的字节到长度**：真实 post-store 内存的 `8DC4` 字节经原掩码到 `8CC4 pending-count`、`7D10` moved。不是独立 unpad 返回或严格 PKCS#7。`6784/6788/678C` 另以同一实际 Final 后内存读取两个私有 moved，再相加写 caller moved；不能把它直接等同单个 Final 长度，Release 后的 `14CD0` 读仍单独保留。实际输入 key 在 `30C64` 写 ctx+F0=A0 **之后**才由 `30C78` 读取；不自动等同旧入口快照。
- **NSData 真写者/真 getter**：原非复制正常分支 `1812F323C` 写原 buffer，`325C` 写原 moved；后续 getter 独立采样真实 ivar-offset cell。11 项局部 Store/Select 归约给出有条件读回/字段外字节保留。工厂实际是 `objc_allocWithZone` 和 `objc_autorelease`，不是 objc_alloc / autoreleaseReturnValue；没有省略最终 autorelease 的真实返回与效果。length0 的 placeholder 可先调用默认 free 再返回实际 ZeroData，不能无条件保留原缓冲别名和寿命。
- **CF 实际分派源**：原构造体 `18134576C` 先转换 NS encoding，`5764` 采样 allocator，之后才在 `57EC` 交给 CF；NS 编码4不能原样作为 CF 编码4，CF 入口内存也不能拿外层消息入口快照替代，已在父层纠正错接并保留各组件独立 guard。ExternalRepresentation 先取 byte pointer，再取 length，最后 funnel 使用 length 调用后的内存；两次独立读的是 CFData **type20** 槽 `1DD2DCD68`，不能混作 NSString type7 或冻结同一次 class/memory。原 native/forwarding 两臂与 bytes/length selector、PAC target 已具体定位；活跃槽、IMP、对象身份、解码到 UTF8 的真实同状态绑定仍未证明。
- **release 写集缩小到真实局部锥**：B0 写者 `853C48` 到直接消费者 `856320`，相关外调是末次 `853C54`，而非整个 80B 函数的 800 调用。原递减 CAS `oldISA-2^56` 只可能改变 receiver+7 字节；六个局部反例查询均 UNSAT。不是整次 release 纯函数，也未从正常 CAS 偷推 receiver 对齐；B4/table 在释放后重读、析构/customRR/重入/并发与地址标签别名仍需实际绑定。两处真实 JSON producer、四个保留写入和三个清空臂已追出，不能选一个字典版本替代全部历史。
- **六个边界与23项义务的真实状态**：六个原 caller 的12个潜在轮均接上组件的原参数端口和旧逐式指纹；新增通用 Final/CBC 表达式 DAG 5807 节点，未增加输出/成功 UF。端口计划不等于 actual-output 等式：六个旧 unpad **尚未被完整库返回替换**，23项原义务保留，本轮关闭0项，不声称联立求解或到24B014/UI已证。尚缺全部 Create/Update/多块、Final copy/Release、活跃分派、字符串内容及 callback root 的同状态边。
- **失败证据未隐藏**：provider 最初4项聚合局部查询的 all-UNSAT 断言未通过，逐项状态没有落盘，不能称4项已证；保留脚本且未重跑，改成11项精确归约。旧 wrapper CFG 解析在37C838失败也留档，无完整 CFG 声明。未重试旧完整超时，未运行新完整授权查询；旧8.6393s UNKNOWN仅是历史结果。

完整说明、原字节、条件域、接口和核验：`work/dgassistant-239-native-values/NATIVE_VALUE_BINDINGS_2.3.9.md`。PASS只代表证据/局部数学/文件完整性，不代表授权或主界面成功。

### 新App启动契约增补：值、对象与进入条件

1. 缓存层向验证层交付**原密文字节、实际设备标识来源、各次时钟采样及错误**；不要把“缓存非空”“NSString非nil”或“库正常返回”当作验证成功。保留短输入、空串、部分输出、失败/过期分支。
2. 解密适配层交付有明确长度及所有权的结果，分别记录 Update/Final status、各 moved 及总长度。旧 App 的 decoder 掩码并非严格 PKCS#7；本轮仅证明原单块组件，不能直接移植为已验证的完整兼容 AES/签名模块，也不能用成功替身补多块/CF/UTF8 边。
3. 不在旧 NSData 缓冲已释放或长度0默认 deallocator 处理后继续读。构造/读取必须关联同一对象、实际偏移采样、内存版本和寿命。ExternalRepresentation 的 pointer 与 length 是前后两次调用，解码看到的是后一次调用后的字节，不保证前次快照不变。
4. 合法进入事件仍必须来自**同一次**真实解密/验签、udid、endtime/ct 校验及实际完成参数，随后绑定真实24B014第一回调和主线程UI交接；外层回调指针存在、B0布尔范围或局部CAS字节不变，都不能代替这条完成链。新App可先实现独立、显式、可测试的启动状态机；不要把尚未闭合的旧函数图写成可直接沿用的成功契约。
5. 验收状态分开保存：`SourceVerified`、`ConditionalValueChecked`、`ActiveBindingVerified`、`AuthVerified`、`UIReady`。本轮只增加前两类证据；没有推进后三类，未知/失败不能提升为已授权，也不代表已证明全局不可达。

## 本轮逐轮内存、真实失败写入与空串构造纠正（2026-10-17）

本节优先于历史推断，详见`work/dgassistant-239-round-memory/ROUND_MEMORY_AND_DISPATCH_2.3.9.md`及cipher/provider/dispatch/joint子报告。三路复用现有GUI56134/MCP13338/session ae41be7e，仅静态原DG/IDA/已有本地库/cache和host表达式；未连接手机、执行/仿真目标或库、改授权/IDB、兑换、安装、选成功值/域/IMP或导出私密输入/模型。

- **先纠正真实load地址。** 第一采样仍为16520 `081141b9 LDR W8,[X8,#110]`；第二实际在**16528** `291541b9 LDR W9,[X9,#114]`，旧报1652C `2a01280a`实为BIC，不是第二load。global对象与32位选择算式未变。164BC/164C4 retain与164D0实际length之后才采样；两cell为RW __data。原5指令section含__obf的432个page-ADRP seeds、每seed最多192B直线解析只见这两read且未解析到重叠write，fresh IDA也仅ADR/read xrefs；这不是全部别名/其它image/并发writer排除，不拿文件初值或caller快照当实际采样。
- **失败也有实际库写入，不能回滚成全零。** 原CCCrypt在672C先把GetOutputLength真实estimate写进caller moved，6730之后才判断capacity；Update错误6764直接Release，因此可能保留estimate。Final后的6784/88/8C无论其status先写实际updateMoved+finalMoved，Release又是独立真实写/释放屏障。SimpleUpdate在73F4先调CBC可能改输出/IV，callback status0后7410先增加moved，7418才查remaining capacity，错误不回滚这些写。Final的两次operation读取跨GetBlockSize、padding decoder及CBC后内存/私有buffer都分别保留；不把status0当形状、未改写内存或成功明文证明。
- **六caller已逐发生点接按轮源/效果模型。** 原ordinal138/143/148/153/220/225处X2/X3 AST和entry frontier逐项匹配旧unpad来源；428原call与5122显式store组成5550节点的旧符号时序，不是实机trace/闭合native内存。每caller保留short、可选前置、最终、166B4 X21与cleanup；12potential轮分别接24份getter、12份constructor候选计划，22处原UTF8 consumer也按实际ordinal/receiver AST接入，不合并跨调用/跨轮同对象内容。14B00 key/IV标为call入口memory view，**不是该PC的真实LDR**；Create后实际key展开/IV复制版本仍需原调用效果闭合。
- **getCString失败不等于17B都保持零。** 原NSString默认1812CBA7C对capacity17先动态length，再调用getBytes；X2=buffer,X3=16,X4=&本次SP20hex,X5=encoding,W6=4，NSRange整体在SP+0/+8，remainingRange在SP+10hex，不能伪造X7=range。成功CBB08读本次used，CBB0C写buffer+used的NUL；失败CBB18只清首byte，先前helper可能写入的prefix仍在。__NSCFString有真实override186FC14B8，encoding转换/CFStringGetCString另走原分支；4CF48对1DD2DCD00的读取与constructor2248、UTF8 3150不是同次采样，不偷用同slot内容恒定。CF encoder以实际处理字符数==实际length判成功，仍保留partial writes、copy/PAC和动态callback。
- **关键修正：最终NSString非nil不是解密成功门。** 原NSPlaceholderString `initWithData:encoding:`181345738首条CBZ X2，data为NULL的原臂直接1813457B4/7B8/7BC返回unslid1DE6C5078，无encoding/CF decode调用。v3原metadata确认该singleton是__NSCFConstantString、flags7C8、长度0、chars首byte0，即非nil空串。它只是在实际绑定该body/实际nil-data分支下成立，未选择live类/IMP、runtime输入或当前授权；但足以纠正旧通用“非nil⇒data非NULL”和ACPDS“非short+非nil⇒status0/shape/unpad字节”的无条件化。后续parse/设备/时间可能拒绝空串，不能把此静态错误臂叫激活或主界面反例，也不能仅给六个unpad填成功输出。
- **release写集追到真实析构producer。** C++析构B9478实际lookup结果→X22→B94A0认证调用，随后真实superclass/PAC/回环；不是独立选一个析构IMP。DG九个.cxx_destruct及一个dealloc原metadata/全体bytes已核，Partial示例先按self+20/28/30条件free再super dealloc；其.cxx_destruct强清self+40/10/8。真实storeStrong先retain新值、C10E0写8B，再把实际旧值tail到原release，零store不等整调用无副作用。选取17原库函数得到43直接write、30call/认证transfer、17外tail的may-site清单，非完整可达trace。全80B虽没有语法可确证的B0地址参数，仍有504未知地址store与800calls；两lookup不合并、不选nil/tagged/Partial活跃类，不推出noescape/跨release保bit。

**模型层与求解边界。** 新按轮源/条件/内存效果DAG已建立并实际调用三个子接口，但候选库/Foundation body、actual dynamic return/postmemory、全部buffering/optimized路径与callback root仍未全闭，**不是完成版native值/SMT模型**。原23个索引及逐式fingerprint全保留为历史/源条件义务，没有删除或把错误摘要当native公理；旧986/1856/2850也不是新模型计数。本轮完整查询0次，未重跑旧同式超时；旧8.6393s UNKNOWN仅历史引用。尚未证明有效缓存经24B014到管理主界面的真实可达性，亦未证明全局不可达；完整性PASS不能触发AuthVerified。

### 新App启动契约：逐轮输出与失败保真

1. 将164D0 length实际返回的short门与Base64字节长度分开；g110/g114必须来自164BC/4C4/4D0效果之后16520/**16528**这两次实际采样。1652C是BIC。不能用文件初值、同slot旧读取、独立normal flag或caller旧memory快照替代。
2. 以caller/前置或最终轮/调用发生点记录实际memory版本；保留前置轮的分配、消息、构造及释放，即使其字符串不作最终输出。每轮两getter虽接同kaiv对象，仍是不同buffer、写过程和读取；最终166B4只保存最终构造返回。
3. 原getCString BOOL未检查，默认失败仅清buffer首byte，不能把其余16B回填零。按实际length/getBytes/used写与CF override/copy/encoder分支保留所有partial writes；若新App改成严格编码成功/完整key检查，应标明安全/兼容性变化，不假称旧App已检查。
4. 区分三个计数cell：caller moved先从0变为estimate；UpdateMoved(SP20hex)与FinalMoved(SP18hex)是两份私有cell。Update错误路caller moved保留estimate；只有Final已调用后678C才把两私有cell的实际重读sum写回caller moved，不以Final status0为条件，再保留Release效果及之后读回版本。capacity/Update/Final错误不自动回滚buffer、IV或moved；调用者错误free→nil与成功dataWithBytesNoCopy分支、构造/分派失败均保留。status0不能代shape或actual buffer内容。
5. 必须区分nil NSData、非nil空串、非空实际明文及已验证授权。原placeholder的initWithData:nil候选可返非nil空串；原short又可返非nil错误CF，所以最终字符串非nil不能触发AuthVerified。新App若将空串明确归为解密/解析失败，这是显式处理策略，不能依旧非nil摘要沿用。
6. constructor2248/getCString4CF48/UTF8 3150等同slot的不同读取分别绑定实际启动历史、早置flag、superclass/cache writer和captured IMP；注册/flag1/原RO方法只给来源，不给活跃绑定。provider候选body与动态call postmemory的等价不能靠节点连线假定。
7. release按实际receiver、原guard、CAS/side-table/析构/强清/旧值嵌套release保留写集；语法没有B0参数不等noescape。可重叠零store即使保Boolean范围也可能改原bit，不能用候选0/1、signed-nonpositive快路径或“析构无写”代实际footprint。
8. 原23项义务保留为来源/算法验收，但需以修订后的真实分支/producer兑现；旧good和2850历史UNKNOWN不是新native模型结果。只有真实缓存、解密/验签、设备/时间、原block/token、三个阶段接受以及主队列/self/Block生命周期同次闭合，才进入管理UI。source模型或完整性PASS均不是授权通过事件。

## 本轮ACPDS非short、活跃分派与必要域纠正（2026-10-17）

本节优先于历史推断。详见`work/dgassistant-239-nonshort-dispatch/NONSHORT_AND_ACTIVE_DISPATCH_2.3.9.md`及cipher/provider/dispatch/joint子报告。本轮3路复用GUI56134/MCP13338/session ae41be7e，仅静态原文件/IDA及已有本地库；未连接手机、执行/仿真目标或库、修改授权/IDB、兑换、选择成功返回/域或导出模型。

- **ACPDS非short不再只是一个汇总函数。** 原16380入口的重复length臂被源范围排除，实际164D0的length返回在164E4作unsigned `<2` 比较。short返回原CF100BB96D8，公开文本“解密数据为空”，不是nil，也不调用Base64/CCCrypt。非short16504用16520/1652C两次真实32位读生成`UGT32((g110 XOR g114)*0x55465392+0xB329B93B,0xDBFBB67B)`：false先走165A4前置轮，true跳过；两者最后都走16610最终轮，只有最终166B4结果存入X21。10项全值标量证书裁掉伪重复/循环，不固定global、不选正常返回。非short源码为1或2轮Base64→AES消息→UTF8构造；**只有实际非nil NSData且分派到原实现时，才对应1或2次CCCrypt**，不能把六个汇总AST当六次真实库调用。
- **真实库调用臂及错误释放已落实。** 原AES decrypt wrapper固定选14FB0(op1)，AES128Operation固定选14A14→14B00；14A0C并非同次必执行的第二次CCCrypt。两份32B缓冲各清零17B，再分别getCString(max17,UTF8=4)，BOOL均未检查。实际NSData length→X26、wrapping length+16→capacity、未查NULL的malloc→X23、实际bytes→X6、moved单元清零→X28。14B18仅检查实际CCCrypt W0：非0经已证原分派只free一次→nil；0经14CDC用同malloc buffer和实际moved构造NSData，仍可能构造失败。原CCCrypt重绑定11参数/W0透传证书只读继承，不把保存槽地址当活跃系统函数值。
- **关键纠正：shape不是已证源码必要门。** 原DG调用者没有非空、mod16、capacity溢出或malloc NULL检查；Final75A4..75D4直接交pending count，padding wrapper7CDC正常保存core长度后W0=0；core8C98 floor(n/blocksize)、8CB0 CBC之后不检查status，再用(blocks−1)*blocksize定位decode并返回n−count。故旧good中的`n>0 && n%16==0`只能作为**未兑现的输入/内存适用域**，不能由nonshort+nonnull或status0单独推出。本轮没有构造坏输入、挑未初始化字节或声称实际反例；也没有删掉算法义务来获得“成功”。六旧unpad UF仍需真实按轮/缓冲/活跃实现绑定。
- **六caller与新callee源API已同状态审计，但不是新的完整native模型。** 保留原852边、428调用、986主式与1856provider源扩展的旧身份，六个length/short/Base64/key17/IV17/status/unpad源项逐项AST匹配；同kaiv对象分组1/3/1/1不等于跨轮或跨调用缓冲内容稳定。旧getCString/status函数没有前置/最终轮及逐次memory版本；内部16520/1652C实际采样尚未在该汇总状态执行，未拿别处读取或新独立flag补进去。原classref/import-cell标签还可能只是slot身份proxy，不是live类值，其非零不能证明实际消息分派。原23条作为待兑现/有条件义务全保留；**旧2850式不是已经完成的本轮双轮native可达性模型**。
- **CF活跃来源推进到真正启动注册及继承写者。** Foundation原__objc_nlcatlist唯一category的真实`load`→181349038→_NSInitializePlatform，先在181348C08写inited=1，再调用原CFInitialize与NSToDoAtProcessStart。后者真实objc_lookUpClass(`NSString`)返回经18136CF08写___NSStringClass1DD2E4590，allocWithZone读同物理cell；registry/realization/回调写SP+8及NULL分支均保留，不填NSString类。它还以两次真实lookup结果调用class_setSuperclass，写普通类/元类并flushCaches，所以base RO继承链不能直接冻结成活跃链。登记不等于实际执行，早置flag也不等于完成。
- DG bytes-selector安装flag1015EC4D4是__bss/ZEROFILL，无原文件字节；37E7BC/37E940在嵌套安装、class/Method查找及saved IMP发布**之前**就STLR1，不能当已完成或CAS互斥证书。37DEF0的另一次acquire值还会在本块被table pointer覆盖，不是额外有效完成检查。没有把这两flag或原import proxy变成CF两slot同值/活跃IMP的证明。
- **isKindOfClass与release已有真正执行体，而非API名字。** 两个field lookup从同pointer cell/key对象的不同实际读取和message/retain事件分别产3710、3780，未合并对象/字典版本/refcount。原NSObject实例isKind方法真实metadata→1800CA858，其唯一正常RET的W0来自CSET/literal→EOR，候选body范围0/1已核；但先调用的是实际objc_msgSend$class，不是无副作用object_getClass，活跃override/类别/继承/PAC仍须绑定。原objc_release signed X0<=0快路径无写/无调用，可**有条件**保B0；正对象仍有ISA/CAS重试、最后引用dealloc/_objc_initiateDealloc、custom release、认证hook/side-table等真实副作用。未挑nil/tag/refcount，未跨release强保bit。因此本轮无新增无条件入口范围，仍累计103、open89/14、前缀461/1783，F30/parser/首65DF98仍未闭合。
- **37C0AC输出构造替换层已补原字节静态证书。** 原入口两setup臂均在有效role/原ARC alias域把X0/X1/X2/X3原样送入37C520；它使用37C3F0从1015EC3E0读取并保存的那次IMP，不重读当前slot，也不强选Foundation。中间table index1被原局部式排除；post/cleanup的其他SAT分支未选择。1CC额外cleanup的固定28D目标是42C，不是RET；42C可退出或再回1CC，循环保留。在无隐藏写的有效私有cell/ARC正常身份域，42C保存D8支配唯一正常RET，故可证正常返回**指针**来自实际saved-IMP结果；这不证明内容、无副作用、有限进展或当前原IMP。异常清理继续到Unwind_Resume，不变成成功返回。

**本轮没有运行修订后完整链求解，也没有重跑旧完整超时。** 历史2850式8.6393s UNKNOWN仅保留为历史结果，不能冒充新双轮/活跃分派模型的结果。有效缓存经24B014到管理主界面的真实可达性仍未认证，亦未证明全局不可达；现已明确需补的是实际按轮输入/输出/内存版本、真实Foundation/库分派、入口root/last-writer、设备/时间与三回调/UI生命周期，不是“随便给六个输出成功值”。完整性PASS不代表授权通过。

### 新App启动契约：非short按轮、错误与活跃分派

1. 区分NSString UTF16 length<2的short门与Base64解码后的字节长度。旧short返回公开错误CF对象而非nil；调用者不得把非nil等同激活/解密成功。实际nonshort的前置轮/最终轮按原两次global采样和时序建模，前置结果不用作最终明文，但其调用/分配/构造/副作用不能省掉。
2. 只有实际NSData receiver非nil且消息命中原AES实现，才有对应CCCrypt调用。每轮保留各次NSData length/bytes、两份getCString缓冲、capacity/malloc/moved、实际32位status和NSData/UTF8构造结果，不把同cipher/kaiv对象自动当跨轮内容及status相同。
3. status非0按原正常分派free同buffer一次并返nil；status0使用实际moved和同buffer构造NSData，仍保留构造/分派失败。原getCString BOOL、malloc NULL、length+16溢出及对齐并无显式门；新App若增加严格输入、容量、padding/UTF8安全检查，应标为安全/兼容性变化，不假称旧App已经检查。
4. `n>0 && n%16==0`是原数学CBC输出关系尚需兑现的形状/内存域，不能从status0或非short+nonnull反推。原core忽略CBC status这一事实保留；不能删除域/义务后依赖可满足性，也不能挑成功内存或加独立normal flag。真实native输出未闭前，不强等六旧unpad UF。
5. 构造器/类启动flag区分未开始、进行中、完成发布。Foundation inited和DG4D4均先置位再工作，不能用flag1认定CF初始化/IMP已发布或已互斥。原类注册/回调、superclass写与cache刷新须在真实启动顺序内绑定；import-cell身份不是live类对象。
6. isKindOfClass候选body的0/1范围只在实际method绑定及正常返回域成立；其内部class仍动态消息。两个field lookup/retain结果按实际发生点分别保留，不能为release强推同一字符串、tagged或第二拥有引用。release快路径只作条件footprint；普通/CAS/析构/custom/hook副作用必须联回B0/后续读写。
7. 37C0AC使用捕获的saved IMP与原四参数，保留可重复cleanup和异常。有效私有cell/正常ownership域中的返回指针身份不是UTF8内容、活跃Foundation或无副作用证书。前置/最终initWithData均可能穿过该替换层，不能让一次汇总UTF8函数掩盖它们的时序。
8. 原23算法义务仍保留为按真实输入/输出/控制兑现的要求；旧2850查询不代表修订后双轮native链已验证。只有实际缓存、解密/签名、设备/时间、原block/token采样、三阶段接受与对象/主队列生命周期闭合才可进入管理UI；无手机/无授权修改的本轮静态完整性PASS不能触发AuthVerified。

## 本轮真实流式输出、活跃绑定与入口联立修订（2026-10-17）

本节优先于历史推断。主报告见`work/dgassistant-239-output-transport/OUTPUT_TRANSPORT_AND_REACHABILITY_2.3.9.md`，子报告位于cipher/provider/entry/joint。本轮三路复用GUI56134/MCP13338/session ae41be7e，仅静态原文件/IDA及已有本地库；不连接手机、不执行/仿真目标或库、不修改授权/IDB、不兑换、不选成功域或返回。

- **六个unpad边界已有精确构造来源。** 在原host ACPDS关系构造实际unpad AST的当下记录PC/occurrence与同次cipher、kaiv、output、key/IV/cipher字节及actual status；原对象记录和旧UF/参数逐项AST相等。对应为66734C→647/648、64B198→656/657、6642CC→664/665、669A88→673/674、66317C→764/765、65C494→773/774，不再按节点顺序配对。这是同852边符号关系的来源绑定，**不是六次运行期CCCrypt均已发生**；ACPDS short/error、Base64/nil及原调用臂仍保留。
- **真实Update/CBC/Final缓冲输运继续补实。** 实际CommonCBC descriptor+18/+20经原v3链到_cccbc_mode_crypt；Create7144/7150写block16/pending0，mode传同state开头IV与state+10 keyctx。Update5DC0把推进后最后密文复制到cryptor+8；CBC四类batch各从postinput X3-10读取最后密文，25E8写回原IV指针。Final75B8/BC再取同pending输入/count，75CC用本次SP+8作输出，75F4按actual finalMoved复制到原out+actual updateMoved；one-shot保持实际两长度相加。N=16保留原IV，不虚构一次Update CBC。容量、status、活跃memcpy/PAC/别名及optimized机器等价不被略过；corehelper不检查CBC status，不能由wrapper0或one-shot status0强认正确输出。
- 同六实际事件已产stream_plan并接回同一联合状态：同key/IV/cipher、Update前缀、retained末密文、后续IV、两段数学CBC及末字节slice均来自原AST，不造独立输出/成功flag。shape与actual status只是**未断言且不充分**的已有来源guard；实际非short调用臂、NSData/缓冲/64位计数及完整库机器域仍须核实。因此**六个旧unpad UF尚未被替换，也未加入六个输出等式**。本轮是来源/真实输运和数学分块的推进，不冒充native输出已完全兑现。
- **CF活跃绑定具体到真实setter生命周期。** 全原CoreFoundation __text直接B/BL到私有bridge的19处均在已登记initializer内；这不是全writer/实际执行证明。bridge锁/unlock有真实快慢分支，generic ISA填充在锁体之外，已核reader窗口未共同获取该锁，未排除调用者持锁，不能据此推两次slot相等。constructor的实际object_setClass经cache veneer到1800BCDC8，按真实class flags可走initialize lookup，再tail changeIsa的CAS/side-table链；返回来自旧ISA，不是新NSString对象。lookup得到的IMP不在此处被直接调用，亦不称必执行+initialize。NULL/正常、PAC、并发及CF回调域保留。
- **运行时新增方法的真实目标纠正。** 原名字writer及参数cells落实37FD24/3803EC的class_addMethod为NSPlaceholderString / `initWithData:encoding:` / replacement37C0AC；encoding来自实际NSString同selector Method。37FD68的actual oldIMP经37FD74写1015EC3E0，37FD84进行真实替换；add返回未检查。这不是UUID的`initWithBytes:length:encoding:`。不能再以这两add断言UUID构造被改写，也不能倒推全图无hook，独立37DB68与安装/别名历史仍在。
- **又补21处原源范围，累计103。** 631累计14、open89、保守entry前缀461块；80B累计89、open14、前缀1783块。两个原STRB确实写0，任意重叠清零都保持已有full32 BOOL范围，无须假定disjoint；但低字节重叠可能把1变0，不能保留原CSET身份。最终含回边图重验全部source/must-writer。两个80B首cut已具体为83CFEC的actual isKindOfClass: unmasked W0，以及当次intValue==257后frameB0跨objc_release853C54的副作用，未填成功bit或忽略release。
- **完成地址纠正。** 83B04C只是`STR W11,[X19,#BD4]`保存实际数值低32位；实际invoke是84B738..748按BD8/BD4/BD0/BC8装载X8/W2/W1/X0后BLR84B748。该invoke虽进入80B保守前缀，836F50/F30、8467C4 parser及第一/第三producer的65DF98仍未进入相应闭前缀；不能由第二producer的调用拓扑补出同次root或24B014成功事件。
- **第一回调新增精确源式而非进度替身。** 24B388/390两次真实word读先OR，原MBA经mask恒等式与mod2^32环证书精确等同`((A|B)*0x3C607103+0x6E9ACEFB)^0x3C56BAAE`。其24B470相等回环条件等价`(A|B)==0xC1929026`；不等才继续原后继，不固定A/B、不合并迭代或FD8。另24B7D4比较常量0x418D2728与W8>>30，对任意32位W8均不可能相等；CSEL取原NE W27仍保留实际寄存器transport域，不直接当业务成功。
- **同状态联立保留23算法条件。** 新观察器在同852边/428调用状态中保留986主式、1856 provider扩展、5原桥与FPA2BV，仍为2850联合式；六个精确unpad来源及九类stream表达式逐一绑定到该状态，23原算法条款没有减少。第一回调进度门仅作已证精确规范式，不加成功条件。父层新局部结果为11项UNSAT及16项字节结构恒等；初次CBC混合检查的3个UNKNOWN/timeout原样保留，未重跑同式，另用覆盖任意原长度的商参数纯整数证据及解释型序列语义分解。它们不是23条已解或native机器证明。**本轮没有重跑完整query**；最新完整结果仍为前案2850式8.6393s UNKNOWN，不输出模型。

**有效缓存经24B014到管理主界面的真实可达性仍未认证，亦未证明全局不可达。** 现已补实际六源配对、关键缓冲/IV/Final输运与21处入口范围；尚缺实际调用臂/库全等与活跃绑定、完整入口root/跨调用读写、设备/时间及三阶段回调/UI生命周期的同状态闭合。完整性PASS只证明证据和声明边界，不是授权成功证书。

### 新App授权启动契约：本轮真实来源与执行边界

1. 为每次ACPDS调用保留call-site/occurrence、cipher/kaiv对象、实际key与IV两缓冲、status、padded与unpad输出身份。六源配对依上述构造点，不按列表顺序，也不把构造了AST当作真实解密调用已发生。短输入、nil/Base64及原错误调用臂独立保留。
2. 流式AES-CBC输运必须保持同一个cryptor：fresh pending与block size来自实际Create；Update的pending保存末段**密文**，IV推进取最后处理密文而非明文；Final读取同pending，输出经本次栈buffer与actual moved拷回原out+updateMoved。N=16原IV保持；不执行不存在的前块读或虚构一次Update。原status/capacity/拷贝/64位计数/别名与调用臂不能由单一status0替代。
3. 原数学CBC分块与同源末字节slice可以在明确shape域用有限序列/归纳对应，但这不自动绑定所有optimized库机器路径或活跃实现。shape和actual status guard不充分，不能据此强等六旧UF；新App若采用严格PKCS7、独立验签或不同编码，应作为明确行为变化测试。
4. CF初始化登记、generic过渡ISA、专门bridge和busy/done各自建模；原锁不是两reader同值证明。object_setClass是依实际class metadata的lookup、CAS与生命周期过程，返回旧ISA，不作为新对象；不要把可选lookup当作必执行initialize，也不能抹去其副作用。
5. 区分实际安装选择子。NSPlaceholderString/initWithData:encoding:的37C0AC替换及saved1015EC3E0，不等同UUID构造选择子。保留Method NULL、add失败、继承/category、encoding来源和原安装时序，不因这两add而升级或取消UUID路径的活跃绑定检查。
6. 范围保持与值身份分开：零字节写即使重叠仍可保BOOL范围，但可能把1变0；不要拿它证明原CSET值未变。release可能触发对象析构/动态效果，必须有实际footprint或noescape证据才跨过，不能仅凭系统API名字忽略。isKindOfClass:实际W0与receiver/class来源也不能选成YES。
7. 完成调用按原block布局和实际参数装载识别：83B04C只是低32保存，84B748才是该producer的真实invoke；不能串成第一24B014实机事件。第一回调的两次global读取及每次循环保持独立，进度门OR==C1929026是失败/回环谓词的等价形式，不是授权成功凭据。
8. AuthVerified必须等待真实解密/签名、设备与时间、实际缓存输入及完整控制/生命周期约束兑现。三阶段接受后再按原主队列界面构建链；文件存在、图拓扑、callback参数保存、520状态写入、局部UNSAT或证据PASS都不能单独恢复主界面。本轮23算法条件仍在，不把来源联立等同已经解完。

## 本轮活跃绑定、跨锥与真实返回修订（2026-10-17）

本节优先于历史推断。详见 `work/dgassistant-239-active-cross-cone/ACTIVE_BINDING_AND_CROSS_CONE_2.3.9.md` 及provider/stt/control/algorithm子报告。本轮三路静态复用PID56134/MCP13338/session ae41be7e，不连接手机、不执行/仿真目标或库、不改授权、不兑换。

- **CF活跃绑定补到真实注册和过渡写者。** CoreFoundation唯一INIT_FUNC_OFFSETS原项1870F9A60=`38530b00`，base186F3B000+B5338即186FF0338，DG强依赖该库。初始化不是dispatch_once：done1DD2DCF22非零、busy1DD2DC958 bit0置位都早退。FF04AC先以认证的table[0]通用填充slots1..71（包括type7），FF04C8才专门bridge `__NSCFString`；正常返回边局部图中04C8支配done写FF0808。登记不等于已执行，busy早退不等于完成；重入期可见过渡ISA映射，不能把两个实际类槽读取冻结成同值或强选正常CF对象。
- DG真实字节产出NSString/NSPlaceholderString名缓冲后分别objc_getClass；primary Method实际NULL/nonNULL由table10154C368分到37DFEC/37DE2C，alternate class来源真实存在，但后继CFF与完整fallback仍保留。37EB4C/37F414是嵌套安装器，不是名字产出函数；37F414确有class_addMethod，target37C0AC。**“37DB68本体无add”不能外推整个调用图无add或constructor必未hook。** stt853AAC仍使用frame24C8保存的824EE4那次saved-IMP读取，不是调用时当前global或objc_msgSend。
- **88C2D8真实返回不是成功替身。** 两层原消息wrapper都AND W0,#1；654104实际调用NSFileManager/defaultManager产生的receiver与fileExistsAtPath:，path从*frame22B0原强对象读入，未挑一份固定cache路径。3AD190完整4640B无BL/BLR，实际双C字节/cursor循环的唯一RET前读取原输出byte再AND1；未将它强命名为strcmp/substring、未选输出bit，非法指针、NUL/进展和alias域保留。8968EC同样实际AND wrapper，inner3F2EF0的getaddrinfo输入/真实status分派、freeaddrinfo、原输出byte和global副作用分别记录；不等同DNS成功、45.205.27.120:2可达或授权通过。
- **又补49处源范围边，累计82。** 631累计13（本轮+11）、全代码open90、保守entry前缀453块；80B累计69（+38）、open34、前缀1582块。全部原源transport/must-writer在最终回边图重验；stt入口8456C8现拓扑可达，但F30源836F50、parser8467C4及completion仍未进闭前缀。没有用图路径证明实际root/缓存/同次条件。537段27349选择DG/IDA字节相等；两个原磁盘零/IDA extern-fixup不同的import槽另列，不改文件/IDB、不当live函数或class指针。
- **stt跨锥已接过两道同源NULL门。** 12节点局部图从836F64保存实际51960C返回P，经8A8重读生成20C，再经B0重读生成3944；两门必须绑定同一P，不是两份独立指针。NULL原目标分别调用493800，第一非NULL目标进B0复制、第二非NULL目标进parser；原cell角色有效且不重叠、无隐藏/并发别名写入及无中间调用/覆盖域内，同次P读写关系已核，但opaque自环/重复循环仍可能不进展。493800有实际正常RET和复杂副作用，不称必然exit，也不把非NULL假定为真。
- parser正常返回后5节点局部图先转实际status到10A8、clear10B8，再立即用同out查询公开字段`ss`；其原tag3/cstring消费者与3EB224/intValue比较已列。共享out还用于`ss5`（不是sss）和`sign`。sign正常返回后的9节点局部图，真实tag2→round/FCVTZU64数值DA0与`signExtend64(2*actual_intValue + actual_word960 mod 2^32)`比较；EQ才去stt，NE去83BF70失败侧。这是原字段数值关系，不是sign status==0，也不冒充全部密码学验签。stt失败可能保留先前sign/ss5/ss handle；原numeric及尤其当前intValue实现的alias/barrier未被跳过，故不无条件锁定最后out或强置NULL/0。10A8九个明确角色用途均是status写转发，不把存状态写成已检查状态。
- **23算法条件继续保留，新增真实流式组件证据。** 实际padding descriptor+10/+18经v3页链分别到_ccpkcs7_padlen/_ccpkcs7_reserve；11个库函数2424B另列。原Update非零返回跳release、不调Final；正常后Final地址=out+实际updateMoved，最终actual两长度相加。core解填充调用CBC后不检查其返回status，按实际末块/末字节计数返回n-count；wrapper正常RET的W0=0不代表正确明文或合法授权。四个新反例UNSAT仅证16对齐域的末字节地址、保留末块长度和输出组合算术，不认证真实Update已输出n-16或Final已输出16-count；旧末字节算术只hash复用，没有重跑。
- 同852边/428调用/986式中23原算法条款、六次实际ACPDS来源及六个同padded参数unpad边界逐项盘点，没有据node顺序猜配对，没有给旧UF新增输出等式或成功domain。真实Update/CBC/IV/缓冲/Final字节产出仍需接回六个调用，所以本轮**不重跑未变化的2850式**；最新完整结果仍是上一轮8.6393s UNKNOWN，不谎报新完整求解或“只剩6题”。

**有效缓存经24B014到管理主界面的真实可达性仍未认证，也未证明全局不可达。** 本轮取得初始化顺序、跨锥同源谓词、真实数值门和49条新范围边；活跃绑定/调用副作用、完整entry读写时序、余前沿和真实算法产出仍不能由局部UNSAT或完整性PASS替代。

### 新App授权与启动契约：本轮真实分支与数据身份

1. CF生命周期须区分原注册入口、busy进行中、done完成来源和type7过渡映射；普通初始化正常边中的bridge-before-done不能替代真实执行/类对象/PAC及两次读取无覆盖证据。不要在busy早退时把CF视作已完整可用，也不固定ISA槽为预期__NSCFString。
2. 方法安装保留实际NSString primary、NSPlaceholderString alternate、Method NULL门及嵌套安装器副作用；只凭原base方法表缺项或37DB68本体无class_addMethod不能认定全局无hook。853AAC严格使用824EE4捕获到24C8的那次值，保留nil/更改/非返回，不用当前global或普通消息返回替换。
3. 文件存在性消费实际path强对象及实际消息返回经AND1的bit，不把fileExistsAtPath等同cache内容有效、验签或授权。原C字节predicate及DNS helper即使正常RET范围0/1，也须保留真实输入/循环/异常/副作用，另保留DNS/getaddrinfo的真实错误status，不能选择“未拦截”bit或把DNS、TCP:2和授权成功合并。
4. 51960C返回P到parser的两个NULL门、8A8/B0都用同次P；原无覆盖局部域中不凭空制造第二份指针。保留P==NULL的真实493800调用和非进展循环，不称该调用必exit或无副作用，不因局部路径就忽略入口/生命周期。
5. 原caller在parser正常返回后清lookup out10B8再查ss，随后还有ss5/sign/stt。getter错误-2/-3本身不清旧out；必须逐次read-from，而不是一次clear沿用至stt。tag3读取原cstring（NULL可能先解引用）、tag2走真实round/FCVTZU64；不能统一为NSString.intValue或错误0。字段名仅在原initializer及源字节未改写域成立。
6. sign到stt的局部门保留实际DA0、当次intValue及当时word960：32位`2*intValue+word960`回绕后sext64比较，相等才到stt。它不是sign状态成功检查，也不是已经证明的完整密码学验签。保留当前intValue实现与numeric helper对共享out的调用/alias域；不能无条件宣称stt失败后必为sign、nil或0。
7. 真实系统解填充的wrapper正常状态0不是成功替身：core未检查CBC返回值，必须另绑定actual CBC输出/IV/Update缓冲/Final长度与编码、字段及设备时间验证。旧严格PKCS7所有尾字节一致不是已证旧App必要门；若新App采用更严格padding/独立验签，应明确作为协议/安全行为变化测试，而不冒充原行为。
8. 原23算法条款仍全部在；本轮四个span/组合lemma及49个范围补边不等于授权闭环。保守图能到stt但不能提供同次parser/root prestate，24B014完整链仍未认证。AuthVerified只能来自真实输入/状态/数据与控制验证，不能由状态写入、拓扑、局部算术或文件完整性PASS产生。

## 本轮真实绑定、最终写入与间接边修订（2026-10-17）

本节优先于后续历史推断。详见 `work/dgassistant-239-binding-order/BINDING_ORDER_AND_CONTROL_2.3.9.md` 与provider/stt/control子报告。三路只读复用PID56134/MCP13338/session ae41be7e；只做静态，不连接手机、不执行/模拟目标或库、不改授权、不兑换。

- **设备与CF绑定不再只有“runtime未知”。** 原DG currentDevice→identifierForVendor→UUIDString各次receiver来源表达式/保存cell已逐个锁定，实际对象类/当前值仍未证。实际UIDevice实现调用LSApplicationWorkspace，原同步XPC `getIdentifierOfType:completionHandler:` 的type=0；completion186DCCA58把真实回复经ARC写byref forwarding+28hex，public方法再从同处读回。不能从API名字把回复对象强绑为本地__NSConcreteUUID，未输出设备值。
- 已按libobjc `method_getName@1800BE61C/620`实际selector-base1822C1612解出五类原relative方法表/继承链。原NSPlaceholderString表有constructor1812B8870，而捕获的NSString230/NSObject35 base entries无同selector；这是原表事实，不等于live lookup必nil，也不忽略分类/运行时增补。DG setup块3BE054实际依次调用3798C0→37DB68→53B8，但不在现有152块provider候选路线；不能说已先安装，也不能说从未安装。37DB68四次method_getImplementation→写global1015EC400→method_setImplementation真实来源保留，未把历史installed-hooks替身当实证。
- **CF真实注册/读写已追到同槽。** ___CFInitialize的186FF04BC/C0取原`__NSCFString`名字，FF04C4设type7，FF04C8调用_CFRuntimeBridgeClasses；该函数经实际objc_getFutureClass/PAC在186FE98D4写type7 ISA槽1DD2DCD00。_CFRuntimeCreateInstance@186FC2248和CStringPtr native检查@186FC3150均读同槽。原CFStringClass record表另为1DBFA6B30→1DE6F44E8，不能混作ISA表。相同槽位并不自动等同两次读取的值：真实初始化顺序、类实现化、PAC、中间writer及对象生命周期仍分账，未强加CF正常返回。
- **stt原输入有四份不同来源、13个3AD8写者。** 八次replacement来自3AD0/36F0/218/190各两臂，另四次storeStrong(NULL)及一次直接NULL初始化。853AAC这一来源的实际target是frame24C8←824EE4实读saved-IMP global1015EC400；不是因选择子initWithBytes就可以称objc_msgSend。另三来源分别为8147C0→38DAB8、8528A8原ADASAMGG82:key:消息、8523EC原stringWithUTF8String:消息；所有实参/实际返回/清空按原cell记录，不合并为任意JSON或选定成功对象。
- **已补真实局部顺序，不只列writer身份。** 七组有限cone共14条局部路径保留两项原目标：四个真实对象producer保存source后，经各自双retain臂写3AD8；51960C同次真实返回先836F64写F30再8552FC/857BF8写8A8；parser同次真实status先4A4后10A8并清10B8、copy原root→840；getter同次status先DF4后10A8，再copy实际lookup→2670。后面三组无调用，前四组只保留原retain。各组在实际进入/正常进展、原table/index、live/distinct cells及无额外alias/并发写域内穷尽局部分支；不选status==0、不把retain返回改为成功对象，也不把七组拼成已可达entry路径。8A8→8B0→parser→getter跨锥最终写入仍有具体缺边；getter-2/-3本身不清旧out。
- **33处原间接范围真正补边。** 63137C补2处（全inventory open103→101，保守entry前缀158块）；80B9CC补31处（103→72，前缀907块，新增真实interior heads后规范块2055）。64E7E0实际index源是663DBC CSET(global1015EB0BC==0)→663DC0 full32 writer→frame14DC，不选global值；8536E0实际源是835B28→3B0388真实W0→frame107C，该helper在原代码/表绑定、私有栈槽及ABI未受额外callee/alias写破坏域内，每条正常RET都先经原CSET/return-slot writer，因此仅证明实际返回范围0/1，不选择sysctl/flag结果或保证正常返回。calls/未知地址写是hard barrier，新增回边后全部33项重验；仍不宣称已到parser/getter/completion。
- 下一真实前沿已具体列出：631660454消费654104的BL88C2D8返回；80B83615C/83C8EC/8570D0消费实际3AD190返回，另两字节源、8968EC返回、opaque BLR853C54及STRB840A6C别名障碍分列。不是再笼统把101/72条写为待证，也不按table两槽就强加BOOL。
- **剩余23条算法义务已拆分，未假报解决17条。** 原同852边/428调用/986式及五桥完全保持。真实outer/CBC输出逐字节依赖的是先前输入/密文而非先前输出，八个原index0调用可按有限序列归纳改写为解释型seq.mapi闭Lambda；CBC仍内联原AES轮/密钥展开/S-box，原key/IV/guards/任意长度不变，无独立输出。现在19条含indexed-map、6条仍含显式Rec，重叠617/618两条，恰好仍覆盖原23条；用户Rec应用13→5（hash31四、空白1），不表示密码/序列理论消失。28项符号有限次序回归及2项任意长度结构反例UNSAT，一般等价依据明确归纳，不从有限回归外推。
- 对此实质表示变式仅跑一次全2850式联合查询，8s配置实测8.6393s返回UNKNOWN/timeout；无模型，无成功替身，无未变化公式重试。真实绑定、跨锥最终写入、完整验证producer和24B014/后续回调仍未全部联立。

**有效缓存经24B014到主界面的真实可达性仍未认证，也未证明全局不可达。** 本轮有具体回复producer、初始化/类槽writer、七组顺序证书及33处范围补边；剩余义务不会由局部UNSAT、保守前缀接通、map表示变化或完整性PASS替代。

### 新App授权与启动契约：本轮来源及顺序修订

1. 设备provider中的identifierForVendor组件来自原UIDevice→LSApplicationWorkspace→同步XPC取type0标识→completion真实回复→byref forwarding读取。不要把它替换为随机UUID、硬件UDID或预期固定字符串；服务字段名udid也不能据此被直接等同于硬件UDID。UUIDString/CF构造仍需实际回复对象的类/IMP、初始化及合法生命周期，不因候选方法表存在就生成验证成功。
2. 区分原方法metadata、安装操作及当前绑定。原setup块不在现有provider候选路线，不代表一定未执行，但也不能宣称已安装。NSString/NSObject候选原方法表未见对应constructor不等于live lookup必nil：原selector相对编码、继承、分类/运行时添加和真实class参数都须保留。stt的853AAC分支实际通过frame24C8保存的824EE4那一次global1015EC400读取值调用（不等同于调用时当前global值），不当成普通objc_msgSend或自动成功构造。
3. CF fresh构造设置类与CStringPtr native-class检查读同一type7 ISA映射表槽1DD2DCD00；不是两份独立随选的类常量。必须保留两次实际读取各自的memory版本，及_CFRuntimeBridgeClasses的原写者、PAC、可能中间改写和正常返回域；同地址不能自动冻结成同值。ROM/fresh/NULL/fallback各分支与旧契约保持分离。
4. stt强对象3AD8有不同上游与替换/清空writer，不合并成任意成功JSON。四份来源为3AD0、36F0、218、190，各次原调用/retain/storeStrong及last-writer版本独立；尤其savedIMP构造与objc_msgSend来源不能混用。
5. 本轮局部顺序证书只能在各自入口和原table/index、正常进展、live/distinct cells、无额外alias/并发写条件下使用：51960C同次真实返回先F30后8A8；parser同次status先4A4后10A8并清lookup out；getter同次status先DF4后10A8，再复制实际lookup到2670。它们覆盖各锥全部原分支，但不能无依据把三个独立锥拼成同次entry路径、跨锥last-writer或实际授权成功。失败status不挑为0，getter失败本身不自动清空旧out。
6. producer间接index范围只能从原前驱、全宽writer及真实helper所有正常返回推出；保留未知地址写、调用及alias barrier，新增回边后重验。保守entry图接通不是条件已满足，更不是24B014已运行。sysctl相关helper的正常返回BOOL范围证明依赖原代码/表绑定、私有栈槽与ABI未受额外callee/alias写破坏；不认证sysctl失败缓冲区/副作用或正常返回必然存在。即使正常返回BOOL，也不证明它一定返回“未调试”，不得替换返回或跳过检查。
7. 23条原算法/序列义务仍保留：其中19条使用解释型indexed map、6条含显式Rec（重叠2条）。这不等于只剩6个问题；真实AES轮/密钥展开、原key/IV、外层输入反馈、任意长度、原hash31/空白扫描、浮点与失败guards全部保留。全2850式唯一变式查询仍UNKNOWN，不能用表示变化、范围证明或局部顺序证书生成AuthVerified。

## 本轮CF返回、stt对象与验证控制流修订（2026-10-16）

本节优先于后续历史推断。详见 `work/dgassistant-239-cf-stt-producer/CF_STT_AND_PRODUCER_2.3.9.md` 及其provider/stt/control子报告。继续三路只读复用GUI PID56134、MCP13338、session ae41be7e；不连接手机、不执行/模拟目标或系统库、不修改授权、不兑换。

- **UUID候选已越过CF入口追到真实返回。** 实际serializer的36个ASCII字符在`186FBF4FC` funnel走ASCII快臂，绕过DecodeByteStream；36>11排除两个短tagged返回。保留StringROM查询/命中/CFRetain，不假设必无命中。fresh分支`186FBFDA0`以实际allocator、type7、extra38调用_CFRuntimeCreateInstance；实际NULL经`186FBFDA8→FF00→FFD0→186FBFFE8`原样返回NULL，未填成功对象。
- 原fresh非NULL/native候选在实际flags/CAS域下，object+16写长度36、object+17拷贝原36B、object+53写NUL。实际`-[__NSCFString UTF8String]→CFStringGetCStringPtr`在当前全局编码/原类/PAC/存活条件满足时返回同object+17；**0x600是CF ASCII，不是UTF8**，其对0x08000100请求的兼容门已落实。直接取指针失败会转动态super候选_bytesInEncoding，原getBytes/分配/长度不符/NULL失败最终也可返回0。46项局部反例UNSAT不等于实际constructor/ROM/allocator/活跃IMP已成功，尚未新增同852返回等式。
- **stt的root不是任意成功JSON。** frame3908保存的是原out-cell地址（84DF0C），不是独立树；`8467C4`取该地址，`8467CC`先置NULL；`8467D0`取原cell8B0的C输入，`8467D4→3E8794→3E2704`实际解析，返回status写4A4。C输入上游为cell3AD8原对象经`836F60→8960B0→8960A0→51960C`，实际返回的原writer/指针身份链为F30→8A8→8B0；同一可达路径上的last-writer顺序尚未证明。parser wrapper真实`3E89EC/F0`检查status==0，false直`3E8AA8`返回实际status、不转发临时root，只有成功臂才经原identity转出。未把NULL out或失败status替换成有效树；另一初始分派可先执行3E8BDC core，未合并为同一次调用或假定不存在。51960C还补到实际Base64/options0、length、malloc(size+1)、UTF8String及7F5C98输出缓冲身份；51A904/51B49C的NULL返回writer照实保留，未把整个转换算法当作已验证解密JSON。
- 原getter`8456C8..DC→3E8BF8`从3908所指同一out-cell读回原root，按实际键指针1014D0797取字段；“stt”字节结论依赖原初始化臂，不冻结可变键全局。getter要求root.tag==4；wrong-type原-2、未命中原-3、命中才写实际values[index]及status0；-2/-3失败臂不执行match out-store，也不自动清空10B8，可能保留先前输出，不能推出NULL或数值0。随后才是原tag2 double→round/FRINTA→FCVTZU64→low32，经第二callback sext32消费。该值仍不是ct/endtime或直接本地时钟。调用者status还会转写实际cell10A8；写状态不等于已找到其后立即拒绝/接受的消费分支。
- **验证producer补了全代码inventory，不能冒称完整已解CFG。** 63137C共253620B/63405指令/2198 canonical块；80B9CC共314272B/78568指令/2051块。原table来源、直接边、局部BOOL/常量索引按原字节列账，但各仍有103处跨块索引未证范围的间接边；table候选边也保留实际运行时绑定条件。最相关open精确为64E7E0/index读frame+AB3C和8536E0/index读frame+A4CC，各唯一显式W32 writer来自同块前载值，另613/504个未知地址写站点仍有alias义务。不强加0/1范围、不以成功status连通completion；原entry到实际验证/完成frontier仍须完整数据与控制证明。
- **不只列完成端，已补出真实nil拒绝锥。** 643704真实retain返回的nil判断→原frame2178→table10157A268[1]6433C0；两段原opaque index在同一实际全局字节表达式下反例UNSAT、恒0，接654E38→66A0BC调用493800。callsite没有重新装X0/X1，未补参数或从前次nil推寄存器值。随后667210起20块本地控制锥0未解、到66BCE4 RET，不含65DF8C/65DF98原completion；四处BLR按原GOT为objc_release。另有dispatch_after，deadline取cell35F8/35D8、原mainqueue及global blocks100B97BB0/100B97BF0；只证明提交，不说已执行、已退出或全程序绝不会回调。
- **37条递归确有缩减。** 原同一852边、428调用、986条件及五桥587/607/731/748/779全部保持。15个首NUL应用实际index均0，按有限序列一般归纳精确改写为原同字节输入的IndexOf/SubSeq；未选NUL位置、输入长度或返回值。含Rec条款37→23、显式Rec应用28→13（真实AES-CBC6、outer2、hash31四、外层空白1）。28项任意字节有限回归全UNSAT；两项一般SMT证明UNKNOWN如实保留，一般等式依据明确归纳，不冒充全自动证明。
- 对这一实质变式只作一次完整联合查询：原986+provider1856，再保留全部9条FPA2BV结果共2850式；配置8s，实测9.977s返回UNKNOWN/timeout，无模型，无成功替身，也没有重复旧同式查询。23条剩余Rec条款已按原编号和家族逐项存档；浮点与真实外部语义仍未消失。

**有效缓存经24B014到管理主界面的真实可达性仍未认证，也未证明全局不可达。** 目前已有真实CF正常/失败返回、实际root解析/字段错误分支和完整代码清单；剩余不是“随便选个成功值”，而是活跃provider/CF返回绑定、stt外层对象/解密返回与status消费、完整验证producer间接边、同次三回调及对象生命周期的联立缺口。完整性PASS只验证证据，不是授权或UI成功证书。

### 新App授权与启动契约：真实来源与失败分支

1. 保持实际provider对象、嵌套constructor、返回字符串与后续字节视图的同一来源。原UUID producer输出36个ASCII字符并不证明NSString/CF对象实际构造成功；ROM命中、fresh分配NULL、动态fallback、编码全局重算、CAS重试、PAC/异常与生命周期分别保留。不要用预期UUID字符串或“constructor成功”开关填补返回。
2. 若实现本案已核的原fresh CF候选布局，长度字节、payload及NUL分别位于object+16/+17/+53；这不是跨系统版本通用对象布局。0x600是CF ASCII，0x08000100是UTF8；原直接读取兼容门与fallback失败返回0必须区分。新App应通过正常公开字符串API管理生命周期，不复制内部布局来规避验证。
3. 第二验证的stt输入是原对象经51960C返回的C输入，再经原parser产出的root及原getter；不能把任意JSON、ct/endtime或本地时钟替代它。F30→8A8→8B0是原writer/指针身份链，尚未证明同一可达路径上的last-writer顺序。3908保存原out-cell地址、该out-cell先置NULL；parser只有实际status==0才转发临时输出。root.tag不符的-2、key未命中的-3、数值handle tag不符的0和NULL/无效指针解引用不是同一种失败，不合并为合法时间0。
4. 上述helper的失败语义不自动等于调用者必定立即退出：实际status写入与转发须继续追到真正消费分支。getter的-2/-3本身不执行match out-store，也不自动清空10B8，可能保留旧输出；不得自动补NULL或0。完整验证producer未闭时，不能因“字段存在”“state222已写”或“控制表有一条目标边”生成AuthVerified；三次回调各自q、全局和时钟样本仍须绑定同次状态。
5. 验证完成与UI提交保持原三阶段顺序。24B014是第一回调，不是已验证的缓存入口；24B8F4、24BFB8后才涉及提交24CBB8及管理界面。不得把852条选择路径、九个必要门、两个全函数CFG inventory或局部CF返回证明当作完整可达性；520仍不是已证本地等待开关。
6. 首NUL改写仅改变数学表示：原986条件和五桥不变，15应用均原index0，未选NUL位置或限定明文长度。剩余23含Rec条件、13显式Rec应用及浮点/真实API/完整控制流仍未闭合；变式2850联合查询UNKNOWN，不能据此生成许可证、迁移为“授权成功”或声称离线验收通过。

7. 原nil拒绝侧存在真实无本地completion的20块收尾锥，但其中异步watchdog必须与当前返回分开：dispatch_after提交不等于立即执行/退出，不据此承诺全程序永不回调。493800 callsite未重新装参，不能补零参数。两个producer最相关未知索引来自frame+AB3C/+A4CC的原前载/转存，还须原writer宽度、别名和控制条件证明，不能凭table两槽强塞BOOL。

## 本轮构造返回、520与完成参数修订（2026-10-16）

本节优先于后续历史推断。详见 `work/dgassistant-239-return-consumers/RETURN_CONSUMERS_AND_PRODUCERS_2.3.9.md` 及provider/consumers/completion子报告。继续只读复用GUI PID56134/MCP13338/session ae41be7e；不连接手机、不执行或模拟目标/系统库、不修改授权、不兑换。

- UUID嵌套DG wrapper已落实：37D984以self/_cmd/bytes/length/encoding五原参调用当次load64(1015EC400)。saved IMP有四处紧接method_getImplementation的写入，不能冻结为原系统constructor。37DA20首门恒false；37DA80第二门精确为32位(U−V)bit26，false真实回环重采，true才走正常返回。返回追到原saved IMP及ARC调用/栈槽，不用成功对象或无条件终止替身。
- NSString class-cluster候选分支可返回原NSPlaceholderString单例，其自有initWithBytes:length:encoding:不必经过NSString基类hook。旧“同名selector重合”不能提升为UUID本次必被拦截。候选路径实际encoding4→08000100 UTF8→CFStringCreateWithBytes，参数来源已核；惰性class cell、活跃IMP/类、CF funnel最终返回和UTF8视图仍未闭合，未新增端到端返回等式。
- byref原metadata明确为flags0x20000000、size32、forwarding+8、W32 payload+24初值2，不是flags0。copy/dispose原helper与实际libsystem_blocks已联接；初次promotion将payload区域8字节送真实__platform_memmove，后4字节不是已知零。copy可能先于写520、搬的是初2；已heap assign仅refcount。不能据搬迁就说读到了520或已唤醒等待。
- 有界消费图排除了本地“读520后才显示UI”解释：24B8F4共12处X21使用，无payload load；63137C正常返回后只有dispose/CFF/return，无wait/signal。第三callback原接受分支先写520再直接提交只捕获self的mainqueue UI block。未找到数字520业务消费者，不等于证明全程序无别名/异步消费者。
- 第二完成W2来源是实际对象的stt tagged handle：tag==2时读double+8，经round（本地真FRINTA ties-away）→FCVTZU64→low32，交24B8F4再sext32；非numeric原分支返回0，NULL/坏指针不是这个分支。**不是tz0111ct/endtime，也不是直接本地时钟。** 另一独立CFAbsoluteTime采样经epoch与FCVTZS64参与比较，绝不合并。
- 完成参数产出前沿已补：第一/第三65E354写C0C=52，65E378实际FD8参与signed q/3+111+FD8再保存W1；第二83B020写C18=222、signed q/7+55保存W1，stt低32保存W2，经84B738..48调用。q1/q3来自实际arc4random occurrence→LCG32(1664525*r+1013904223)→unsigned mod90001+10000的条件正常返回；q2另是arc4random_uniform(90001)+10000，不互换各次采样。
- 37条递归继续按真来源细分：两个实际hash<10**16推得对应3EA174 key最多16位，剪去八个不可能的高位包含分支；不选真实key值/长度。原852边/428调用/986式保持，仍37条含Rec条件、28个显式Rec应用。没有新的安全完整同态返回API，不为此小剪枝重跑旧完整2850超时；上轮UNKNOWN仍是最新完整求解结果，不能说本轮已重新求出。

**完整有效缓存经24B014到主界面仍未认证，也未证明全局不可达。** stt当前对象上游、完整getter/验证producer控制流、真实活跃dispatch/CF返回、各次全局与捕获生命周期仍须同状态闭合。

### 新App授权与启动契约：本轮纠正

1. 将业务验证、UI提交与Block生命周期分离；不要实现“等520解锁主界面”或“dispose就是signal”。原局部接受分支直接写状态并提交UI，UI block仅捕获原ViewController self。520暂只能作为已知状态副作用，不是已确认的外部等待协议。
2. 若复原byref布局，保留flags0x20000000、size32、forwarding与W32 payload的区别；初次stack→heap搬迁8字节不代表520被消费，payload后4字节不补零。malloc/PAC/copy失败和已heap refcount分支不得用成功返回屏蔽。
3. 第二次完成参数须保留stt实际tagged数值类型与转换顺序：round-away binary64→unsigned64→low32→signed32扩展消费。不要替换成NSString.intValue、ct/endtime或本地now。getter状态失败、非numeric零分支、NULL解引用、FP异常/陷阱及源库版本绑定须分账，不能把全部失败统一为合法0时间。
4. 第一/第三完成W1和第二W1分别由实际q、不同FD8/状态writer产出；独立random/clock/global采样不合并。q1/q3的真实LCG+mod来源不是任意uniform成功challenge；条件正常返回公式也不是全部CFF已可达/终止。
5. 嵌套NSString构造须按实际类/IMP查找；仅基类hook同名不意味着placeholder自有方法被拦截。DG wrapper真转发仍可能在第二门循环重采，saved IMP可被重写，CF funnel结果未证前不能赋预期UUID字符串。
6. 两个实际key的1..16位范围只是原hash归纳不变量的消费，不是选择成功key或任意限制许可明文。剩余37条递归与真实API/producer必须联立；缓存非nil、局部算术正确、状态52/222写入或UI代码存在都不能生成AuthVerified。

---

## 本轮外部语义、递归与主界面链修订（2026-10-16）

本节优先于后续历史推断。详见 `work/dgassistant-239-external-closure/EXTERNAL_SEMANTICS_AND_UI_2.3.9.md` 及 provider/recursion/callback 子报告。本轮仍只做静态，未连接手机、执行或模拟目标/系统库、修改授权或兑换。旧session19918359已失效；复用同一GUI PID56134/13338，新session为ae41be7e，未另启IDA。

- provider真实格式实参已纠正：3BE7F8从frame+5A8取build C指针，3BE814分配原SP空间，3BE81C写入实际栈槽，3BE828的stringByAppendingFormat:消费该%s vararg，不是X3。原UF签名含memory，但缺显式SP/vararg消费语义；本轮补观察来源，未伪造格式结果。
- 原系统候选__NSConcreteUUID.UUIDString读取receiver+8的16字节，经共享cache真实ADRP/ADD/BR跳板186CE8260→18E5A6ECC uuid_unparse_upper，生成36个大写ASCII字符与NUL。**这不是端到端UUIDString返回UTF8证明**：随后stringWithUTF8String:动态调用initWithBytes:length:encoding:（W4=4），该selector与DG历史替换目标重合。候选返回等式已撤下，未加“构造成功/未修改”替身。
- %lld的512字节token上限有真实本地libc指令依据，不是任意截断。保留原locale/库绑定/指针及域外结果后，重复inner whitespace折成0，digits完整展开512步。852边/428调用/986式保持；显式Rec应用30→28，**含Rec条款仍37**，六次真实AES-CBC、两次outer、四次hash和NUL等未删除。
- 下游原链已到具体主UI：ViewController.viewDidLoad@24ABD0的self经24AC64及各block+32传到24B014→24B8F4→24BFB8→主队列24CBB8。第二回调有独立q2/7+55、真实64位时间窗口及C18=222；第三回调分别保留两次helper、各次FD8、C0C=52和原非调度/回环分支，不能把它们填真。
- 24CBB8的管理界面不是更换rootVC：24E21C分配UITableView，24E260 style=2，24E278 setTableView:，同原self为dataSource/delegate，24E468加到self.view，24E8FC refreshData、24E90C stts。byref经forwarding+24写520是状态写，不是已证semaphore_signal；实际等待消费者仍缺。调度提交、原self来源和UIKit调用链均不等于真实成功事件。

完整新表示同次联合查询：2850式，结果UNKNOWN；仅因真实512-token展开/重复空白折叠才执行这一次新查询，未重复旧同式超时。provider仍有1856条条件source/memory契约；未新增UUID返回内容式、未强制route/成功域、未取模型。**有效缓存经24B014到主界面的完整真实可达性仍未认证，也未证明全局不可达。**

### 新App授权与启动契约：本轮增量

1. 旧App是已有ViewController/viewDidLoad self的窗口壳，经异步worker和三阶段验证，再在mainqueue向同self.view添加管理列表。不要将其重建为“激活后必然换rootVC”；原对象存活、block复制/生命周期、真实调度与消息成功仍须保证。
2. 第二回调使用自己的q2、完成W1/W2和后一次CFAbsoluteTime采样：原精确门是ULT64((sext32(W2)-FCVTZS64(D0+epoch)+22) mod2^64,45)且C18==222；只有普通不溢出域才可解释为±22秒。第三回调的不同helper/FD8/C0C读不得合并或用零/预期token代替。
3. 主界面承接点是配置UITableView(style2)、同self数据源/代理、addSubview、搜索/刷新并调用refreshData/stts。byref520写入不授权解除等待；没有实际消费者证据前，不实现为已确认旧协议的唤醒信号。
4. provider UUID路径须区分“实际16字节序列化C缓冲”和“嵌套NSString构造后的返回对象”。当前后者有真实动态替换边界，不能直接信任非nil或系统方法名。%s必须从同次真实SP槽读取，保持NULL、编码、异常及格式化失败，不赋固定build/UUID。
5. %lld的512只是版本化libc的数字token宽度，包含符号、排除前导空白，不是整个许可明文的最大长度。仍须保留外层无界空白、真实输入/符号、溢出饱和、assignment count、原out-cell失败保持及原域外行为。
6. 这些静态合同尚不是可直接宣称旧授权互通的完整实现；缓存非nil、组件局部证明、dispatch提交或UI构造代码存在均不足以产生AuthVerified。真实解密/unpad、设备/时间、provider实现、完整完成producer及回调路径仍必须同状态成立。

---

## 本轮同状态来源、递归与浮点修订（2026-10-16）

本节优先于后续历史结论。详见 `work/dgassistant-239-state-link/STATE_LINK_AND_REACHABILITY_2.3.9.md` 及 provider、recursion、solver 子报告。只读复用13338 / PID56134 / session19918359；未连接手机、执行目标、修改授权或兑换。

- 慢provider已接到原852边状态中真实638E48第0次调用：继承实际寄存器，按原prolog派生栈帧，再追3B8538→87F820→87F810→43301C及内层UTF8String/strlen/malloc/memcpy原实参。最终采用写B028的生产路线；旧路线虽经过hash却读回旧B028，已弃用，不能把“出现hash调用”当成其产物最终返回。
- 新padding使用同次post-malloc内存的Store/Select链，每次STRB后分别读取D74D0/D4，不再以71对自由输入代替全局；真实+1/+2步进、未写malloc旧字节和末尾低32长度覆盖保留。不冻结文件初值、不assert全清零、不选块长。单块长度和私有栈/可读写域只是组件适用条件，不是新增授权门。
- 原982式加4条真实hash31归纳范围为986。精确折叠后重新按依赖分组，最大分量503含499条原编号式和全部4条范围引理，不是“原501简单加2”。实际十进制key的所有1..20长度域允许精确折叠；原38条含Rec条款现为37，仍含30个显式Rec应用及30条解释Seq条款。7类一步展开与原定义body机械身份一致，递归尾项、实际AES/输入、%lld扫描和失败返回均保留；未换成自由输出UF。
- 浮点621真实来源是6628D8的_CFAbsoluteTimeGetCurrent第0次调用，经6628DC保存frame24B8，再641BBC加978307200.0，641BC0为FCVTZS X8（64位，不是W8）。该结果仍有7条位片/内存重组活用；不能只证明最终数值转换就删掉原FP。保留全部9条FPA2BV转换式及NaN辅助解释，不固定时钟、FPCR或NaN成功值。
- 完整同态分量的新表示和原body一步展开查询仍UNKNOWN；局部证明、纯等式必要子集SAT均不能认证完整501、有效缓存或24B014。provider source/memory仍有明确扩展契约和外部调用未闭合，不能把新命名UF包装成真实实现已还原。完整callback CFG与主UI续执行仍未证，也未证不可达。

### 新App启动契约：本轮补充

1. provider应以每次实际调用及实际对象为单位，保存其来源、状态与错误；区分计算新产物后写B028和读取旧B028。栈帧须由原调用SP派生，不能重置为独立成功态。原App其余provider调用并未因本轮首个调用的展开而自动闭合。
2. UTF8String的实际C指针、含NUL内存视图、strlen、malloc与memcpy必须同次绑定。padding每次从当时内存读全局，保留原步进和malloc旧字节；组件normal-domain与64字节分区不得作为实际授权接受条件。NULL、分配/编码/解析失败不能转为空串或已验证授权。
3. 真实十进制key无NUL/长度域和hash31范围只是可复用的原算法不变量；仍须完成原Base64、外层解包、AES、unpad、设备一致性与时间判断。%lld必须消费实际明文及真实out-pointer/status，不能赋预期时间值。
4. 分开记录CFAbsoluteTime与其他独立时钟采样。这里加978307200.0属于该次时钟基准转换，不是服务器endtime的来源证明，也不能与另一NSDate或ct采样合并。保留原64位转换与实际FPCR/非陷阱适用条件；NaN数值局部定理不是可用授权状态。
5. 现有AuthVerified→续执行→主界面的兼容实现仍不完整。新App不得仅凭缓存非nil、局部SAT、provider条件桥或callback布局解除等待/进入主界面；待原解密、设备/时间、状态和完整callback条件均被真实来源证明后，才能声称沿用旧授权互通。

---

## 本轮对象字节桥与provider填充修订（2026-10-16）

本节优先于后续历史结论。详细新增证据：`work/dgassistant-239-byte-bridges/BYTE_BRIDGES_AND_PADDING_2.3.9.md`；子报告见该案bridges、provider、solver目录。只读复用13338 / PID56134 / session19918359；不连接手机、不修改授权、不兑换。

- 五条桥的实际对象/别名/编码4及下游已落实：两次独立文件NSData→各自NSString/UTF8String→原外层解包→各自C串构造/UTF8 NSData→plist；ct的65C494 ACPDS→656244编码→66189C JSON。两次同path读回不合并内容，nil字节不当空串，UTF16单位数不当UTF8字节数。
- 原BV/UF绑定可推出748@65659C、779@656244的非nil guard；前三个guard仍须条件化。非nil不是合法明文或授权成功。五份原anchor全部保留，仅作已证guarded同值替换，11份受影响公式同context反例UNSAT，不添成功返回。
- 462条必要式的纯Seq等式子语言经机器检查可一致转换EUF表示，约3.57秒SAT；3份UF签名和全部共享BV对象/guard/q/global保持。完整501因真实Rec/解释Seq/FP被明确拒绝翻译，等价归一化查询仍UNKNOWN；不能用462的SAT认证实际字节算法或整链。
- provider原strlen与padding已推进到同来源C字节、长度、分配/padding和LE消息字：末尾只STR W写bitlength低32；原清零循环有依赖逐次全局采样的额外步进。全清零normal domain只是组件适用域，不是原授权新增拒绝门，不固定全局、不选择自由N/摘要/route，也不直接套标准MD5 padding。
- 两个原stack block构造臂24AE80与24AFB0均指向24B014，实际q/capture writer及63137C入口保存已核原字节；未注假block。24B608转80B9CC仍是下一验证，不是直接主UI。**真实有效缓存到24B014/等待恢复/主界面的完整可达性仍未认证，也未证明不可达。**

### 新App启动契约：本轮限定

1. 保留每次文件读取、NSString/C串/NSData、plist/JSON的对应对象与错误；同路径不是快照。Foundation具体异常、编码/分配失败和不可变性仍有实现域，不能从类名或指针相同推广。
2. 已蕴含的两个非nil guard仅是原约束引理，不能充当VerifiedGrant；ct短输入可能返回非nil错误字符串。原nonshort、解密/设备/时间和结构解析必须仍成立，前三个guard不得填真。
3. provider接口必须由实际同次UTF8String C指针及含NUL内存视图、实际长度/分配实参和原全局采样驱动。无NUL、NULL、分配失败不转空串或成功。padding正常域和固定块数是分析分区，不是已确认原App接受/拒绝条件。
4. 462等式子语言只用于精确表示诊断，不可替换完整501中的AES/扫描/长度递归与FP；形式组件和局部SAT不是完整旧许可互通实现。
5. 两处原block构造的+16 invoke、+32实际对象、+40实际W0与原入口q/block保存是有条件布局契约，不是capture生命周期/全局跨采样一致性证明；恢复等待链不得仅凭非nil、接口布局或局部SAT发生。

---

## 本轮AES真轮与约束分量修订（2026-10-16）

本节优先于后续历史结论；完整新增证据：`work/dgassistant-239-core-closure/CORE_CLOSURE_2.3.9.md`，三路子报告为该案 `aes/FINDINGS.md`、`provider/FINDINGS.md`、`solver/SOLVER_PARTITIONS_2.3.9.md`。只读复用13338 / PID56134 / session19918359；不连接手机、不修改授权、不重新兑换。

- AES轮、密钥展开与实际mode descriptor目标已补原字节。新完整表达式接入同一852边、六次ACPDS，旧AES结果UF不再被其CBC关系引用；原key/IV/cipher来源及失败保留，真实系统绑定仍有版本适用前提。
- 慢provider的22是与sysctlbyname("kern.osversion",...)同buffer配对的strcpy预填常量，不是已观测系统版本；五组先后路径未全证。4319E8可由uname及UIDevice.systemVersion产出版本片段，-520-仅fallback，不能固化旧替身-520-22。OC/C两路日期必须分开。原64轮压缩/四字feed-forward已展开为定义绑定；消息padding、完整来源和slow route仍未闭合，没有通过自由digest/route伪联立。
- 原982条件完整拆为448个共享声明分量；初检445 SAT/3 UNKNOWN，两个小分量精确复核SAT，最大501分量全绑定15秒仍UNKNOWN。旧74条无前提恒等证书中新版仅73条哈希匹配，可等价化简为909条；它们不在最大分量，不能冒称已解决其瓶颈。
- 最大分量457条BV/UF必要式SAT，加回五条对象/byte/Seq桥后462条仍UNKNOWN，已定位662998、649C10、667D68、65659C、656244的桥定义及641BBC的FP条件。不得删桥、独立返回或把必要子集SAT当全式SAT。
- 五个回调/状态全局均writable；direct xrefs不能排除间接writer，不能固定文件初值来通过opaque-progress。24B014仍是原caller布局及必要门接口，不是本轮真实回调/UI事件。**未证明真实有效缓存必达24B014/主界面，也未证明不可达。**

### 新App可沿用的契约边界

1. 只有真实合法响应/缓存经过完整设备、时间、解密和状态校验后，才允许恢复等待链；不得把本案局部SAT、超时、非NULL或一份字段存在当成功。保留原短输入/Base64/UTF8/分配/CCCrypt及来源失败，原外层options0与ACPDS options1不能混同。
2. key与IV来自原两次独立getCString写入；不因同一源对象就假定两缓冲区写入相同或成功。新AES表达式不提供授权密钥/明文，也未重加“严格检查全部PKCS7尾字节”的错误门。
3. 设备产出需绑定每次实际provider来源和fallback：真实版本片段、kern.osversion写后C串、两路独立日期、原四字序列化；不能使用固定22、-520-、自由设备ID或未绑定摘要。64轮压缩接口尚不构成完整可投产provider。
4. 原65DF98完成调用前的X0/X1/X8、block+16=24B014、+32控制器、+40 q，及SDIV32(q,3)+111+当次FD8和1014C2C0C==52只给必要接口。各次q/FD8和可写全局的读取/时序不能无证合并。24B4C4死返回不是新增授权门。
5. “有效缓存必达主界面”的强契约仍需补齐真实缓存/系统/Foundation产出、slow route与padding、全局时序和回调等待恢复CFG。本轮不生成、伪造、修改或重新兑换授权，不提供放行失败的实现。

---

## 本轮算法产出与同状态联立修订（2026-10-16）

[本轮真实库字节与联合约束报告](../dgassistant-239-algorithm-bound/ALGORITHM_BOUND_STARTUP_2.3.9.md)优先于历史正文。3个子智能体复用只读IDA13338/PID56134/session19918359；未连接手机、运行或仿真目标、改授权、兑换、导出模型/密钥/有效许可，不用成功替身。

1. **原外层字节已接到扫描输入，不再是独立解析返回。** 冷852边同状态中展开6B2BB4反馈/ROR3、3EA174十进制key文本及实际strstr/strlen关系；65DA94原指针经可证明的字节重组恒等式，关联到strstr返回+12的同一解包字节后缀。范围/内存fallback仍保留，实际文件字节未观测。六次ACPDS而非原重点四次均保留原cipher/kaiv/输出身份。
2. **找到并核对真实候选libc字节。** 本机20D67标记libsystem_c的5完整函数与拆分缓存同字节；链为_sscanf→_vsscanf_l→___svfscanf_l→_strtoimax_l。实际%lld整数token最多512字节、符号占额、前导空白不占；signed溢出饱和并写errno34，scanf不读该errno，仍写64bit和返回1匹配。旧两个UNREDEEMED scanf UF不创建，23项数学测试UNSAT；locale/合法内存/INT_MAX长度域未全局假定，未认证手机实际加载版本或完整机器等价。
3. **撤回严格PKCS7必要成功门。** 真实CommonCrypto/corecrypto代码并不支持把“全部尾padding字节均相等”直接设作ACPDS非nil必要条件；末字节helper只做范围掩码。已在最终联合查询前移除过强门，实际unpad仍绑定同一padded字节而不选成功。后续只读v3 slide header/页链补证AUTH槽1E2376EF0静态目标为1D50E7CDC，并接到corecrypto解填充；这是冻结求解后的证据补充，不回填算法已展开或runtimePAC成功。-4303为AlignmentError，不能误称DecodeError（-4304）。这也不直接证明DG接受坏授权。
4. **provider与24B014条件纠正。** 原provider有4处53B8调用发生点；快缓存检查3B77A8/BC后，真正返回在3BCA54再读B028，不能当原子快照。11次原provider实际返回只加有条件缓存接口，未强选fast、未填设备ID；慢路径完整产出仍开放。24B4C4 helper返回不参与授权比较，不能新增一门；真实四条数据门、原失败返回、opaque进度回环及helper最后FD8采样均分别保留。
5. **真正提交一次同状态联合查询。** 852原边、428调用、0未知opcode，在全部原条件/定义之外加入扫描、解包、11provider关系与原caller/24B014必要条件；去掉99重复AST引用后982条件，30.690秒返回UNKNOWN(timeout)。五个block/q/payload/invoke/52局部等式仍UNSAT。caller布局为原字节接口前提，不注入假block；该查询不是完整callback CFG或UI事件认证。

八个getter标签由同次冷初始化落实：CB600=tz0111cs、CB640=tz0111cc、CB680=tz0111ct、CB6A0=tz0111cst、**CB6C0=tz0111cst12（不是cc2）**、CB6E0=tz0111udid、CB720=tz0111udidd、CB740=tz0111cc2。字段名明确不等于这些字段已通过校验。

**当前边界：** 原608候选仍被拒绝为有效解码路径证据；本轮新增真实字节/算法关联不靠旧SAT续证。完整AES轮/密钥展开、getCString/Base64/UTF8/解析真实产出、文件/设备输入及慢provider、环境与跨采样一致性仍未全兑现，真实有效缓存到24B014/主界面未认证；不将条件数、字节数当整体完成比例。

DG本轮174区间长度和121011字节、去重118343；新增去重71447，累计去重319144原文件/IDA一致字节。18个外部库函数13408代码字节及表单独核，不混入DG/IDA计数。六份原稿完整备份；冻结子报告和旧UNKNOWN保持原来源/版本边界。

### 新App契约本轮增量

1. 同一LaunchContext保留文件版本、解包字节、实际对象及q/block/采样；tz0111cst12、ct、cc2不可合并。扫描必须消费同源字节，不以任意匹配状态/未来时间补链。
2. 若要求兼容此候选旧libc，明确512token、signed饱和、失败保留和溢出仍写回；采用更严格现代解析/拒绝溢出时作为安全行为变更验收，而非宣称完全旧兼容。
3. 新协议可严格校验padding并独立验签，但严格PKCS7不是已证旧接受域；不能以错误文本非nil、status替身或单个局部门满足就创建VerifiedGrant。
4. provider宜使用明确不可变快照；旧两次重读/慢fallback/FD8生命周期需要独立兼容测试，不沿用固定设备ID。第一回调只保留真实数据门、状态门和原opaque进度；不添加死helper门、不伪造回调或手写52。
5. 真实输入及剩余算法/状态条件兑现后再恢复等待链；当前交付的是接口、依赖与错误契约，不是完整旧授权互通证书，也不生成许可证或绕过补丁。

---

## 本轮同状态静态接链修订（2026-10-16）

[本轮852边同状态原字节报告](../dgassistant-239-state-bound/STATE_BOUND_STARTUP_2.3.9.md)优先于下方历史正文，三路子智能体与父审共同复核，只读 IDA 13338 / PID 56134 / session 19918359。未连接手机、执行/仿真目标、修改授权或兑换；没有成功返回替身、模型或有效缓存导出。

1. **前态与正桥已实接，而非分别设成功对象。** 新 `cold_fused.py` 在同一静态寄存器/逐字节内存状态中传播冷入口5 + 首缓存前置234 + 首缓存时间180 + 第二次非NULL桥10 + 设备/一致性/原completion423 = **852条原边、428次调用、0未知opcode**。所有原分支条件仍待同链兑现；0未知opcode不代表Foundation/AES等真实结果已展开。
2. 首缓存 `6499C4→662334→63EFF8→64E724` 的字典与 `6451F4/frame1F88` 保持同对象；不能用后续 `643A48/6468AC/65C804` 代替首次读取。纠正最短CFG两种错误：期限拒绝臂原本通清理；另一捷径要求同一次decoder同时NULL/非NULL，两条原分支即UNSAT。正确路经原 `%lld` 扫描，`88C6F8`把X2输出指针送SP首变参；扫描状态1才写，失败保留旧值。解析算法/状态仍未兑现，未选成功值。
3. `6313A4→66A138` 的原冷初始化自然写出 `%@` 两字节 `25 40`，在后续 `6389E0` 同状态guard=True；BSS初始化flag保留原分支条件，未强置零。只读 `100AE7F90` 原字节 `00000040e427cd41`（978307200.0）绑定原FADD/FCVTZS。封存847边运行中guard=False是缺冷前态，不是App实际格式错误；四个历史UNKNOWN也未回填成新852边求解结果。
4. `63F9BC index1→64161C→65EF58→65659C→65C804` 的真实非NULL桥五项身份在同一状态成立。第一plist `63EFF8`、第二plist `65C804` 和原JSON IMP `66189C` 分开；CT/CB6C0、四次ACPDS、hash31/NUL比较、日期和设备provider按实际对象及occurrence相联。不冒称未知CB6C0就是cc2，不把关联操作项当实际明文。
5. 原 `65DF98` 前五个局部等式的否定均UNSAT：X0为原block、q单元为原q、W1为 `SDIV32(q,3)+111+65E378晚采FD8`（32位）、X8读取原block+16、原C0C出口写52。原caller `24AE80/84` 的block布局接口指向24B014；没有伪造block内存或执行回调。24B014自身复算、状态复核及FD8再采样仍是后继条件，不等于直接显示主界面。

**证据边界：** 旧608边候选继续为 `REJECTED_AS_VALID_DECODE_PATH`；旧847边四阶段联合查询仍是历史UNKNOWN(timeout)。新852边只做当前源码同状态传播、常量兑现和局部证明，未新跑全链SMT。真实Base64/缓冲区/AES/UTF8、扫描、Foundation解析及设备源仍未全部兑现，因此“有效缓存到24B014真实可达”和“旧授权完整互通”均未认证；不再用18/77、59/77或边数推算整体完成百分比。

本轮293区间长度和78036字节、去重77594，新增去重37746，累计去重247697原文件/IDA一致字节；六份写前原稿完整备份。字段/回调子报告封存的847边记录不改写，由新cold852报告限定当前补充。

### 新App启动契约本轮增量

1. 单一LaunchContext保存q、continuation、文件版本/解析对象、设备和日期occurrence。首读和第二读即便路径相同也不得视为同次快照；不可用任意成功字段填补前置链。
2. 非NULL解包必须顺经真实NSString/NSData/第二plist桥，逐层处理NULL/nil、错误文本、类型、扫描写效应和解密状态；不以length>0或status替身生成VerifiedGrant。
3. CT的解密字节、intValue、hash31和设备比较保持同源，保留signed32/unsigned64与FP舍入/2038边界。新Int64解析或显式格式初始化属于明确行为改进，不承诺错误输入逐字节旧兼容。
4. 实际输入及所有原校验兑现后才允许状态机恢复等待链；原C0C=52与payload只是出口副作用，不是新App可手写的授权或token接口。consumer重采全局及24B014自身复核不可省略。
5. 目前可沿用已核接口、依赖和失败契约；完整旧缓存互通仍需真实算法与同链输入验收。该契约不提供密钥、激活码、许可证生成、伪造回调或绕过校验的实现。

---

## 本轮子智能体并行复核修订（2026-10-16）

[三路原字节复核与纠正](../dgassistant-239-parallel-audit/PARALLEL_AUDIT_2.3.9.md)优先于下方历史正文：**撤回旧608边候选作为“有效缓存成功路径”的证据资格**，不再仅写“缺动态见证”。原6468AC解包返回，经65DD90/94/98形成非零索引；63F9BC旧候选选择0到656580，明确要求返回NULL。原641D08写零到另一NSString单元；从真实66A138初始化复核后，frame2910与24F8相差16字节、不别名，65659C编码接收者仍为nil。旧SAT与完整历史JSON保留，不证明这一条是真实成功路径；也不据此断言整个App合法授权不可达。

已补出非NULL原分支：63F9BC索引1→65BB7C→657674→64161C stringWithUTF8String:→65EF48 retain→65EF58写frame2910→65659C编码。具体参数/保存点有原字节，但整组CFF条件及真实解密输入尚未联立，UTF8返回不能替换为成功对象。首次reader的6499C4/662334/63EFF8等不在608候选中；后续643A48/6468AC/65C804重复读取解析确实在，不能混成同一次前置闭环。

6389E0原清单误标为block调用，实际是NSString stringWithFormat:（CF1014CB820、首栈参数来自frame34B8），不是24B014证据。38个字符串门已按来源归组、找到2组严格同参range身份；这不是新增许可通过，不能从旧59门机械扣减。CF1014CB6C0字段名仍未证，不擅自等同tz0111cc2。另补65542C原表常量后继到66A138；FD8有直接写入及多调用生命周期，不能假定零或跨采样稳定。

上轮458项FP/整数局部定理及明确输入子域的数值同源关系保留；18/77与59/77仅为旧候选清单口径，**不是整体进度或剩余工作比例**。本轮123个锚点长度合计13692字节，去重13236，其中新增5644，累计去重209951字节；六份写前原稿按哈希完整备份。只静态，未连接手机、执行/模拟目标、改授权或兑换；有效缓存到24B014及同次UI闭环仍未认证。

### 本轮启动契约纠正

1. 解包C指针、NSString、NSData和解析对象逐层保留真实身份与失败值；NULL解包或nil转换不能靠独立成功返回继续生成VerifiedGrant。
2. 非NULL分支先经stringWithUTF8String:并写回真实对象单元，再交编码/解析；静态正桥存在不等于真实许可通过。
3. 首次解析与重复读取分别绑定文件版本和对象前态；不能把后续同名API当作首次缓存条件已兑现。
4. q/block与共享状态采样一致性分别验收。52是原成功出口副作用，不是可手写的激活接口；第一回调仍有自身复算，后继不等于即时主界面。
5. 沿用已核接口/失败契约可以继续；旧授权完整互通仍需真实输入与完整条件链，不用旧608候选或门数比例替代。

---

## 本轮FP分段证明与真实输入耦合修订（2026-10-16）

[本轮逐字节与数学证据](../dgassistant-239-fp-partition/FP_PARTITION_REACHABILITY_2.3.9.md)：4处FCMP、2处FCVTZS的求解超时已解决。458项分段反命题均UNSAT；全位向量对照求解约8.6秒，正常域约27.9秒，构建时间另列。用原表达式等式定义共享节点，不把新名字作为任意成功值。全位向量对照仅代表RNE/FZ=0的非陷阱数据场景；正常域等价证明覆盖四种舍入和相应FZ情况，未假定实际FPCR为0。

两份十位ASCII数字明文各自的intValue与原31哈希按同一字节计算，15次数值调用关系绑定，覆盖18个数值门，数值耦合检查约29.6秒返回SAT。它是明确输入子域，不是实际合法AES/缓存见证，CB6C0该形状也未被推广到所有producer输出。仍有59个输入相关门和实际文件/密文/设备/前置状态绑定义务；旧608边SAT不认证有效缓存到24B014真实可达。

FCVTZS应明确为向零并按signed32饱和的非陷阱数据语义，不是低32位回绕；NaN的数据结果为0，异常陷阱另论。正常有序时间达到2147483647秒后，该signed32严格大于门不可能通过，已独立证明。十位数字文本的真实哈希落在1311405259169280至1557293745263520，不把它当另一份到期时间。

### 本轮启动契约增量

1. 正常域N1/N2有限且0≤N<2^31时，六门可等价归约为：x>floor(N1)，y>max(floor(N1),floor(N2))，Hx>floor(N1)，Hy>floor(N1)。x/y保留signed32，H保留unsigned64；共享原N1并保留独立N2，不假定时钟不回拨。
2. 十进制与哈希由同一份已解密UTF8输入计算；实际密文到这些字节的验证不可由数值SAT替代。不得把十位文本子域测试升为所有记录格式的完整兼容。
3. 本轮两处FCVTZS不是整数回绕。显式设计非有限时间、异常和2038边界；若新协议用Int64修复，应作为行为/安全变化记录，不为兼容复制旧上界问题。
4. 静态验证分层：字节一致、局部语义、数值同源、全输入门兑现、原completion/24B014、实际UI事件分别验收。没有最后三层的真实输入证据，不产生VerifiedGrant，不手写52或伪造回调。
5. 既有脱敏响应外层/内层含截断，只有字段形状参考价值；本轮未用它充当合法缓存输入，也未复制其中凭据或key。全链真实可达性仍不认证，但原因不再笼统归为这六处FP超时。

本轮重新核对13段共360字节，其中320字节重合、40字节新增，累计去重204307字节；6份写前原稿已备份。仅静态、未连接手机、执行目标、改授权或兑换，未导出模型/授权材料。以下保留历史正文，旧FP超时状态由本节取代，历史实机证据等级不升级。

---

## 本轮具体解密、比较与浮点语义修订（2026-10-16）

[本轮原始字节与被调函数报告](../dgassistant-239-callee-semantics/CALLEE_SEMANTICS_2.3.9.md)：已逐项关联285次调用与77个相关分支。ACPDS:kaiv:的原IMP为16380，实际链为Base64 options=1→AES-CBC/PKCS7→UTF8；五处字段/kaiv对象不同，不能统一套用其他响应入口。CCCrypt经36919C转发时，11个ABI参数及32位状态均有静态相等证明，不换参数或伪造成功。

比较语义纠正：3AF36C是NUL终止完整匹配，等0/不等1；372154是strstr，560474是strpbrk字符集合搜索，不是另外两个相等函数。66189C已识别为1015EC3E8保存的原JSON IMP直接调用，不是未知block。

四处FCMP和两处FCVTZS已落实到原指令与NSDate D0返回：四处比较共享N1采样，另一次截断使用独立N2；signed32 intValue、unsigned64哈希和FP转换分别保留。旧IR没有正确关联浮点返回寄存器，旧608边SAT不能升级成真实callee条件下的全路径认证。一致性约束版仍SAT；含真实FP的探索限时UNKNOWN，不能宣称全链已经验证，也不等于不可达。

### 本轮启动兼容约束

1. 本地缓存解密按原kaiv入口分阶段：Base64、CCCrypt状态、UTF8与原字段检查分层。短cipher返回错误文本可能非nil，length>0绝不等于许可通过。保留五个调用的CF参数，禁止把其他响应阶段的ECB/RSA规则套入。
2. 原key/IV均来自同一kaiv对象，但分别进行maxLength=17、UTF8转换并使用16字节；原getCString BOOL未检查。新App应显式处理编码/长度失败，将安全修正标为行为变化，不承诺错误输入旧兼容。报告不含key、密文或授权材料。
3. 完整设备匹配、大小写忽略比较、子串、字符集合和NSRange分别验收；不得统一改为contains或BOOL。NSString范围/UTF16语义也不等于UTF8 C串语义。
4. 时间门绑定具体NSDate对象和D0秒值，不让每次intValue或FCMP各自成为独立成功开关。保留signed32、unsigned64及向零截断边界；NaN、2038与异常转换不填默认0，更宽时间协议需标明兼容差异。
5. JSON读取调用保存的原IMP，CCCrypt调用保存的原C函数；两保存槽不同且位于BSS，磁盘0或无关偏移不是实际目标。此处已补调用身份，不应作为可手工填充的启动接口。全部验证仍经原completion和24B014自身复核，不新增任何授权写入手段。
6. 静态算法、原调用参数、外部输入、全路径可满足性和同次实机UI事件分别验收。本轮完成callee/操作数语义补证，不宣称旧授权与新App已完整互通；未提供的系统Foundation字节不虚构为已反编译。

本轮578段、204267个去重文件字节与IDA一致；四个加载器绑定槽和两个无文件字节BSS槽明确剔出原文件字节计数。仅本机静态，未连接手机、运行目标、修改授权或兑换。5份原稿写前备份；以下保留历史内容，相关旧缺口和模型结论由本节及新报告限定。

---

## 本轮整数语义、格式F与启动续执行修订（2026-10-16）

[本轮逐字节证据与分支索引](../dgassistant-239-static-completion/STATIC_STARTUP_CLOSURE_2.3.9.md)。本轮静态证据覆盖508个合并区间、127784个去重字节，IDA与原文件一致。3EB224返回uint64十进制累计值，TLS错误文字是独立通道；NULL/空串/非数字返回0，检测到new<old回绕时返回全1，不能称为已证明完备的strtoull实现。cc2的F已解为`%llu`（25 6c 6c 75），P/G格式化输出与后续signed32 intValue检查须分开。

ct解密文本另经UTF8String→3AA0AC，按`h=(31*h+uint8(c))%10^16`生成frame23F8的H；它不是64位到期时间。两处H<=B、H<=C与转换为double后对新NSDate的LS拒绝门，与ct的intValue时间门及cc2时钟门分别保留。

65A968起到65DF98的608条原边、285次原调用已在同一SSA存储关系下闭合；表项与恒定索引无矛盾，覆盖指令无未建模项。外部解密/比较及浮点结果仍为符号条件，不代表某份具体授权已验证。调用者传入的block invoke确认为24B014；原初始化保存同一block/challenge，原成功出口生成参数并调用，24B014仍自行复核后转入后续阶段，而非直接主界面。

### 本轮兼容验收约束

1. P/G以`%llu`表达uint64，回退时依次比较各自intValue与32位截断NSDate秒；不能把三来源统一成server endtime。解析返回0时必须区分TLS错误通道，且不得把new<old检测扩写为通用解析器保证。
2. ct的signed32 intValue时间门和文本哈希H门独立。H与B比较两次，再与C及新NSDate比较；不把其中一处B擅改成A，也不将H当expiry。cc2差分达到122秒的拒绝及各时间比较继续单独验收。
3. 文件读回、解包、plist与udid及后续字符串/整数一致性检查不可跳过。608边证书描述一条满足原条件的连续静态路径，不是全图唯一顺序，也不替代外部加密函数或具体合法材料的验收。
4. 每次启动持有同一block/challenge，沿原成功分支产出状态和参数；C0C=52是原代码副作用，不是新App可手工写入的激活接口。回调参数的32位除法、动态全局重读和24B014自身复核都须保留，不使用固定token或伪造回调。
5. 24B014通过后进入80B9CC/24B8F4等后续阶段，不等同即时进入主界面。本轮没有手机事件；“静态关联已闭合”与“同次实机有效响应到UI已抓齐”分开标注。新App安全协议与错误呈现可另行设计，不机械复制旧实现的脆弱检查和系统级副作用。

本轮仅连接本机13338做静态分析，未连接手机、执行目标、修改授权或兑换。写入前原稿已按哈希备份；以下保留历史内容，相关旧缺口状态由本节及新报告取代，未新增的动态/密码学证据不升级。

---

## 本轮cc2来源与时钟门修订（2026-10-16）

[最新原字节证据](../dgassistant-239-cc2-origin/CC2_ORIGIN_2.3.9.md)：cc2已由A48候选槽推进为三来源回退：先保留block+0x50格式化值；其intValue不晚于截断的NSDate Unix秒时改取全局1015EB0A0；全局格式化值也不晚于另一次采样时，才用响应endtime的`%@`结果覆盖。P/G上游已定位3EB224返回值、全局写入及block捕获；其业务语义与格式F仍有缺口，不能写成cc2始终等于服务器endtime。

读缓存已确认最大两两时钟差分达到122秒进入493800清理；未达到时依次检查cc2>A、cc2>B、cc2>C，并再与新NSDate时间比较，不是三选一。udid后续和ct后续unsigned比较补边见新报告；有效缓存到24B014完整边链仍未全部证明。核对去重21366字节，16份原稿备份；本轮仅静态，无手机连接、授权修改或兑换。以下保留历史证据，旧缺口状态以此段及新报告为准。

新增兼容约束：分别保存捕获快照/全局重读/响应对象的类型及32位比较边界；时钟门需覆盖121秒、122秒和cc2等于任一时间的拒绝边界。不得将udid或ct单门通过直接映射主界面。以上是分段兼容约束，不是可直接宣称完全兼容的启动实现。

## 本轮静态契约增量：cc2 写入槽与差分汇合（2026-10-16）

[本轮证据报告](../dgassistant-239-cache-contract/CACHE_CONTRACT_2.3.9.md)：13338/PID 56134，18 段共 1444 字节与原文件一致。确认 `6274C4` 以 `*frame[A48]` 为值写入 `tz0111cc2`；尚未证明该槽最后到达定义，不能等同服务器 endtime。三时钟分支已推进到差分保存、固定索引 `5D8F → 64C80C` 汇合及与 D_BC 的 signed 比较，不能直接称为最终选钟策略。

回调出口 `65DF98` 调用传入 block 的 invoke，非硬编码 24B014；有效缓存到第一回调仍有条件边缺口。本轮不连接手机、不修改授权、不兑换。初版局部分析器误将未知表沿用为旧表，相关输出已标记 REJECTED，修正后的探索与独立字节证据分开保存。以下为历史章节，未获得的新证据不作升级。

兼容约束：cc2 对象、OpenStep 整数解析、ct 解密比较分别验收；不得用统一 expiry 或任一时钟通过替代。block 实例、invoke、32 位回调参数必须保留各自语义。新 App 的完整兼容验收仍待 cc2 产出和全部选钟/许可条件补齐。

## 本轮缓存字段修订：cc2 原文本与拒绝副作用（2026-10-16）

[最新字段报告](../dgassistant-239-cache-fields/CACHE_FIELDS_2.3.9.md) 补充上轮结论：cc2 缺失不只是返回，原代码调用 493800 清理逻辑，离线观察到偏好键及三目录缓存删除 API，并向主队列安排 2.25 秒校验 block 与 2 秒 abort block；不是设备实删或实际发请求。cc2 非 nil 后还搜索原文本 `tz0111cc2 = ` 并用 `%lld` 扫描，语义相同 XML 不保证兼容；公开 XML 的扫描输入为 0xC，尚未实机重现。公开 OpenStep -1/0 负例完成原扫描及拒绝路径，未构造有效许可。

原字节还确认 clock_gettime(0)、CFAbsoluteTimeGetCurrent 转 Unix 秒、time(NULL) 三来源及 cc2 signed <= 时间比较；它不同于 tz0111ct 的 ACPDS→intValue→FCMP。完整时钟选择策略、cc2 产出关系、合格缓存到全部字段及第一 callback 同次链仍缺。本轮无手机连接/附加、授权改写或兑换；2648 字节比对，14 份原稿备份。最新累计清单位于字段报告目录，下方章节保留为历史证据。

### 兼容契约纠正

- 缓存原文本属于协议：不能仅验证 plist 字典语义等价，就把旧序列化替换成 XML/二进制 plist。保留旧词法要求，或明确建立有版本的新格式；原文本缺标记和 sscanf 失败应成为明确拒绝事件，不复制潜在无效指针行为。
- cc2 非 nil、整数解析、时间比较、ct 解密及许可接受分别验收；数字 0 对象不等于缺字段。cc2 来源尚未与 server endtime 贯通，禁止混用。
- 授权拒绝可能触发清理和延迟终止，不能视为无副作用返回。新 App 的清理限于自身存储域；错误展示与退出策略需显式设计，不机械复制旧 App 的黑屏、系统路径删除和 abort。
- 区分实际 UI/许可成功、标准库模型输出和副作用排队。当前不具备“旧授权启动链已完整复现”的验收条件。

## 本轮静态 reader 修订：第一回调与缓存回退（2026-10-16）

最新 [静态追链报告](../dgassistant-239-static-reader/STATIC_READER_2.3.9.md) 优先于下方历史“fallback 未知 / 读取到 plist 未接通”的表述。24B014 的原分发表已解析，条件通过后构造 24B8F4 block 并调用 80B9CC；不匹配静默返回，不直接进入主界面。离线原 reader 显示 Caches→Preferences→Documents/.apple 的两轮存在检查，缺失才继续；Caches 读 nil 的测试未回退。离线 basename 为 a089...，不同于实机 ae098...，不可混用。

新增原指令连续链：文件模型→原 6B2BB4→设备种子文本包含检查→NSString→UTF8 NSData→plist 入口，公开非许可输入逐字节一致。解析后 count 必须为 8；8 个无关公开键只推进到首个记录字段读取，没有授权写入。文本包含/结构检查不是数字签名；远端 sign 不自动成为缓存读取串行前置条件。首回调实机事件、另两副本实际读回、缓存全部字段到 callback 同次闭环仍缺。本轮未连接手机、附加、修改授权或重新兑换；13 份报告已备份，当前累计核验入口在静态报告目录。

### 新 App 启动契约增量

1. 只读发现候选缓存与许可验证分层。旧兼容顺序为 Caches、Preferences、Documents/.apple；不要把“存在”和“内容有效”合并。新 App 使用自身存储域，不硬编码 /rootfs 或离线 fixture 路径。
2. 缺失回退与读取/解码/格式失败分别建模。已证读 nil 不等同于尝试后两份；旧实现全部失败模式未穷尽，新实现若选择更安全的新策略，应标为行为变更。
3. 外层解码→文本设备绑定前置检查→UTF8→plist→精确旧结构→记录字段验证是不同步骤。兼容层保留旧格式条件；原种子包含/count=8 不能产生 VerifiedGrant，更不能替代新协议的可靠签名验证。
4. 24B014 是带捕获 challenge 和原状态条件的续执行门；后继为 80B9CC/24B8F4，不是主界面。不得用固定 token、写 52 或伪造回调完成启动。
5. 验收记录缺失、读 nil、解码失败、设备文本不匹配、结构错误、字段拒绝、后继启动等脱敏事件。已有实机后半链与新增离线前半链分别标注，禁止宣布同次完整授权成功。

## 本轮内核追踪修订：bind EPERM 与 Caches 写后再读（2026-10-16）

最新证据及边界见 [内核追踪报告](../dgassistant-239-kernel-trace/KERNEL_TRACE_2.3.9.md)，累计核验入口为 `../dgassistant-239-kernel-trace/manifest.sha256`。本节优先于下方历史阶段的“底层 errno 未捕获 / 全部写后再读未证”表述；历史记录保留供追溯。

- 原版 debugserver 的 socket 成功，bind 实际返回 errno 1（EPERM），清理后的日志才是 0；具体策略来源仍未确定。
- SSH raw PTY + 原版 --fd=0 已实际握手。稳定启动后 task_for_pid 成功，但 PT_ATTACHEXC 阶段调试器 SIGSEGV；未获取成功附加/断点事件，未继续绕过。
- 无注入正常启动 PID 61342：三目录各有 1281 字节临时写入、fsync、rename；约 20 秒后 Caches 目标 read 1281，写/读磁盘块相同。Preferences/Documents 在采集窗口无读回事件；rename 输出未包含目标参数，不补造缺失字段。
- 三个实际目标最终摘要相同。审计自身的只读取摘要不算 App 读回；24B014 及 read→decode→校验的同次用户态链仍缺。
- 本轮未使用早期 Frida、未改授权或重新兑换。临时工具已清理；用户确认 DG 管理主界面。

契约补充：分开验收已有授权读取验证、新授权刷新写入和后续读回；旧缓存读取发生在本轮新写入之前，不能把新写入作为进入主界面的必经门槛。三份落盘不等于三份均被读取，fallback 仍需证据。文件存在、摘要相同或成功 read 均不能替代解密、解析及 sign/udid/endtime 校验；新 App 应在自身存储域提供脱敏事件观测。

# 新 App 可沿用的授权与启动契约

## 本轮真实根路径与 debugserver 退出补证

[最新补证](../dgassistant-239-debug-path/DEBUG_STORAGE_PATH_2.3.9.md)已定位三份真实缓存：系统真实`/private/var/mobile/Library/Caches/`、`Library/Preferences/`、`Documents/.apple/`下同名`com.apple.ae098f4c9f0.plist`。SSH处于RootHide路径视图，须经`/rootfs/var/...`访问系统根；`/rootfs`不是App应硬编码的前缀。三份1281字节、Base64外包裹及末尾NUL文件同哈希，正常无Frida启动后全部更新为另一相同哈希。**真实落盘存在和自然更新已证；DG写后再读同一新版本的同次身份/字节关系仍未证。**

原debugserver版本/参数处理正常，TTY输出定位到网络建立失败，原子进程仍返回0；原arm64清理字节会清零errno，日志err0不是监听成功。尚无可信底层errno或附加拒绝证据；Frida观察临时工具的独立SIGSEGV及原reverse-connect失败分别记录，不冒充DG反调试原因。`log`为shell builtin，纠正此前“shell函数”措辞。

24B014唯一启动探针就绪后，PID60554约0.593秒终止，第一callback及后装详细观察均无事件；停止重复早注入。随后临时工具/Frida/转发清理，普通启动PID60593存活超过10秒，用户确认管理主界面；没有新兑换、校验替换或人为授权改写。reader新增307条原指令定位了C字符串→NSString→UTF8 NSData→plist的中间静态边；离线完整桥尝试未到目标，失败保留，不升级为真实闭环。

11份正文修改前均备份；当前完整性入口为[本轮累计清单](../dgassistant-239-debug-path/manifest.sha256)。后续较早章节是历史轮次记录；其中“路径未找到”“本轮未重启”等不得覆盖本节最新证据。

迁移约束：新App把存储定位、包裹解码、plist解析、许可校验分别验收；旧三文件只作只读兼容发现，不用存在/相同哈希/time头生成VerifiedGrant，也不要求新App写系统域。NULL/UTF8/plist失败必须拒绝；需要持久化时写自己的授权域，并单独验证新文件读回，不以BOOL1或UI出现替代。真实key来源和第一callback全实机闭环仍是未完成验收项。

## 本轮存储编码与调试端点续审

[最新存储续审](../dgassistant-239-storage/STORAGE_CODEC_2.3.9.md)已接通原writer的UTF8String→629040→strlen+1→NSData→writeToFile字节链：外层为8字节本地time头、循环第二输入/反馈旋转、相邻字节反馈及Base64，文件包含末尾NUL，不直接是明文plist。原encoder的10组公开文本输出与独立实现一致；原6B2BB4 decoder还原8组非空文本，对2组header-only输入返回nil。**这是离线原指令/显式Framework模型单元，不是实机许可解码或授权接受；公开fixture-key不是真实key。**内层tz0111ct加密、服务器endtime和展示日期继续分层。

无目标debugserver测试也在监听前退出（SSH返回0、无诊断），因此上轮连接时序问题不是已证唯一原因；本轮未连接LLDB、未附加DG或安装断点，24B014仍缺实机事件。实际存储域、准确序列化/第二输入来源、完整读文件到解包再到plist的身份边仍待证。当前DG PID60198保持存活，本轮无App重启/Frida附加、无授权改写/兑换；临时原工具与挂载已清理。10份修改前正文有备份；[本轮累计清单](../dgassistant-239-storage/manifest.sha256)为当前完整性入口，下文较早章节按其原轮次理解。

## 前轮真实 endtime 产出与调试补证

[最新产出补证](../dgassistant-239-producer/PRODUCER_CHAIN_2.3.9.md)：PID60114已实机捕获61ACB8的block+48字典读取endtime（__NSCFString）→原格式化→原CCCrypt（0/0/1/keylen16/IV非NULL，10→16字节，status0）→24字符原返回对象→原setObject:forKey:写tz0111ct并自然返回。关键对象身份关联成立；第一completion原endtime非零结果=1，producer数值与其原转换值相等。此产出关联不再只是模型，但不代表全部许可检查或跨阶段对象指针相同已证。

该PID先从旧ct记录通过原时间门并进入24BFB8/24CBB8入口，约1468ms后才新产出ct，不能倒接因果。三条逻辑路径写调用均1281字节/options1/返回1；写后SSH未找到原路径或已知RootHide前缀路径，外层格式、实际落盘及写后再读仍未闭环。tz0111ct字典字段不混为standard偏好顶层键或tz0111endtime展示缓存。

24B014仍无实机事件：预加载仅onEnter轮在第一worker前终止；原版临时debugserver的转发Connection refused、LLDB握手未成功，未安装断点。无Frida启动曾短暂退出，随后PID60198持续存活且用户确认管理主界面，退出原因不归咎于单一因素。未改授权/输入/结果/时钟、未重新兑换；临时工具/服务/转发均清理，自启不恢复。9份正文修改前已备份；最新完整性以[本轮累计清单](../dgassistant-239-producer/manifest.sha256)及离线verify_producer.py为准，历史清单保留不改。

## 前轮真实比较与启动来源纠正

[最新轻量采集](../dgassistant-239-live-predicates/PREDICATES_CAPTURE_2.3.9.md)已实机抓到第一sign原结果1、第一udid比较0，以及63137C独立udid对象→UTF8→原比较0。PID59897同时捕获第二响应AES/RSA成功组件→24B8F4→63137C→24BFB8→主线程24CBB8正常返回；**该PID的第一sign/udid在UI返回402ms后才判定，不能硬接成该次UI的串行前置门**。PID59980另捕获记录字段tz0111ct→原ACPDS解码→intValue→649084原时间比较→第三callback和主UI；此处不直接消费所定位的endtime对象，也不是标准偏好域顶层tz0111ct键（最终该键不存在）。

前轮当时仍缺第一callback与endtime到ct产出关联；本轮已补真实产出，具体边界及最新清单见首节。较早报告中的“无成功输入”“字段未捕获”等均按各自轮次理解，不将独立模型升级为全实机。

## 前轮合法激活实机验收增量

[本次实机记录](../dgassistant-239-live-success/ACTIVATION_CAPTURE_2.3.9.md)已捕获字符串306→原4AE7B8→4BF660复验。306的data.endtime为NSNumber，仍不是grant或主许可内层字段的统一类型规则。后续正常运行由用户确认进入主界面；只读核查实际/var/mobile/Library/Preferences/apple.allIDTDG.plist中存在tz0111endtime，类型NSString、19字符、日期形状匹配。两次文件读取之间包含重型与无Frida启动，未捕获准确writer。km2此前已存在，因此km2或期限展示缓存不能当作授权凭据。

轻量同PID59577轨迹为24B8F4→63137C→24BFB8→主线程24CBB8，并正常返回。进入UI时C0C=52、C18=222，C14/C48仍257/2；不得把四字都等于接受值设为旧UI的前置契约。第一callback和逐字段sign/udid/endtime检查未同次捕获；新App完整验证器仍需独立验收，不能由跨PID的成功组件拼成兼容SDK证明。

重型插桩时的process-terminated不证明“首次激活设计成退出”。无Frida及轻量观察均已成功；具体重型观测干扰源尚未隔离。最新完整性见合法激活案例manifest。

## 实机验收增量：等待、HTTP失败与观测干扰

2026-10-16实机观察记录在[实机报告](../dgassistant-239-live-auth/LIVE_AUTH_2.3.9.md)。旧App未激活时黑屏且可能自行退出，不能把“未崩溃/窗口存在”当作ReadyForMainUI。一次原completion实收HTTP404 / 200字节 / NSError=nil，说明NSError为空不等于HTTP成功，更不等于VerifiedGrant；它不能被归为明确的激活码拒绝。新App应分别保留HTTP状态、传输错误、响应结构错误、校验拒绝与取消，不从HTTP失败中生成grant。

同次晚附加轨迹仅到原剪贴板处理及exit(0)，授权字快照仍为2/257/257/2，未到业务UI。启动前裸附加的提前终止与正常等待退出分开记账；测试不能通过忽略退出、替换返回值或写状态字来“验收成功”。目前缺合法激活码/完整成功响应，sign→udid/endtime→缓存→续执行→UI这一整条实机成功验收仍未通过；不得交付为已兼容旧后端的实现。最新完整性见实机案例manifest。

## 1. 使用范围

基于已提供 DGAssistant 2.3.9 的原字节审计，供用户自有新 App 重建。**行为契约及第一sign检查已恢复；旧后端完整有效响应和全部接受条件尚未闭环，暂不是可直接替换的SDK或线协议实现。**不以复制授权字、伪造成功响应或持有km2代替服务器许可。最新算法、类型、缓存写入与续执行细节见[字段续审](../dgassistant-239-license/LICENSE_PREDICATES_2.3.9.md)。

详细地址、原字节、响应参数与证据级别见 [RESPONSE_CONTINUATION_2.3.9.md](RESPONSE_CONTINUATION_2.3.9.md)；前轮剪贴板、种子与三阶段启动见 [启动报告](../dgassistant-239-startup/STARTUP_ACTIVATION_2.3.9.md)。

## 2. 状态与事件

以下是新 App 的接口设计建议，不声称是旧代码原有类型名。

| 状态/事件 | 必须成立的约束 |
|---|---|
| BootShell / WaitingForAuthorization | 窗口可见；不构造/开放清理、隐藏、恢复等业务UI。可保留旧空白视觉，但建议提供等待/错误状态 |
| ClipboardCandidate(raw, normalized) | 仅在系统允许后读取；原文与清洗码分离；nil/拒绝/空文本不能作为授权 |
| ActivationPending | normalized去首尾空白及内部ASCII空格/LF/CR；长度至少7只是提交门槛；km2只存待激活原文 |
| RedemptionReported | recharged给出兑换状态；旧306对应“充值成功”提示及重新授权请求，不等于AuthorizationGranted |
| VerificationPending(attemptId, challenge, deviceIdentity) | 重新发起登录验证；响应必须绑定当前尝试，过时结果不得恢复新任务 |
| VerifiedGrant | 由真实验证器产出，不接受UI、偏好缓存、HTTP200或单个token指定成功 |
| StartupFreshnessPassed | 独立第二启动验证和时间新鲜度检查满足；之后还有再次验证 |
| ReadyForMainUI | 全部门控完成，在主线程只构造一次主UI |
| Rejected / TransportFailed / Cancelled | 不开放功能；记录原因；重试或新输入启动新attempt，不复用旧成功标记 |

建议最小接口边界：

```text
ClipboardInput -> Candidate(raw, normalized)
ActivationClient.redeem(candidate, identity) -> RedemptionOutcome
AuthorizationClient.verify(identity, challenge, attemptId) -> UntrustedResponse
AuthorizationVerifier.verify(response, expectedContext) -> VerifiedGrant | Rejection
StartupCoordinator.accept(grant, attemptId) -> next validation | main-thread UI
```

关键不变量：只有 AuthorizationVerifier 能产生 VerifiedGrant；兑换提示、粘贴权限和 km2写入都无此权限。不要把旧整数52/222公开为可由调用者设置的API。

## 3. 兼容行为与未定协议

| 层 | 已确认旧行为 | 新 App 的迁移要求 |
|---|---|---|
| 身份 | 请求username来自原种子provider；与隐藏后缀使用的种子链有关 | 独立封装来源/缓存；新bundle、容器、IDFV等变化需设备验证。不能硬编码审计fixture身份 |
| 输入 | 缓存原文km2，提交清洗码recharge_card | 缓存明确标为未验证；保护敏感输入；不将日志写入明文激活码 |
| 兑换 | `/index.php/api/User/recharged`；表单id/data/data3/data5/data6；无效请求的完整字节已留证 | 字段编码以原函数/有来源请求核对；时间/随机fixture不是生产常量 |
| 第一授权 | 逻辑百度前置POST/nilbody，原completion再走logind1 | 区分两个请求和两个响应；连接策略不是许可判定；重建是否保留前置请求应由后端要求决定 |
| 第二启动 | logind0；响应code字符串257进入不同解码层 | 与logind1、recharged分别建parser；不得统一按“code200即成功”处理 |
| 兑换结果 | 303/304/305的旧错误提示；306描述子串触发提示和重新请求 | 新解析器建议精确状态/类型；若需完全兼容，先用有来源响应验证，不照搬脆弱的对象描述子串当可信成功 |
| 响应crypto | 第二验证原category的CCCrypt参数1/0/3/16/NULL；请求参数0/0/1/16/非NULL | 按阶段隔离；解密返回0之后仍需文本、结构、设备/挑战/时间和真实性验证。不能用AES解密成功冒充验签 |
| RSA工具 | 真实启动层有静态调用；工具负向单元有未先检查返回码的追加行为 | 新代码必须拒绝crypto错误，不能沿用错误缓冲。真实响应key与完整真实性算法仍未定 |
| 授权状态 | 原631写运行时52；第二验证写222；callback还检查token和时间 | 新App用内部可信状态，不向偏好文件保存一个可自认证的activated=true |
| UI入口 | 三阶段验证后主队列构造管理UI，不是启动时立即构造 | 统一协调、幂等、只在主线程；失败、超时、重复/乱序回包不能提早进入 |

`45.205.27.120:2` 是旧包内connect重绑定约束和实际HTTP路径，不是可复用的授权凭证，也不是系统防火墙。是否继续使用该后端须由服务归属和新App要求决定；本轮没有联系它。

## 4. 续执行契约

```text
启动等待
  ├─ 服务分支要求激活 -> 获准后读剪贴板 -> 兑换
  │    ├─ 拒绝/失败 -> 保持未授权
  │    └─ 兑换提示成功 -> 新建/重启授权请求（不是直接进UI）
  └─ 真实授权通过 -> 第一callback -> 第二启动验证
       -> 时间/状态门 -> 再次验证 -> 主线程进入UI
```

旧包已执行确认“兑换306提示→原4BF660重新请求”和“检查后状态写入→原callback”两段；两段之间**真实有效响应恢复原始等待上下文的完整设备时序仍缺**。不能声称原实现一定是semaphore.signal唤醒。原链部分延时块会exit，不是通用重试机制。

新 App 建议使用单一 StartupCoordinator 保存当前attempt和续执行闭包；兑换仅触发复验，验证器确认后才恢复相应任务一次。这是替代复杂等待方式的设计建议，不是已经证明旧App使用同样的协调器。取消、进入后台、再次复制或新请求开始时，应使旧attempt失效。

## 5. 验收用例

| 用例 | 必须观察到的结果 |
|---|---|
| 冷启动且无授权 | 窗口壳出现；管理功能不可达 |
| 粘贴拒绝/nil/空白/不足7字符 | 不提交兑换；不视为激活 |
| 含空格/LF/CR且清洗后足长 | km2保留原文；线上输入使用清洗值；两者均不当作grant |
| 只存在km2 / HTTP200 / code200 / code257 | 均不能直接进入UI |
| 303/304/305 | 正确展示对应拒绝；保持未授权 |
| 306兑换提示 | 触发重新授权；在真实复验前不开放UI |
| crypto失败/非UTF8/错误JSON/不匹配身份或挑战 | fail closed；不使用残留缓冲或以前的grant |
| 第二验证时间过旧/过新/状态未满足 | 不进入第三验证或UI；不得把±22秒误写成许可证有效期 |
| 乱序、重复、超时后到达的响应 | 仅当前attempt可继续；主UI构造一次 |
| 合法成功响应 | 真实解密/真实性判定、状态产出、三阶段续执行及主线程入口均有可核对轨迹 |
| 重启/重新安装/新bundle | 单独检验设备身份及授权持久化；不能从进程内52/222推定跨重启行为 |

最后两类尤其需要设备证据。目前没有将其标记为PASS。

## 6. 成功轨迹补证格式

优先提供脱敏日志：相对/绝对时间、请求路径、响应状态与字段类型/长度、crypto调用参数类型和返回码、输入输出SHA-256、状态写入及回调调用顺序、主UI进入时刻。请勿包含激活码明文、密码、私钥、会话令牌。

若响应密文或验签字段被修改，只能核对时序/结构，不能据此声称重放验签通过。取得日志后应绑定本报告样本哈希及设备/iOS版本，补齐有效响应→状态产出→原等待任务继续→主UI的同次运行证据，再决定旧后端兼容实现。

## 7. 已收到的成功抓包摘要：兼容候选，不直接上线

已登记 `license-server/dg_capture_reference.md` 的脱敏叙述。内层候选包含 state、udid、sign、stt、endtime、ss系列、gg、tk、token、point及嵌套data。字段续审已恢复第一sign算法、udid比较和tz0111endtime的standardUserDefaults写入口；后者写的是格式化NSString，不是摘要所称NSDate，指定suite仍未证实。ntt及其余完整接受条件不能把文档JSON直接当作通过fixture。

特别注意：摘要把code写成数字257，但当前原第一响应对该类型拒绝，字符串257才进入解码；此规则不能直接推广所有内层。摘要AES-CBC参数也不能替换已追到的外层入口。后端往返自测不等于旧客户端互通；恢复的sign不是CRC32或密码学签名，不能自行换算法后仍声称兼容。新App自有安全协议与旧后端兼容必须分开验收。

## 8. 可沿用的字段与续执行精确契约

本节区分已证实旧行为与新App接口建议，不提供许可生成器或授权跳过实现。

### 8.1 请求上下文和第一sign检查

每次请求保存不可变的attempt上下文：身份、原随机数字符串及其intValue、请求捕获Unix秒低32位、challenge、预期completion。旧completion+48捕获随机数，+112捕获请求秒；响应处理期间不得从另一尝试或当前时钟重新取它们。

原第一sign检查先调用ObjC intValue，再按32位比较 `u32(signValue) == u32(capturedTime + 2 * capturedNonceValue)`。它是请求绑定的算术校验，不是整份license的MAC/数字签名。只让这个条件通过不能产出VerifiedGrant；state/身份/有效期/关联字段/其他验证仍属于独立条件。

类型转换是协议的一部分。不要用JSON解析器“方便地”把所有数字与字符串互转。宿主Foundation的越界字符串intValue与NSNumber取低32位有差异，原ARM64只证明转换后W寄存器运算；需要兼容越界输入时，应另做目标iOS版本测试，不照搬审计模型的简单int解析。

### 8.2 身份与时间

- udid取UTF8String，与原provider生成身份进入原3AF36C；匹配返回0。九组原指令单元确认大小写、前缀、后缀不同均拒绝，按NUL结束；不要改成contains、忽略大小写或Unicode规范化。
- endtime有intValue非零门，但非零不等于未过期；另有ssss关联字段拒绝和日期消费。不能把某一单元的exit统一解释为“过期”。
- 原数值时间比较已定位到5EAE20及过期→剪贴板路径；其+3340上游尚未接通，暂不能把该单元当作完整endtime校验器实现。
- 启动callback的±22秒是另一项新鲜度门，不是license期限，也不能替代许可证到期检查。

### 8.3 展示缓存

旧写入口5C60F4调用standardUserDefaults.setObject:forKey:，键是隐藏CF对象1014CA760解出的tz0111endtime。值来自endtime.intValue→NSDate→NSDateFormatter.stringFromDate，原格式为 `YYYY-MM-dd HH:mm:ss`，随后synchronize。缓存是NSString，不是NSDate、整数期限或可信grant；缓存存在、写入成功或可解析都不得恢复权限。

固定GMT0只是离线测试条件，原所测入口没有设置该时区；实机locale/calendar/timezone与磁盘偏好域需单独验收，不能直接采用摘要中的suite名。若为显示正确性改用其他日期格式，应标明是新App改进而非原样兼容。

### 8.4 回调和状态不得混线

旧4BF660把调用者completion保存到5BBE48的+64。初始定时路径本次观察为00A554，兑换后为4DEF48，不是ViewController的24B014。后者应继续由独立启动验证器产生。

原5BBE48构造61ACB8，将调用者completion转交到其+56；后者628ADC从+64的forwarded byref+24取W1并调用保存completion。该路径还写C14=222、C48=52及完成标记；这些地址与主UI使用的C18/C0C不同。当前不能把它们合并成一个activated变量或宣称其已接通631。

60713C把早期完成标记置1后仍可能因缺data2而abort，因此这个标记也不是VerifiedGrant。另有睡眠后主队列检查byref标记的退出看门狗；不能将它描述为semaphore.signal恢复UI。

新App协调器仍只在**当前attempt的完整验证器**产出grant、启动新鲜度及后续验证完成后恢复UI续执行一次；兑换只触发复验。旧组件的静态转交和检查后单元已经补齐，完整同次有效回应→原等待任务→主UI尚未标记PASS。

### 8.5 新增验收断言

| 输入/事件 | 必须核对 |
|---|---|
| 外层数字257 / 字符串257 | 保留原JSON类型；分别拒绝 / 进入解码，不自动转换；内层另验 |
| sign匹配但身份/时间/其他字段错误 | 不因单个算术校验通过开放UI |
| 相同sign但请求上下文已更换 | 以当前attempt捕获值检查，不接受响应自报ss/sss自证 |
| udid只在大小写、前后缀或NUL后内容变化 | 按已恢复的C串语义与目标iOS实际输入约束核对；新协议可明确拒绝NUL，但须标为新规则 |
| endtime为0、1、越界字符串、与ssss不一致 | 分清结构/转换/关联/过期拒绝原因，不能仅测非零 |
| tz0111endtime存在或完成标记为1 | 不当作授权凭证；失败/缺data2不得进入UI |
| C14/C48写入或兑换306提示 | 不能冒充C18/C0C及三阶段启动链完成 |

最新本地复核与五份正文修订的完整性以 `../dgassistant-239-license/manifest.sha256` 为准；此前清单作为历史快照保留。

## 9. 实机证明后的分层契约修正

### 9.1 并行路径不能统一为一次授权回调

原服务响应检查器5BBE48与启动验证器63137C分别记录自己的attempt、输入来源、类型和完成事件。PID59897实际UI返回早于第一sign/udid判定402ms；因此不能实现成“等待C14/C48就位后旧App才进UI”的伪兼容模型。第二响应解密及RSA原调用成功后，C18=222的callback2→第三631→callback3→主线程UI已在同PID接受时序出现；第一callback仍漏采。

新App应只在自身可信完整验证器产生grant后开放管理权限，这是安全设计要求，不是据本轮反推出旧实现全程满足该安全要求。保持已激活重启与首次兑换分开验收，避免把两种启动误画成同一条必须重新兑换的流程。

### 9.2 sign与设备检查的可沿用边界

sign的原32位请求绑定公式及其真实结果1已经捕获；自然intValue输入类型仍是协议边界，算术条件不能升级为覆盖全部许可的数字签名。5BBE48经888EA8调用原比较器实际返回0。631另有CF键1014CB8E0的udid→UTF8→3AF36C，原返回0；保留NUL结束、区分大小写的已恢复语义，不用contains替代。两条设备字段消费不要因名称相同而共享未验证上下文。

### 9.3 tz0111ct时间门，不冒充服务器endtime或展示日期

631对记录下标键1014CB680（实机名tz0111ct）取值；该原getter结果作为NSString ACPDS:kaiv:的cipher实参；自然解码结果再做intValue；SCVTF把有符号32位值变double，649084比较当前时间来源数值。PID59980七次对象/数值关联成立，原LS结果0，值大于右侧且右侧接近设备Unix当前秒。第一次判定后同次进入callback3和主UI。

不要把此链替换成直接读取endtime.intValue；也不要仅因键以tz0111开头，就改为standardUserDefaults顶层同名键。最终标准偏好文件无tz0111ct顶层键，原getter接收者来自另一个记录cell；该轮当时尚不确定产出及存储域；本轮已证61ACB8读取endtime、原加密并写ct字典字段，实际存储域/外层编码/写后再读仍未闭环。tz0111endtime则仍是展示用的19字符日期缓存，角色不同。

原LS=true静态表目标64C85C、false目标664184已读出；没有在手机设置过期值或改时钟，因此真实过期拒绝行动未验收。不得把本轮未过期样本命中作为全部有效期失败分支测试。

### 9.4 当前验收矩阵

| 验收项 | 结果 | 限制 |
|---|---|---|
| 第一sign公式在真实请求匹配 | 已观测原结果1 | 不是完整密码学验签 |
| 第一udid及631独立udid匹配 | 已观测原比较0 | 不保存真实设备标识 |
| 第二响应crypto→callback2→第三验证→UI | 同PID59897已记录；UI正常返回并存活 | 未逐条观察所有隐含条件、未取本轮JSON code值 |
| tz0111ct原解码/转换/时间门→UI | 同PID59980已记录 | 不能替代服务器endtime全部检查 |
| 24B014第一callback | 未捕获 | ready时C0C已经52，最早附加发生干扰 |
| 服务器endtime→ct字典产出 | PID60114已真实捕获 | 外层编码后续以离线原指令补齐；实际持久化/写后再读仍缺 |
| endtime全部拒绝分支 | 未穷举 | 不改真实许可去构造过期/错误值 |
| 不修改授权的采集和服务收尾 | 已核对 | 本轮临时工具/服务/转发已清理；PID60198存活且用户确认主界面 |

综上，交付是可审计的分层契约与实机组件接受证据，不是全部已兼容旧服务器的可上线授权SDK。

## 10. 真实producer补证后的缓存契约

1. 输入为61ACB8原block+48字典的endtime；实机是__NSCFString。6270B0原getter对象经6E8作为stringWithFormat:参数，格式化对象经990进入sub_20255tz0111:kaiv:。原CCCrypt参数0/0/1、16字节key、IV非NULL，原status0；本轮10字节明文→16字节输出，返回24字符字符串。日志不保留期限、key/IV或密文。
2. 6283D0原setter以tz0111ct为键、以原加密返回对象为值；接收者是__NSDictionaryM，原setter自然返回。这个缓存构造链已由实机对象关联替代原来的“仅上游未知”。第一endtime非零门原结果1仅证明该门通过，不等于全部身份/关联/期限判定已接受。
3. 同线程其后出现三路径1281字节write调用、options1、BOOL1，但外部未找到路径；后续已恢复外层自定义包裹和strlen+1，仍不假定实际存储域、原子写后可读、准确序列化或完整磁盘格式已兼容。持久化适配器应单独验收，不能只以setter或write返回作为VerifiedGrant。
4. 此次旧ct读取/原解码/时间门→UI入口发生在新ct生成前约1468ms。协调器不能按这份轨迹要求“本次ct新写完才进UI”，也不能反向省略完整验证。已证的时间门仍是记录getter→ACPDS→signed32 intValue→double→FCMP LS，不替换为直接读取展示日期。
5. 新App使用自己的完整验证器产出请求绑定grant，UI续执行只能对当前attempt恢复一次。上述观察约束是兼容行为证据，不是可生成旧许可的算法、完整后端兼容SDK或跳过验证的依据。24B014、全部endtime拒绝分支、真实持久化与写后再读均需独立验收。

## 11. 外层存储包裹，不是授权验签

原writer的620498经88B3EC/88B3DC调用629040，两个参数都是C字符串；输出包裹由strlen计长，加1构造NSData，再执行writeToFile。包裹结构为LE64(time(NULL))头与两遍反馈变换后的body，整体Base64；最后写出的NUL不计入Base64正文。time头是本地生成时刻，不是server endtime，不能用于授予权限。

原变换：第一遍以0x5A开始，逐字节`ROL8(plain XOR cyclicKey XOR previousFirstPass,3)`，更新反馈；第二遍从索引1向前，用当前字节异或本遍已更新前字节右移2。独立参考与原CPU指令的10组公开文本测试一致。原reader的662334经88C890/88C880进入6B2BB4逆包裹，8组非空原字节还原、2组header-only返回nil。代数逆函数不包含全部旧边界，不能作为完整兼容解析器。

准确writer输入文本序列化、第二C字符串的3EA174产出来源、真实磁盘域及文件→解包→plist的全部身份边仍待验证。当前参考实现不保存实际key/许可，也不输出VerifiedGrant。不因包裹可逆就弱化第一sign、请求/设备绑定、关联字段、期限或UI协调规则。详见最新存储续审的模型边界和离线复核命令。


## 12. 2026-10-19 接手离线纠正与新App启动契约边界

这是后续证据追加，不重写第9.4节的历史轮次。样本SHA256：3841f080d158a9a9f942eb0ca7f38ec8ba7e1677c23c1b92054fb82452e5cf78；所有地址为该2.3.9样本未滑移VA。详见[协议复核报告](../../dg239-protocol-takeover-20261018/report/PROTOCOL_REVIEW.md)及其逐原件索引。两轮各50项离线测试通过，不能据此宣称完整兼容。未运行目标、请求服务器、兑换或修改授权。

| 启动状态 | 已有证据 | 实现/验收限制 |
|---|---|---|
| 未激活黑屏等待 | 历史用户观察；粘贴板输入及后续校验局部记录 | 黑屏不是唯一授权状态标志，不能用超时直接进主界面 |
| 兑换/首次激活 | recharged构造及离线解析fixture；历史合法充值提示后退出 | 不以fixture的306或单code替代真实接受与落盘；本轮不重新兑换 |
| 已有授权重启 | 缓存局部读回、原时间门及后续UI观察 | 不要求每次重启重新兑换；准确文件格式、设备/请求/时间绑定仍待齐 |
| 验证与异步续执行 | 后续24B014事件及UI观察 | 第9.4“未捕获”是旧轮次结论；同attempt验证、block入队/执行与UI完整因果链尚未齐 |
| 拒绝/退出 | 历史失败观察及局部原分支 | 不将调试干扰和业务拒绝混同；错误/过期/不匹配等全部拒绝分支需独立负测 |

该表是新App验收拆分，不是已证明的旧App唯一状态机。三接口固定调用顺序、首次落盘后方可进入UI等均不得从不同轮次拼接推出。

### 三接口的证据边界

| 接口 | 已核原件及位置 | 本轮确认 | 未闭合 |
|---|---|---|---|
| logind1 | response/evidence/first-negative-protocol-257-native.json.gz 与 first-negative-numeric-257.json.gz，均 /events/364，解析点 0x1005D08A8 | 两份离线最终 HTTP 200 输入分别为28/26字节；code分别为字符串/数字；不能统一类型 | 实机同事务最终响应、通用封装、完整解码与接受条件 |
| logind0 | startup/evidence/activation-second-json-exploration.json.gz，/events/19374/args/1 → 19377/args/0 → 19380/args/0 → 19384/args/0；响应fixture另见 second-negative-protocol-257-native.json.gz /events/19728 | 构造片段2068→2422→2439→2456字节，最终字段id/data/data2/data3/data5/data6；解析点0x1008496AC | 构造记录socket缓冲缺正文，不等于真实发送0字节；前置crypto属请求侧，不是响应解码 |
| recharged | startup/evidence/activation-clipboard-final-exploration.json.gz，/events/672、734、1947；响应fixture另见 activation-negative-activation-*.json.gz /events/1944或1945 | 记录缓冲527字节=153字节头+374字节正文；两内层JSON版本不得互换；解析点0x10037C868 | 通用变换、真实send结果及服务器接受、最终响应到落盘关联 |

表内response/与startup/分别指工作区work/dgassistant-239-response/与work/dgassistant-239-startup/。八份响应均为离线解释器fixture，不是新增捕获的服务器响应。每份原件SHA、精确JSON pointer、字段类型及摘要见本轮interface-matrix.json。请求构造、待发送缓冲、系统send结果和服务器接受分层验收；HTTP100不是最终响应，MODEL事件不是真实库返回。

两份既有实机日志（work/dg-correlated-start-once-20261017/raw-events.jsonl、work/dg-gap-once-20261017/raw-events.jsonl）共30条JSON-resp局部观察，其description不是原始HTTP/JSON，不能恢复原JSON标量类型；邻近CONNECT、线程或时间不足以指定接口。本轮为这批记录建立的端点归属live最终响应为0，完整live解码闭合为0；不否认历史合法充值和主界面观察。

### data3与百度前置请求

- data3的0x1003C6838→frame130→0x1003C38D8比较EB008派生密钥对象长度，不是正文长度。≤1到3C5DE4，>1到3C0F60；短臂局部index0进入3C1CCC dispatcher而非RET。3C1D58外部写集未闭合，空正文/空key/nil/空字典须分开验证。
- 两个40字符参数初始化均有41字节（含NUL）；局部%02X初始化成立，但3B508C copy接收者、活跃选择及跨调用版本仍未绑定。198次fixture交换和多长度算术测试不是完整返回测试，不得据此实现“空输入直接返回空串”。
- 百度completion入口x0/x1/x2/x3的保存槽为frame3DF0/3DF8/3E00/3E10。5CAE98/5CAEA8的storeStrong消费entry_x2/entry_x3；5CE924→5FC168消费saved_entry_x0+20捕获对象，不是response-data参数。
- 5CAEC4与5E1928/5E197C是不同内存版本，不能强制相等；两分派表分别为101570F58（0→5F7BB8，1→5E8588）和101570FC8（0→5D5490，1→60428C）。局部组合不证明完整异步路径。
- 百度请求可省略仍未证明（omission_proven=false），也未证明一定业务必需。必须补齐错误/取消/正常返回到真实请求的参数、队列/锁/完成标记及全部副作用等价，不能凭“虚拟伪装”或解释器403/无响应模型直接删除。

### 启动与后端接入边界

历史确认的“合法充值提示→正常退出→再次启动显示管理主界面”保留；不把首次退出一律解释为失败。后续启动原件存在24B014事件，因此早期“未捕获”只属于当时轮次；事件存在仍不等于sign/设备/期限、缓存、异步block到UI全部同状态闭合。

已有局部server endtime→加密→tz0111ct setter及ct getter→ACPDS→signed32 intValue→double→时间比较。展示tz0111endtime不是许可，外层LE64本地时间+反馈变换+Base64不是验签；准确三个磁盘域、序列化、写后读回和失败回退仍开放。未完成可信验证前不能因code、显示日期或文件存在就授予权限。

新App兼容旧服务器的P0仍是：逐接口真实请求/连接代次与最终响应归属；全部动态字段的通用封装和活跃密钥版本；完整响应解码及sign/udid/endtime绑定与拒绝条件；缓存到24B014/UI的同attempt协调。客户端兼容不等于重建能签发旧激活码的服务器。本轮没有交付可上线兼容SDK，也不将报告验收当作完整授权链验收。


## 2026-10-19 接收对象到解析输入的局部续审

本附录仅适用于 DG 2.3.9 原样本。证据：`work/dg239-protocol-receive-binding-20261019/report/RESPONSE_BRIDGE_REVIEW.md`、`response-bridge.json`、`parser-slot-writers.json`；38 项离线测试通过、无跳过，原始失败日志保留。该测试范围不包含完整回调 CFG、真实库调用副作用或实机最终响应。

- 导入槽 `0x100B942C8` 的身份为 `_objc_retain`，不能标为 `_objc_retainAutorelease`；`0x1003A9A04` 用调用后保存槽写入目标，而非直接用 x0 返回寄存器。导入身份不等于活跃实现或对象寿命证明。
- 接收 handle 的 callback/context 存在保存、替换和恢复；调用点 `0x1008C19BC` 与 `0x1008C19E4` 分别使用 handle+0x240 / +0x250，不能混并为登记时的同一上下文。
- `logind0` 的 `0x1008496AC` 解析输入来自当次 frame+0x1160 指向槽；`0x100843FB8` / `0x100849B50` 分别准备对该目标传入零 / frame+0x370 的 `_objc_storeStrong` 调用。仅核对原字节及调用参数，未证明执行效果、同一请求的先后和完整写者集合。槽地址相同不能推出接收对象与解析对象相同。
- `logind1` 的 `0x1005D08A8` 数据来源为当次 frame+0x3768 指向槽。`0x10037C868` 是共享解析跳板，不能当作 recharged 专属实机响应的归属证据。

本轮新增端点归属实机最终响应=0、完整响应解码闭合=0。下一优先项是将 logind0 的登记/包装/累积对象/解析输入及解码结果联到同一事务，再逐接口复核。data3 空输入的完整返回、40 字符参数的活跃来源、百度正常/错误/取消到授权请求的依赖仍开放；既不能宣称百度可省略，也不能据此宣称必需。新 App 的完整旧协议兼容和缓存到主界面链仍未验收，不以局部通过授权发布可上线 SDK。
