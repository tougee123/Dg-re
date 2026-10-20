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

## 本轮逐轮内存、真实失败写入与空串构造纠正（2026-10-17）

本节优先于历史推断，详见`work/dgassistant-239-round-memory/ROUND_MEMORY_AND_DISPATCH_2.3.9.md`及cipher/provider/dispatch/joint子报告。三路复用现有GUI56134/MCP13338/session ae41be7e，仅静态原DG/IDA/已有本地库/cache和host表达式；未连接手机、执行/仿真目标或库、改授权/IDB、兑换、安装、选成功值/域/IMP或导出私密输入/模型。

- **先纠正真实load地址。** 第一采样仍为16520 `081141b9 LDR W8,[X8,#110]`；第二实际在**16528** `291541b9 LDR W9,[X9,#114]`，旧报1652C `2a01280a`实为BIC，不是第二load。global对象与32位选择算式未变。164BC/164C4 retain与164D0实际length之后才采样；两cell为RW __data。原5指令section含__obf的432个page-ADRP seeds、每seed最多192B直线解析只见这两read且未解析到重叠write，fresh IDA也仅ADR/read xrefs；这不是全部别名/其它image/并发writer排除，不拿文件初值或caller快照当实际采样。
- **失败也有实际库写入，不能回滚成全零。** 原CCCrypt在672C先把GetOutputLength真实estimate写进caller moved，6730之后才判断capacity；Update错误6764直接Release，因此可能保留estimate。Final后的6784/88/8C无论其status先写实际updateMoved+finalMoved，Release又是独立真实写/释放屏障。SimpleUpdate在73F4先调CBC可能改输出/IV，callback status0后7410先增加moved，7418才查remaining capacity，错误不回滚这些写。Final的两次operation读取跨GetBlockSize、padding decoder及CBC后内存/私有buffer都分别保留；不把status0当形状、未改写内存或成功明文证明。
- **六caller已逐发生点接按轮源/效果模型。** 原ordinal138/143/148/153/220/225处X2/X3 AST和entry frontier逐项匹配旧unpad来源；428原call与5122显式store组成5550节点的旧符号时序，不是实机trace/闭合native内存。每caller保留short、可选前置、最终、166B4 X21与cleanup；12potential轮分别接24份getter、12份constructor候选计划，22处原UTF8 consumer也按实际ordinal/receiver AST接入，不合并跨调用/跨轮同对象内容。14B00 key/IV标为call入口memory view，**不是该PC的真实LDR**；Create后实际key展开/IV复制版本仍需原调用效果闭合。
- **getCString失败不等于17B都保持零。** 原NSString默认1812CBA7C对capacity17先动态length，再调用getBytes；X2=buffer,X3=16,X4=&本次SP20hex,X5=encoding,W6=4，NSRange整体在SP+0/+8，remainingRange在SP+10hex，不能伪造X7=range。成功CBB08读本次used，CBB0C写buffer+used的NUL；失败CBB18只清首byte，先前helper可能写入的prefix仍在。__NSCFString有真实override186FC14B8，encoding转换/CFStringGetCString另走原分支；4CF48对1DD2DCD00的读取与constructor2248、UTF8 3150不是同次采样，不偷用同slot内容恒定。CF encoder以实际处理字符数==实际length判成功，仍保留partial writes、copy/PAC和动态callback。
- **关键修正：最终NSString非nil不是解密成功门。** 原NSPlaceholderString `initWithData:encoding:`181345738首条CBZ X2，data为NULL的原臂直接1813457B4/7B8/7BC返回unslid1DE6C5078，无encoding/CF decode调用。v3原metadata确认该singleton是__NSCFConstantString、flags7C8、长度0、chars首byte0，即非nil空串。它只是在实际绑定该body/实际nil-data分支下成立，未选择live类/IMP、runtime输入或当前授权；但足以纠正旧通用“非nil⇒data非NULL”和ACPDS“非short+非nil⇒status0/shape/unpad字节”的无条件化。后续parse/设备/时间可能拒绝空串，不能把此静态错误臂叫激活或主界面反例，也不能仅给六个unpad填成功输出。
- **release写集追到真实析构producer。** C++析构B9478实际lookup结果→X22→B94A0认证调用，随后真实superclass/PAC/回环；不是独立选一个析构IMP。DG九个.cxx_destruct及一个dealloc原metadata/全体bytes已核，Partial示例先按self+20/28/30条件free再super dealloc；其.cxx_destruct强清self+40/10/8。真实storeStrong先retain新值、C10E0写8B，再把实际旧值tail到原release，零store不等整调用无副作用。选取17原库函数得到43直接write、30call/认证transfer、17外tail的may-site清单，非完整可达trace。全80B虽没有语法可确证的B0地址参数，仍有504未知地址store与800calls；两lookup不合并、不选nil/tagged/Partial活跃类，不推出noescape/跨release保bit。

**模型层与求解边界。** 新按轮源/条件/内存效果DAG已建立并实际调用三个子接口，但候选库/Foundation body、actual dynamic return/postmemory、全部buffering/optimized路径与callback root仍未全闭，**不是完成版native值/SMT模型**。原23个索引及逐式fingerprint全保留为历史/源条件义务，没有删除或把错误摘要当native公理；旧986/1856/2850也不是新模型计数。本轮完整查询0次，未重跑旧同式超时；旧8.6393s UNKNOWN仅历史引用。尚未证明有效缓存经24B014到管理主界面的真实可达性，亦未证明全局不可达；完整性PASS不能触发AuthVerified。

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

---

## 本轮外部语义、递归与主界面链修订（2026-10-16）

本节优先于后续历史推断。详见 `work/dgassistant-239-external-closure/EXTERNAL_SEMANTICS_AND_UI_2.3.9.md` 及 provider/recursion/callback 子报告。本轮仍只做静态，未连接手机、执行或模拟目标/系统库、修改授权或兑换。旧session19918359已失效；复用同一GUI PID56134/13338，新session为ae41be7e，未另启IDA。

- provider真实格式实参已纠正：3BE7F8从frame+5A8取build C指针，3BE814分配原SP空间，3BE81C写入实际栈槽，3BE828的stringByAppendingFormat:消费该%s vararg，不是X3。原UF签名含memory，但缺显式SP/vararg消费语义；本轮补观察来源，未伪造格式结果。
- 原系统候选__NSConcreteUUID.UUIDString读取receiver+8的16字节，经共享cache真实ADRP/ADD/BR跳板186CE8260→18E5A6ECC uuid_unparse_upper，生成36个大写ASCII字符与NUL。**这不是端到端UUIDString返回UTF8证明**：随后stringWithUTF8String:动态调用initWithBytes:length:encoding:（W4=4），该selector与DG历史替换目标重合。候选返回等式已撤下，未加“构造成功/未修改”替身。
- %lld的512字节token上限有真实本地libc指令依据，不是任意截断。保留原locale/库绑定/指针及域外结果后，重复inner whitespace折成0，digits完整展开512步。852边/428调用/986式保持；显式Rec应用30→28，**含Rec条款仍37**，六次真实AES-CBC、两次outer、四次hash和NUL等未删除。
- 下游原链已到具体主UI：ViewController.viewDidLoad@24ABD0的self经24AC64及各block+32传到24B014→24B8F4→24BFB8→主队列24CBB8。第二回调有独立q2/7+55、真实64位时间窗口及C18=222；第三回调分别保留两次helper、各次FD8、C0C=52和原非调度/回环分支，不能把它们填真。
- 24CBB8的管理界面不是更换rootVC：24E21C分配UITableView，24E260 style=2，24E278 setTableView:，同原self为dataSource/delegate，24E468加到self.view，24E8FC refreshData、24E90C stts。byref经forwarding+24写520是状态写，不是已证semaphore_signal；实际等待消费者仍缺。调度提交、原self来源和UIKit调用链均不等于真实成功事件。

完整新表示同次联合查询：2850式，结果UNKNOWN；仅因真实512-token展开/重复空白折叠才执行这一次新查询，未重复旧同式超时。provider仍有1856条条件source/memory契约；未新增UUID返回内容式、未强制route/成功域、未取模型。**有效缓存经24B014到主界面的完整真实可达性仍未认证，也未证明全局不可达。**

---

## 本轮同状态来源、递归与浮点修订（2026-10-16）

本节优先于后续历史结论。详见 `work/dgassistant-239-state-link/STATE_LINK_AND_REACHABILITY_2.3.9.md` 及 provider、recursion、solver 子报告。只读复用13338 / PID56134 / session19918359；未连接手机、执行目标、修改授权或兑换。

- 慢provider已接到原852边状态中真实638E48第0次调用：继承实际寄存器，按原prolog派生栈帧，再追3B8538→87F820→87F810→43301C及内层UTF8String/strlen/malloc/memcpy原实参。最终采用写B028的生产路线；旧路线虽经过hash却读回旧B028，已弃用，不能把“出现hash调用”当成其产物最终返回。
- 新padding使用同次post-malloc内存的Store/Select链，每次STRB后分别读取D74D0/D4，不再以71对自由输入代替全局；真实+1/+2步进、未写malloc旧字节和末尾低32长度覆盖保留。不冻结文件初值、不assert全清零、不选块长。单块长度和私有栈/可读写域只是组件适用条件，不是新增授权门。
- 原982式加4条真实hash31归纳范围为986。精确折叠后重新按依赖分组，最大分量503含499条原编号式和全部4条范围引理，不是“原501简单加2”。实际十进制key的所有1..20长度域允许精确折叠；原38条含Rec条款现为37，仍含30个显式Rec应用及30条解释Seq条款。7类一步展开与原定义body机械身份一致，递归尾项、实际AES/输入、%lld扫描和失败返回均保留；未换成自由输出UF。
- 浮点621真实来源是6628D8的_CFAbsoluteTimeGetCurrent第0次调用，经6628DC保存frame24B8，再641BBC加978307200.0，641BC0为FCVTZS X8（64位，不是W8）。该结果仍有7条位片/内存重组活用；不能只证明最终数值转换就删掉原FP。保留全部9条FPA2BV转换式及NaN辅助解释，不固定时钟、FPCR或NaN成功值。
- 完整同态分量的新表示和原body一步展开查询仍UNKNOWN；局部证明、纯等式必要子集SAT均不能认证完整501、有效缓存或24B014。provider source/memory仍有明确扩展契约和外部调用未闭合，不能把新命名UF包装成真实实现已还原。完整callback CFG与主UI续执行仍未证，也未证不可达。

---

## 本轮对象字节桥与provider填充修订（2026-10-16）

本节优先于后续历史结论。详细新增证据：`work/dgassistant-239-byte-bridges/BYTE_BRIDGES_AND_PADDING_2.3.9.md`；子报告见该案bridges、provider、solver目录。只读复用13338 / PID56134 / session19918359；不连接手机、不修改授权、不兑换。

- 五条桥的实际对象/别名/编码4及下游已落实：两次独立文件NSData→各自NSString/UTF8String→原外层解包→各自C串构造/UTF8 NSData→plist；ct的65C494 ACPDS→656244编码→66189C JSON。两次同path读回不合并内容，nil字节不当空串，UTF16单位数不当UTF8字节数。
- 原BV/UF绑定可推出748@65659C、779@656244的非nil guard；前三个guard仍须条件化。非nil不是合法明文或授权成功。五份原anchor全部保留，仅作已证guarded同值替换，11份受影响公式同context反例UNSAT，不添成功返回。
- 462条必要式的纯Seq等式子语言经机器检查可一致转换EUF表示，约3.57秒SAT；3份UF签名和全部共享BV对象/guard/q/global保持。完整501因真实Rec/解释Seq/FP被明确拒绝翻译，等价归一化查询仍UNKNOWN；不能用462的SAT认证实际字节算法或整链。
- provider原strlen与padding已推进到同来源C字节、长度、分配/padding和LE消息字：末尾只STR W写bitlength低32；原清零循环有依赖逐次全局采样的额外步进。全清零normal domain只是组件适用域，不是原授权新增拒绝门，不固定全局、不选择自由N/摘要/route，也不直接套标准MD5 padding。
- 两个原stack block构造臂24AE80与24AFB0均指向24B014，实际q/capture writer及63137C入口保存已核原字节；未注假block。24B608转80B9CC仍是下一验证，不是直接主UI。**真实有效缓存到24B014/等待恢复/主界面的完整可达性仍未认证，也未证明不可达。**

---

## 本轮AES真轮与约束分量修订（2026-10-16）

本节优先于后续历史结论；完整新增证据：`work/dgassistant-239-core-closure/CORE_CLOSURE_2.3.9.md`，三路子报告为该案 `aes/FINDINGS.md`、`provider/FINDINGS.md`、`solver/SOLVER_PARTITIONS_2.3.9.md`。只读复用13338 / PID56134 / session19918359；不连接手机、不修改授权、不重新兑换。

- AES轮、密钥展开与实际mode descriptor目标已补原字节。新完整表达式接入同一852边、六次ACPDS，旧AES结果UF不再被其CBC关系引用；原key/IV/cipher来源及失败保留，真实系统绑定仍有版本适用前提。
- 慢provider的22是与sysctlbyname("kern.osversion",...)同buffer配对的strcpy预填常量，不是已观测系统版本；五组先后路径未全证。4319E8可由uname及UIDevice.systemVersion产出版本片段，-520-仅fallback，不能固化旧替身-520-22。OC/C两路日期必须分开。原64轮压缩/四字feed-forward已展开为定义绑定；消息padding、完整来源和slow route仍未闭合，没有通过自由digest/route伪联立。
- 原982条件完整拆为448个共享声明分量；初检445 SAT/3 UNKNOWN，两个小分量精确复核SAT，最大501分量全绑定15秒仍UNKNOWN。旧74条无前提恒等证书中新版仅73条哈希匹配，可等价化简为909条；它们不在最大分量，不能冒称已解决其瓶颈。
- 最大分量457条BV/UF必要式SAT，加回五条对象/byte/Seq桥后462条仍UNKNOWN，已定位662998、649C10、667D68、65659C、656244的桥定义及641BBC的FP条件。不得删桥、独立返回或把必要子集SAT当全式SAT。
- 五个回调/状态全局均writable；direct xrefs不能排除间接writer，不能固定文件初值来通过opaque-progress。24B014仍是原caller布局及必要门接口，不是本轮真实回调/UI事件。**未证明真实有效缓存必达24B014/主界面，也未证明不可达。**

---

## 本轮算法产出与同状态联立修订（2026-10-16）

[本轮真实库字节与联合约束报告](work/dgassistant-239-algorithm-bound/ALGORITHM_BOUND_STARTUP_2.3.9.md)优先于历史正文。3个子智能体复用只读IDA13338/PID56134/session19918359；未连接手机、运行或仿真目标、改授权、兑换、导出模型/密钥/有效许可，不用成功替身。

1. **原外层字节已接到扫描输入，不再是独立解析返回。** 冷852边同状态中展开6B2BB4反馈/ROR3、3EA174十进制key文本及实际strstr/strlen关系；65DA94原指针经可证明的字节重组恒等式，关联到strstr返回+12的同一解包字节后缀。范围/内存fallback仍保留，实际文件字节未观测。六次ACPDS而非原重点四次均保留原cipher/kaiv/输出身份。
2. **找到并核对真实候选libc字节。** 本机20D67标记libsystem_c的5完整函数与拆分缓存同字节；链为_sscanf→_vsscanf_l→___svfscanf_l→_strtoimax_l。实际%lld整数token最多512字节、符号占额、前导空白不占；signed溢出饱和并写errno34，scanf不读该errno，仍写64bit和返回1匹配。旧两个UNREDEEMED scanf UF不创建，23项数学测试UNSAT；locale/合法内存/INT_MAX长度域未全局假定，未认证手机实际加载版本或完整机器等价。
3. **撤回严格PKCS7必要成功门。** 真实CommonCrypto/corecrypto代码并不支持把“全部尾padding字节均相等”直接设作ACPDS非nil必要条件；末字节helper只做范围掩码。已在最终联合查询前移除过强门，实际unpad仍绑定同一padded字节而不选成功。后续只读v3 slide header/页链补证AUTH槽1E2376EF0静态目标为1D50E7CDC，并接到corecrypto解填充；这是冻结求解后的证据补充，不回填算法已展开或runtimePAC成功。-4303为AlignmentError，不能误称DecodeError（-4304）。这也不直接证明DG接受坏授权。
4. **provider与24B014条件纠正。** 原provider有4处53B8调用发生点；快缓存检查3B77A8/BC后，真正返回在3BCA54再读B028，不能当原子快照。11次原provider实际返回只加有条件缓存接口，未强选fast、未填设备ID；慢路径完整产出仍开放。24B4C4 helper返回不参与授权比较，不能新增一门；真实四条数据门、原失败返回、opaque进度回环及helper最后FD8采样均分别保留。
5. **真正提交一次同状态联合查询。** 852原边、428调用、0未知opcode，在全部原条件/定义之外加入扫描、解包、11provider关系与原caller/24B014必要条件；去掉99重复AST引用后982条件，30.690秒返回UNKNOWN(timeout)。五个block/q/payload/invoke/52局部等式仍UNSAT。caller布局为原字节接口前提，不注入假block；该查询不是完整callback CFG或UI事件认证。

八个getter标签由同次冷初始化落实：CB600=tz0111cs、CB640=tz0111cc、CB680=tz0111ct、CB6A0=tz0111cst、**CB6C0=tz0111cst12（不是cc2）**、CB6E0=tz0111udid、CB720=tz0111udidd、CB740=tz0111cc2。字段名明确不等于这些字段已通过校验。

**当前边界：** 原608候选仍被拒绝为有效解码路径证据；本轮新增真实字节/算法关联不靠旧SAT续证。完整AES轮/密钥展开、getCString/Base64/UTF8/解析真实产出、文件/设备输入及慢provider、环境与跨采样一致性仍未全兑现，真实有效缓存到24B014/主界面未认证；不将条件数、字节数当整体完成比例。

DG本轮174区间长度和121011字节、去重118343；新增去重71447，累计去重319144原文件/IDA一致字节。18个外部库函数13408代码字节及表单独核，不混入DG/IDA计数。六份原稿完整备份；冻结子报告和旧UNKNOWN保持原来源/版本边界。

---

## 本轮同状态静态接链修订（2026-10-16）

[本轮852边同状态原字节报告](work/dgassistant-239-state-bound/STATE_BOUND_STARTUP_2.3.9.md)优先于下方历史正文，三路子智能体与父审共同复核，只读 IDA 13338 / PID 56134 / session 19918359。未连接手机、执行/仿真目标、修改授权或兑换；没有成功返回替身、模型或有效缓存导出。

1. **前态与正桥已实接，而非分别设成功对象。** 新 `cold_fused.py` 在同一静态寄存器/逐字节内存状态中传播冷入口5 + 首缓存前置234 + 首缓存时间180 + 第二次非NULL桥10 + 设备/一致性/原completion423 = **852条原边、428次调用、0未知opcode**。所有原分支条件仍待同链兑现；0未知opcode不代表Foundation/AES等真实结果已展开。
2. 首缓存 `6499C4→662334→63EFF8→64E724` 的字典与 `6451F4/frame1F88` 保持同对象；不能用后续 `643A48/6468AC/65C804` 代替首次读取。纠正最短CFG两种错误：期限拒绝臂原本通清理；另一捷径要求同一次decoder同时NULL/非NULL，两条原分支即UNSAT。正确路经原 `%lld` 扫描，`88C6F8`把X2输出指针送SP首变参；扫描状态1才写，失败保留旧值。解析算法/状态仍未兑现，未选成功值。
3. `6313A4→66A138` 的原冷初始化自然写出 `%@` 两字节 `25 40`，在后续 `6389E0` 同状态guard=True；BSS初始化flag保留原分支条件，未强置零。只读 `100AE7F90` 原字节 `00000040e427cd41`（978307200.0）绑定原FADD/FCVTZS。封存847边运行中guard=False是缺冷前态，不是App实际格式错误；四个历史UNKNOWN也未回填成新852边求解结果。
4. `63F9BC index1→64161C→65EF58→65659C→65C804` 的真实非NULL桥五项身份在同一状态成立。第一plist `63EFF8`、第二plist `65C804` 和原JSON IMP `66189C` 分开；CT/CB6C0、四次ACPDS、hash31/NUL比较、日期和设备provider按实际对象及occurrence相联。不冒称未知CB6C0就是cc2，不把关联操作项当实际明文。
5. 原 `65DF98` 前五个局部等式的否定均UNSAT：X0为原block、q单元为原q、W1为 `SDIV32(q,3)+111+65E378晚采FD8`（32位）、X8读取原block+16、原C0C出口写52。原caller `24AE80/84` 的block布局接口指向24B014；没有伪造block内存或执行回调。24B014自身复算、状态复核及FD8再采样仍是后继条件，不等于直接显示主界面。

**证据边界：** 旧608边候选继续为 `REJECTED_AS_VALID_DECODE_PATH`；旧847边四阶段联合查询仍是历史UNKNOWN(timeout)。新852边只做当前源码同状态传播、常量兑现和局部证明，未新跑全链SMT。真实Base64/缓冲区/AES/UTF8、扫描、Foundation解析及设备源仍未全部兑现，因此“有效缓存到24B014真实可达”和“旧授权完整互通”均未认证；不再用18/77、59/77或边数推算整体完成百分比。

本轮293区间长度和78036字节、去重77594，新增去重37746，累计去重247697原文件/IDA一致字节；六份写前原稿完整备份。字段/回调子报告封存的847边记录不改写，由新cold852报告限定当前补充。

---

## 本轮子智能体并行复核修订（2026-10-16）

[三路原字节复核与纠正](work/dgassistant-239-parallel-audit/PARALLEL_AUDIT_2.3.9.md)优先于下方历史正文：**撤回旧608边候选作为“有效缓存成功路径”的证据资格**，不再仅写“缺动态见证”。原6468AC解包返回，经65DD90/94/98形成非零索引；63F9BC旧候选选择0到656580，明确要求返回NULL。原641D08写零到另一NSString单元；从真实66A138初始化复核后，frame2910与24F8相差16字节、不别名，65659C编码接收者仍为nil。旧SAT与完整历史JSON保留，不证明这一条是真实成功路径；也不据此断言整个App合法授权不可达。

已补出非NULL原分支：63F9BC索引1→65BB7C→657674→64161C stringWithUTF8String:→65EF48 retain→65EF58写frame2910→65659C编码。具体参数/保存点有原字节，但整组CFF条件及真实解密输入尚未联立，UTF8返回不能替换为成功对象。首次reader的6499C4/662334/63EFF8等不在608候选中；后续643A48/6468AC/65C804重复读取解析确实在，不能混成同一次前置闭环。

6389E0原清单误标为block调用，实际是NSString stringWithFormat:（CF1014CB820、首栈参数来自frame34B8），不是24B014证据。38个字符串门已按来源归组、找到2组严格同参range身份；这不是新增许可通过，不能从旧59门机械扣减。CF1014CB6C0字段名仍未证，不擅自等同tz0111cc2。另补65542C原表常量后继到66A138；FD8有直接写入及多调用生命周期，不能假定零或跨采样稳定。

上轮458项FP/整数局部定理及明确输入子域的数值同源关系保留；18/77与59/77仅为旧候选清单口径，**不是整体进度或剩余工作比例**。本轮123个锚点长度合计13692字节，去重13236，其中新增5644，累计去重209951字节；六份写前原稿按哈希完整备份。只静态，未连接手机、执行/模拟目标、改授权或兑换；有效缓存到24B014及同次UI闭环仍未认证。

---

## 本轮FP分段证明与真实输入耦合修订（2026-10-16）

[本轮逐字节与数学证据](work/dgassistant-239-fp-partition/FP_PARTITION_REACHABILITY_2.3.9.md)：4处FCMP、2处FCVTZS的求解超时已解决。458项分段反命题均UNSAT；全位向量对照求解约8.6秒，正常域约27.9秒，构建时间另列。用原表达式等式定义共享节点，不把新名字作为任意成功值。全位向量对照仅代表RNE/FZ=0的非陷阱数据场景；正常域等价证明覆盖四种舍入和相应FZ情况，未假定实际FPCR为0。

两份十位ASCII数字明文各自的intValue与原31哈希按同一字节计算，15次数值调用关系绑定，覆盖18个数值门，数值耦合检查约29.6秒返回SAT。它是明确输入子域，不是实际合法AES/缓存见证，CB6C0该形状也未被推广到所有producer输出。仍有59个输入相关门和实际文件/密文/设备/前置状态绑定义务；旧608边SAT不认证有效缓存到24B014真实可达。

FCVTZS应明确为向零并按signed32饱和的非陷阱数据语义，不是低32位回绕；NaN的数据结果为0，异常陷阱另论。正常有序时间达到2147483647秒后，该signed32严格大于门不可能通过，已独立证明。十位数字文本的真实哈希落在1311405259169280至1557293745263520，不把它当另一份到期时间。

本轮重新核对13段共360字节，其中320字节重合、40字节新增，累计去重204307字节；6份写前原稿已备份。仅静态、未连接手机、执行目标、改授权或兑换，未导出模型/授权材料。以下保留历史正文，旧FP超时状态由本节取代，历史实机证据等级不升级。

---

## 本轮具体解密、比较与浮点语义修订（2026-10-16）

[本轮原始字节与被调函数报告](work/dgassistant-239-callee-semantics/CALLEE_SEMANTICS_2.3.9.md)：已逐项关联285次调用与77个相关分支。ACPDS:kaiv:的原IMP为16380，实际链为Base64 options=1→AES-CBC/PKCS7→UTF8；五处字段/kaiv对象不同，不能统一套用其他响应入口。CCCrypt经36919C转发时，11个ABI参数及32位状态均有静态相等证明，不换参数或伪造成功。

比较语义纠正：3AF36C是NUL终止完整匹配，等0/不等1；372154是strstr，560474是strpbrk字符集合搜索，不是另外两个相等函数。66189C已识别为1015EC3E8保存的原JSON IMP直接调用，不是未知block。

四处FCMP和两处FCVTZS已落实到原指令与NSDate D0返回：四处比较共享N1采样，另一次截断使用独立N2；signed32 intValue、unsigned64哈希和FP转换分别保留。旧IR没有正确关联浮点返回寄存器，旧608边SAT不能升级成真实callee条件下的全路径认证。一致性约束版仍SAT；含真实FP的探索限时UNKNOWN，不能宣称全链已经验证，也不等于不可达。

本轮578段、204267个去重文件字节与IDA一致；四个加载器绑定槽和两个无文件字节BSS槽明确剔出原文件字节计数。仅本机静态，未连接手机、运行目标、修改授权或兑换。5份原稿写前备份；以下保留历史内容，相关旧缺口和模型结论由本节及新报告限定。

---

## 本轮整数语义、格式F与启动续执行修订（2026-10-16）

[本轮逐字节证据与分支索引](work/dgassistant-239-static-completion/STATIC_STARTUP_CLOSURE_2.3.9.md)。本轮静态证据覆盖508个合并区间、127784个去重字节，IDA与原文件一致。3EB224返回uint64十进制累计值，TLS错误文字是独立通道；NULL/空串/非数字返回0，检测到new<old回绕时返回全1，不能称为已证明完备的strtoull实现。cc2的F已解为`%llu`（25 6c 6c 75），P/G格式化输出与后续signed32 intValue检查须分开。

ct解密文本另经UTF8String→3AA0AC，按`h=(31*h+uint8(c))%10^16`生成frame23F8的H；它不是64位到期时间。两处H<=B、H<=C与转换为double后对新NSDate的LS拒绝门，与ct的intValue时间门及cc2时钟门分别保留。

65A968起到65DF98的608条原边、285次原调用已在同一SSA存储关系下闭合；表项与恒定索引无矛盾，覆盖指令无未建模项。外部解密/比较及浮点结果仍为符号条件，不代表某份具体授权已验证。调用者传入的block invoke确认为24B014；原初始化保存同一block/challenge，原成功出口生成参数并调用，24B014仍自行复核后转入后续阶段，而非直接主界面。

本轮优先缺口已静态补齐：整数返回语义、F与ct/udid到第一回调的条件调用链。不再沿用下方历史“F未知／该静态边未接通”的当前状态；服务器加密函数的具体运行结果和第一回调实机事件不因此升级。

本轮仅连接本机13338做静态分析，未连接手机、执行目标、修改授权或兑换。写入前原稿已按哈希备份；以下保留历史内容，相关旧缺口状态由本节及新报告取代，未新增的动态/密码学证据不升级。

---

## 本轮cc2来源与时钟门修订（2026-10-16）

[最新原字节证据](work/dgassistant-239-cc2-origin/CC2_ORIGIN_2.3.9.md)：cc2已由A48候选槽推进为三来源回退：先保留block+0x50格式化值；其intValue不晚于截断的NSDate Unix秒时改取全局1015EB0A0；全局格式化值也不晚于另一次采样时，才用响应endtime的`%@`结果覆盖。P/G上游已定位3EB224返回值、全局写入及block捕获；其业务语义与格式F仍有缺口，不能写成cc2始终等于服务器endtime。

读缓存已确认最大两两时钟差分达到122秒进入493800清理；未达到时依次检查cc2>A、cc2>B、cc2>C，并再与新NSDate时间比较，不是三选一。udid后续和ct后续unsigned比较补边见新报告；有效缓存到24B014完整边链仍未全部证明。核对去重21366字节，16份原稿备份；本轮仅静态，无手机连接、授权修改或兑换。以下保留历史证据，旧缺口状态以此段及新报告为准。

## 本轮静态契约增量：cc2 写入槽与差分汇合（2026-10-16）

[本轮证据报告](work/dgassistant-239-cache-contract/CACHE_CONTRACT_2.3.9.md)：13338/PID 56134，18 段共 1444 字节与原文件一致。确认 `6274C4` 以 `*frame[A48]` 为值写入 `tz0111cc2`；尚未证明该槽最后到达定义，不能等同服务器 endtime。三时钟分支已推进到差分保存、固定索引 `5D8F → 64C80C` 汇合及与 D_BC 的 signed 比较，不能直接称为最终选钟策略。

回调出口 `65DF98` 调用传入 block 的 invoke，非硬编码 24B014；有效缓存到第一回调仍有条件边缺口。本轮不连接手机、不修改授权、不兑换。初版局部分析器误将未知表沿用为旧表，相关输出已标记 REJECTED，修正后的探索与独立字节证据分开保存。以下为历史章节，未获得的新证据不作升级。

## 本轮缓存字段修订：cc2 原文本与拒绝副作用（2026-10-16）

[最新字段报告](work/dgassistant-239-cache-fields/CACHE_FIELDS_2.3.9.md) 补充上轮结论：cc2 缺失不只是返回，原代码调用 493800 清理逻辑，离线观察到偏好键及三目录缓存删除 API，并向主队列安排 2.25 秒校验 block 与 2 秒 abort block；不是设备实删或实际发请求。cc2 非 nil 后还搜索原文本 `tz0111cc2 = ` 并用 `%lld` 扫描，语义相同 XML 不保证兼容；公开 XML 的扫描输入为 0xC，尚未实机重现。公开 OpenStep -1/0 负例完成原扫描及拒绝路径，未构造有效许可。

原字节还确认 clock_gettime(0)、CFAbsoluteTimeGetCurrent 转 Unix 秒、time(NULL) 三来源及 cc2 signed <= 时间比较；它不同于 tz0111ct 的 ACPDS→intValue→FCMP。完整时钟选择策略、cc2 产出关系、合格缓存到全部字段及第一 callback 同次链仍缺。本轮无手机连接/附加、授权改写或兑换；2648 字节比对，14 份原稿备份。最新累计清单位于字段报告目录，下方章节保留为历史证据。

## 本轮静态 reader 修订：第一回调与缓存回退（2026-10-16）

最新 [静态追链报告](work/dgassistant-239-static-reader/STATIC_READER_2.3.9.md) 优先于下方历史“fallback 未知 / 读取到 plist 未接通”的表述。24B014 的原分发表已解析，条件通过后构造 24B8F4 block 并调用 80B9CC；不匹配静默返回，不直接进入主界面。离线原 reader 显示 Caches→Preferences→Documents/.apple 的两轮存在检查，缺失才继续；Caches 读 nil 的测试未回退。离线 basename 为 a089...，不同于实机 ae098...，不可混用。

新增原指令连续链：文件模型→原 6B2BB4→设备种子文本包含检查→NSString→UTF8 NSData→plist 入口，公开非许可输入逐字节一致。解析后 count 必须为 8；8 个无关公开键只推进到首个记录字段读取，没有授权写入。文本包含/结构检查不是数字签名；远端 sign 不自动成为缓存读取串行前置条件。首回调实机事件、另两副本实际读回、缓存全部字段到 callback 同次闭环仍缺。本轮未连接手机、附加、修改授权或重新兑换；13 份报告已备份，当前累计核验入口在静态报告目录。

## 本轮内核追踪修订：bind EPERM 与 Caches 写后再读（2026-10-16）

最新证据及边界见 [内核追踪报告](work/dgassistant-239-kernel-trace/KERNEL_TRACE_2.3.9.md)，累计核验入口为 `work/dgassistant-239-kernel-trace/manifest.sha256`。本节优先于下方历史阶段的“底层 errno 未捕获 / 全部写后再读未证”表述；历史记录保留供追溯。

- 原版 debugserver 的 socket 成功，bind 实际返回 errno 1（EPERM），清理后的日志才是 0；具体策略来源仍未确定。
- SSH raw PTY + 原版 --fd=0 已实际握手。稳定启动后 task_for_pid 成功，但 PT_ATTACHEXC 阶段调试器 SIGSEGV；未获取成功附加/断点事件，未继续绕过。
- 无注入正常启动 PID 61342：三目录各有 1281 字节临时写入、fsync、rename；约 20 秒后 Caches 目标 read 1281，写/读磁盘块相同。Preferences/Documents 在采集窗口无读回事件；rename 输出未包含目标参数，不补造缺失字段。
- 三个实际目标最终摘要相同。审计自身的只读取摘要不算 App 读回；24B014 及 read→decode→校验的同次用户态链仍缺。
- 本轮未使用早期 Frida、未改授权或重新兑换。临时工具已清理；用户确认 DG 管理主界面。

# DGAssistant 2.3.7 与 2.3.9 本地差异报告

## 本轮真实根路径与 debugserver 退出补证

[最新补证](work/dgassistant-239-debug-path/DEBUG_STORAGE_PATH_2.3.9.md)已定位三份真实缓存：系统真实`/private/var/mobile/Library/Caches/`、`Library/Preferences/`、`Documents/.apple/`下同名`com.apple.ae098f4c9f0.plist`。SSH处于RootHide路径视图，须经`/rootfs/var/...`访问系统根；`/rootfs`不是App应硬编码的前缀。三份1281字节、Base64外包裹及末尾NUL文件同哈希，正常无Frida启动后全部更新为另一相同哈希。**真实落盘存在和自然更新已证；DG写后再读同一新版本的同次身份/字节关系仍未证。**

原debugserver版本/参数处理正常，TTY输出定位到网络建立失败，原子进程仍返回0；原arm64清理字节会清零errno，日志err0不是监听成功。尚无可信底层errno或附加拒绝证据；Frida观察临时工具的独立SIGSEGV及原reverse-connect失败分别记录，不冒充DG反调试原因。`log`为shell builtin，纠正此前“shell函数”措辞。

24B014唯一启动探针就绪后，PID60554约0.593秒终止，第一callback及后装详细观察均无事件；停止重复早注入。随后临时工具/Frida/转发清理，普通启动PID60593存活超过10秒，用户确认管理主界面；没有新兑换、校验替换或人为授权改写。reader新增307条原指令定位了C字符串→NSString→UTF8 NSData→plist的中间静态边；离线完整桥尝试未到目标，失败保留，不升级为真实闭环。

11份正文修改前均备份；当前完整性入口为[本轮累计清单](work/dgassistant-239-debug-path/manifest.sha256)。后续较早章节是历史轮次记录；其中“路径未找到”“本轮未重启”等不得覆盖本节最新证据。

## 本轮存储编码与调试端点续审

[最新存储续审](work/dgassistant-239-storage/STORAGE_CODEC_2.3.9.md)已接通原writer的UTF8String→629040→strlen+1→NSData→writeToFile字节链：外层为8字节本地time头、循环第二输入/反馈旋转、相邻字节反馈及Base64，文件包含末尾NUL，不直接是明文plist。原encoder的10组公开文本输出与独立实现一致；原6B2BB4 decoder还原8组非空文本，对2组header-only输入返回nil。**这是离线原指令/显式Framework模型单元，不是实机许可解码或授权接受；公开fixture-key不是真实key。**内层tz0111ct加密、服务器endtime和展示日期继续分层。

无目标debugserver测试也在监听前退出（SSH返回0、无诊断），因此上轮连接时序问题不是已证唯一原因；本轮未连接LLDB、未附加DG或安装断点，24B014仍缺实机事件。实际存储域、准确序列化/第二输入来源、完整读文件到解包再到plist的身份边仍待证。当前DG PID60198保持存活，本轮无App重启/Frida附加、无授权改写/兑换；临时原工具与挂载已清理。10份修改前正文有备份；[本轮累计清单](work/dgassistant-239-storage/manifest.sha256)为当前完整性入口，下文较早章节按其原轮次理解。

## 前轮真实 endtime 产出与调试补证

[最新产出补证](work/dgassistant-239-producer/PRODUCER_CHAIN_2.3.9.md)：PID60114已实机捕获61ACB8的block+48字典读取endtime（__NSCFString）→原格式化→原CCCrypt（0/0/1/keylen16/IV非NULL，10→16字节，status0）→24字符原返回对象→原setObject:forKey:写tz0111ct并自然返回。关键对象身份关联成立；第一completion原endtime非零结果=1，producer数值与其原转换值相等。此产出关联不再只是模型，但不代表全部许可检查或跨阶段对象指针相同已证。

该PID先从旧ct记录通过原时间门并进入24BFB8/24CBB8入口，约1468ms后才新产出ct，不能倒接因果。三条逻辑路径写调用均1281字节/options1/返回1；写后SSH未找到原路径或已知RootHide前缀路径，外层格式、实际落盘及写后再读仍未闭环。tz0111ct字典字段不混为standard偏好顶层键或tz0111endtime展示缓存。

24B014仍无实机事件：预加载仅onEnter轮在第一worker前终止；原版临时debugserver的转发Connection refused、LLDB握手未成功，未安装断点。无Frida启动曾短暂退出，随后PID60198持续存活且用户确认管理主界面，退出原因不归咎于单一因素。未改授权/输入/结果/时钟、未重新兑换；临时工具/服务/转发均清理，自启不恢复。9份正文修改前已备份；最新完整性以[本轮累计清单](work/dgassistant-239-producer/manifest.sha256)及离线verify_producer.py为准，历史清单保留不改。

## 前轮真实比较与启动来源纠正

[最新轻量采集](work/dgassistant-239-live-predicates/PREDICATES_CAPTURE_2.3.9.md)已实机抓到第一sign原结果1、第一udid比较0，以及63137C独立udid对象→UTF8→原比较0。PID59897同时捕获第二响应AES/RSA成功组件→24B8F4→63137C→24BFB8→主线程24CBB8正常返回；**该PID的第一sign/udid在UI返回402ms后才判定，不能硬接成该次UI的串行前置门**。PID59980另捕获记录字段tz0111ct→原ACPDS解码→intValue→649084原时间比较→第三callback和主UI；此处不直接消费所定位的endtime对象，也不是标准偏好域顶层tz0111ct键（最终该键不存在）。

前轮当时仍缺第一callback与endtime到ct产出关联；本轮已补真实产出，具体边界及最新清单见首节。较早报告中的“无成功输入”“字段未捕获”等均按各自轮次理解，不将独立模型升级为全实机。

分析日期：2026-10-16。类型：普通授权逆向，flavor=null；不作恶意软件或漏洞定性。

**前轮合法激活实机增量**：已真实捕获兑换字符串306→4AE7B8→4BF660复验；后续运行中AES/RSA成功、字符串257及C18=222已出现。无Frida正常启动由用户确认进入管理主界面，随后只读确认实际tz0111endtime偏好缓存存在。轻量提前附加进一步捕获24B8F4→63137C→24BFB8→主线程24CBB8正常返回、进程存活；入UI时C14/C48仍为257/2，不能将四个状态统一作UI门。第一callback及逐字段sign/udid/endtime仍非同次全程捕获，不宣称全部线协议已闭环。详见[合法激活采集报告](work/dgassistant-239-live-success/ACTIVATION_CAPTURE_2.3.9.md)；最新完整性见该案例manifest。以下“无可用激活码”属于前轮历史边界。

**实机续审更新**：已在明确授权下临时启动仅回环监听的 Frida，并从启动后附加捕获原响应 completion、剪贴板处理及 `exit(0)`。一次真实 completion 为 HTTP404 / 200字节 / NSError=nil，不能当作有效许可或“激活码被拒绝”。启动前裸附加存在显著时序干扰；晚附加能到上述原路径。相关状态字仍为2/257/257/2，未进入业务UI；用户目前没有可用激活码。详见[实机报告](work/dgassistant-239-live-auth/LIVE_AUTH_2.3.9.md)，本轮之后正文完整性以该案例manifest为准。临时服务与转发已停止，开机自启未恢复。

## 1. 结论与边界

**2.3.9 不只是更换图标与版本号：除 Foundation 方法替换，还存在九项 C API 重绑定；已测 IPv4 连接受目标地址筛选和端口改写。“结束持久化”的同一子命令路径由旧版 31 次目标请求缩为三次。**
另一方面，31 个清理/隐藏/恢复核心用例、15 个底层进程终止用例与 2.3.7 的原有断言一致；不能将底层匹配逻辑相同误写成上层目标集合也相同。
随包 helper 和其他工具逐文件哈希相同，主程序签名声明的 72 个 entitlement 也相同。
后续深挖另完成 78 个有断言的用例/安装记录，包括真实种子、九个隐藏/恢复/刷新按钮及九种失败输入；授权结果交付仍是明确替身，不是有效许可证或真机运行证明。

初轮及离线深挖的历史范围与授权见 [初轮 scope.md](work/dgassistant-237-239-diff/scope.md) 与 [深挖 scope.md](work/dgassistant-239-deep/scope.md)：当时只对本地包解析、反汇编和内存模拟，另按明确授权启动两个独立 IDA GUI 并接入 MCP；当时不安装、不原生启动 iOS 样本、不连接授权服务器、不操作设备。后续实机观察另受[实机scope](work/dgassistant-239-live-auth/scope.md)约束，不把两种证据混写。
既有 13346 的旧版 IDA 数据库未切换或修改，旧版总报告、子报告及证据清单保留原状。

## 2. 包、身份与权限

| 项目 | 2.3.7 | 2.3.9 |
|---|---:|---:|
| TIPA 大小，字节 | 25,643,741 | 25,993,523 |
| 归档内普通文件数 | 23 | 23 |
| 普通文件解压大小之和 | 42,599,207 | 42,654,497 |
| 主程序大小，字节 | 23,800,176 | 23,272,704 |
| `__obf` 大小，字节 | 11,952,380 | 11,382,072 |
| LC_FUNCTION_STARTS 入口数 | 11,458 | 11,575 |
| 本次解析的 ObjC 方法数 | 247 | 247 |
| 签名 XML entitlement 项数 | 72 | 72 |

主程序减小 527,472 字节，但三份图标各增大 194,254 字节，导致解压文件总量略增；归档压缩率也不同，不能用 TIPA 大小推断功能多少。
函数入口数包含辅助函数和混淆产物，**增加 117 个入口不等于增加 117 项功能**。

23 个文件无新增、无删除，5 个修改：`DGAssistant`、`Info.plist`、`icon.png`、`icon@2x.png`、`icon@3x.png`。
`Info.plist` 逐键仅 `CFBundleShortVersionString` 从 2.3.7 变为 2.3.9；Bundle ID 仍为 `apple.allIDTDG`，build 仍为 1，最低版本声明仍为 iOS 10.0，SDK 声明仍为 iPhoneOS 18.2。
签名声明相同不代表这些权限一定在设备上生效，也不代表程序行为相同。

图标由旧版“动态版”文字、较模糊的画笔尺子，换为红黄“新版”标牌及重绘图案。
预览保存在案例的 `2.3.7/icon-preview.png`、`2.3.9/icon-preview.png`。

以下 18 个文件逐字节相同：

```text
520.ini, 520.plist, 522.ini, Assets_noVoice.mp3, DG.jpg, PkgInfo,
TrollStore.tar, _CodeSignature/CodeResources, ct_bypass, insert_dylib,
ldid, libcrypto.3.dylib, libiosexec.1.dylib, trollstorehelper,
en.lproj/Localizable.strings, zh-HK.lproj/Localizable.strings,
zh-Hans.lproj/Localizable.strings, icon.jpg
```

因此可沿用旧版对**同一 helper 文件本身**的指令分析；不能据此沿用主程序何时调用 `refresh-all`、传什么参数或如何处理返回值的整条结论。

## 3. 主程序实质变化

### 3.1 新增 Foundation 方法替换

新导入 7 个符号，无删除导入；动态库依赖列表相同：

```text
NSHomeDirectory
class_addMethod, class_getClassMethod, class_getInstanceMethod
method_getImplementation, method_getTypeEncoding, method_setImplementation
```

不仅是导入表变化：新版 `0x10037DB68` 安装入口、`0x10037EB4C`、`0x10037F414` 子入口实际执行原始指令，进入运行时方法查询、保存原 IMP、替换 IMP 的路径。
在“相关类和方法均存在”的显式运行时模型中，观察到以下替换：

| 类/方法 | 新包装函数 VA |
|---|---|
| `NSProcessInfo operatingSystemVersionString` | `0x10037B6D8` |
| `NSString componentsSeparatedByString:` | `0x10037BA88` |
| `NSPlaceholderString initWithData:encoding:` | `0x10037C0AC` |
| `NSJSONSerialization JSONObjectWithData:options:error:`，类方法 | `0x10037C73C` |
| `NSString initWithBytes:length:encoding:` | `0x10037D8D8` |

静态还存在 `NSPlaceholderString` 查询/兼容分支，实际落在哪个类取决于设备上的方法实现，不能把模型中的类存在性当作真机事实。
五个普通输入用例均走原 IMP 转发，系统版本文本、普通分隔结果、含 serial 的数据/JSON/字节文本保持原结果。
这证明新增了替换层；**没有证明它会伪造序列号、修改系统版本，或一定提升稳定性/反调试强度**。
它的全部异常、类缺失及其他输入分支本轮未穷举。

新版隐藏后缀入口为 `0x1000E1C74`，其中直接调用 `0x1003B5C4C`；这条种子初始化链可到达上述替换安装代码。
后续已补齐 dyld 对已加载映像的回调，实际执行原始重绑定扫描器，而不是手工填写原函数指针；完整种子链的 18 个用例通过。见深挖子报告 §3。

### 3.2 新增配置访问代码与常量

新版 `0x1000AF3EC` 可构造：

```text
NSHomeDirectory()/Library/Preferences/com.opa334.TrollStore.plist
    -> [[NSUserDefaults alloc] initWithSuiteName:上述完整路径]
```

原指令在 `0x1000AF5F8` 调用 `NSHomeDirectory`，`0x1000AF624` 格式化相对路径，`0x1000AF640` 拼接，`0x1000AF65C` 调用 `initWithSuiteName:`。
模拟中仅返回相应 defaults 对象，未观察到该函数自身写配置。
进一步逐字节扫描 `__text`/`__obf` 的直接 B/BL、ADR/ADRP 引用、全文件绝对指针，以及 ObjC IMP 和初始化入口，均未找到此函数的静态来路；IDA MCP 的入站交叉引用也为空。
因此目前是**静态孤立的配置对象构造代码**，不是已经证实可用的新设置入口。该阴性结果只覆盖上述引用机制，不排除计算式间接调用。原始函数 716 字节及其 SHA-256 见 `trollstore-getter-static-proof.json`。

另外新增明文 CFString `com.tencent.mf.uam`，对象在 `0x100BBA618`，原始指针引用在 `0x100C05000`。
本轮只确认常量存在，不把它推断成新增支持某游戏、读取该应用数据或对其清理。
早期启发式扫描曾因跨指令寄存器追踪不严产生假引用，已修正追踪并重跑；最终不采用该假引用。

### 3.3 C 重绑定与实际网络行为

`0x1003798C0` 安装器处理 `0x100B95DE8` 起九个 24 字节描述符，替换 `send`、`recv`、`connect`、`getpeername`、`inet_ntop`、`inet_pton`、`CCCrypt`、`ptrace`、`sysctl`。
描述符中的名称位于加密数据区，名称由原始初始化代码解出，不是从磁盘明文猜测。原函数指针由实际扫描器保存到 `0x1015EC378` 等槽。

对 `connect` 包装器 `0x10037238C` 的 15 个离线输入：

- `45.205.27.120` 的输入端口分别为 80、443、2，均到达原 connect，但传入的新 sockaddr 端口均为 **2**。
- 实际传入的 16 字节为 `000200022dcd1b780000000000000000`；调用者原 sockaddr 未改写。
- `10.2.3.4`、`154.222.16.171`、`127.0.0.1`、`1.1.1.1` 在相同端口矩阵中均返回低 32 位 `0xFFFFFFFF`，不调用原 connect；未观察到设置 errno 的 `___error` 调用。
- 普通 send/recv、三种 ptrace 请求和 CCCrypt 的所测 ABI 输入保持转发。对端为上述地址/端口 2 且输入人为短 HTTP 响应时，recv 原代码在 `0x100378FD4` 请求 abort；这不证明真实服务的正常响应会崩溃。

这说明不能把整个新增层称为“透明包装”，也不能只凭名称把它定性成反调试增强。已证实的是应用内的目标筛选、端口改写及特定响应输入的中止路径；未证明服务归属、代理、系统级网络重定向或真实授权结果。
旧版在相同描述符结构扫描中命中 3 行，新版 12 行；新增连续九行的安装另有执行证据。这个扫描不能证明旧版没有其他网络限制实现，也不能仅凭旧版字符串推断其实际连线目标。

### 3.4 “结束持久化”目标缩减

对相同 argv `DGAssistant -Set2cd 结束持久化 org.fixture.Target "" "" "" 2`，使用明确的环境/验证交付替身：

| 版本 | 实际提交给底层终止函数的目标请求 |
|---|---|
| 2.3.7 | 31 次，包含重复 `logd_helper`；原始字符串保留于旧证据 |
| 2.3.9 | 三次：`lsd`、`securityd`、`cfprefsd` |

新版调用点为 `0x100219D4C`、`0x100219D60`、`0x100219D74`，入口 `+[dfyyDG2 lrproki:]` 仍为 `0x1000F4B14`。两版共 34 个调用点已独立核对文件偏移及 BL 字节。
非空进程表中，`lsd-helper`、`securityd`、`childsecurityd` 被请求信号 9，仅路径含 securityd、短名称为 other 的条目不命中。kill 全部失败时新版仍遍历三项并返回 0。
这是所测子命令路径的差异，不是“杀死三/31 个进程”的设备结果；与 helper 的 backboardd 信号 15 分开记账。

## 4. 已重新执行且与旧版断言一致的功能

| 范围 | 新版主要 VA | 已验证结果 |
|---|---|---|
| 备份、隐藏、去后缀、恢复 | `0x1000E420C` / `0x1000E27C0` / `0x1000E314C` / `0x1000E4758` | 备份保护、删除 URL/scheme 键、重复追加后缀、非原子恢复及复制失败结果一致 |
| 递归/过滤清理 | `0x1000E54EC` / `0x1000E68A4` | 原文件集合、pak/sig 保护和 2 MiB 边界断言一致 |
| KB 清理和 dat/log/db 清理 | `0x1000E9DE4` / `0x1000ECAF4` | D0 double KB 的严格小于边界及扩展名样例结果一致 |
| Keychain SQL | `0x100996DB4` / `0x1009959BC` | SQLite 内存库中原静态/动态删除及任意 TEXT 列 LIKE 行为一致 |
| 标识符重写 | `0x100998120` / `0x1009974D8` | 短输入生成 UUID、长输入保留、首成功停止的用例一致 |
| 底层进程终止 | `0x1000F4B14` | 15 个原用例一致，仍按短进程名区分大小写的子串匹配，成功取得路径后请求 SIGKILL 9 |

底层进程用例包括精确/子串/大小写/仅路径/仅 comm 匹配、路径 API 失败、kill 失败、sysctl 错误、ENOMEM 重试、分配失败、空表、多命中及自身 PID。
例如新版 `0x1000F5200` 调用 `proc_pidpath`，`0x1000F53A4` 调用 `containsString:`；原有并不按完整进程路径匹配、kill 错误不升级为调用失败的用例未变。

这些是初轮的 **46 个基础用例**，不是完整功能覆盖率；当时隐藏核心使用固定 seed。后续另用原始 provider 跑通 18 个种子/后缀/隐藏用例，确认所测来源顺序为：内存有效值、APFS snapshot、当日缓存、AppleSupport serial、IDFV。
内层仍为按四个小端 32 位字格式化的 word-MD5，再拼 `-520-22`；后缀为标准 MD5 文本 `[15:17]`。fixture IDFV 对应后缀 `01`，不是旧隔离模型的固定 `4d`。

另完成九个隐藏/恢复/刷新操作及九种启动/等待失败输入：按钮确实构造自身 `-Set2cd` 参数，随后提交同包 `trollstorehelper refresh-all`；persona 请求为 `(99,1)`、uid/gid 各 0。主进程启动失败、非零退出、persona 设置失败均未阻止所测尾部刷新及 loading 结束。
启动失败后仍 waitpid 的缺陷保留：复用调用栈的用例等待的是调用前已有 PID 字段，不保证总是 0；不能把初轮零初始化栈结果推广为所有情况。

初轮独立核对 18,727 个指令地址、290 对直接调用；深挖另核对 90,581 个代码指令地址、85 个被模型截获的导入桩地址、292 行事件调用点 BL 编码，以及 IDA 与文件一致的 11 处入口字节。两轮统计存在重叠，不相加作为覆盖率。
旧案例两份清单的 214 条文件哈希继续全部一致。深挖统计见 [verification.json](work/dgassistant-239-deep/evidence/verification.json)。

## 5. 不能误读的限制

- 旧版 126 个用例没有全部迁移。初轮 52 个用例/安装记录之外，深挖 78 项包括两个预期异常输入；不是“78 项全都正常返回”，也不是完整覆盖率。
- 新版环境/挑战值入口 `0x1003F2A18`、验证交付入口 `0x10063137C` 已定位。按钮续执行用例显式提供挑战值和回调结果，原回调比较、原种子、参数构造和子进程请求执行原指令；不称真实授权链已经跑通。挑战值非零也能进菜单，不能把它粗略解释为布尔失败门。
- `command-exploration.json`、`command-argument-probes.json`、`new-initializer-probe.json`、`new-seed-idfv.json` 为探索记录，不作为已通过用例或版本行为差异。某次探索中没有进入 kill 链，不能直接断言新版移除了命令、修复了授权绕过或按钮失效。
- 初轮完整种子的取指失败已确定为 dyld 已加载映像回调缺失；补齐系统回调后，原始扫描器自然保存原函数指针，18 项原种子断言通过，不再保留“真实种子尚未补齐”的过时结论。IDFV=nil 的预期空读与该模型缺失问题分开记录。
- 后续已越过 Security 公钥边界，使用本机真实 Apple 内存接口完成原请求的 JSON/AES/RSA 操作，并从原 completion 追到 `http://45.205.27.120:2/index.php/api/User/logind1`、原 socket 和 connect 重绑定。五个清理按钮已补齐 handler、验证 callback、检查后 block、路径和子进程参数；token 匹配之外还有运行时字 `==0x34` 条件。详见本报告 §9 和授权/清理续审子报告。仍没有有效服务器响应、真实许可通过、实际提权或设备注销的证据。
- 相同 helper 的既有原指令证据可沿用：UID=0 才刷新，存在名称匹配 backboardd 才请求 SIGTERM 15；注册/重建/kill 失败可能仍返回 0。新版父进程何时提交 helper 则采用本轮按钮证据，不以 helper 哈希代替父链核验。
- 文件写入、进程表、socket、UIKit 和多数系统 API 仍为明确的内存边界；续审的 Security/CommonCrypto/JSON/CFHash 使用真实宿主 Apple 内存接口，不能再统称这些运算都是替身。SQL 在 SQLite `:memory:` 中执行，不对主机文件、进程、Keychain 或外网产生样本副作用。

## 6. 证据、发现与调用路径

证据索引 [evidence-index.json](work/dgassistant-237-239-diff/evidence-index.json) 含完整 SHA-256、来源路径、日期与可执行复现命令。

| Evidence | 内容 | 主要复现脚本 |
|---|---|---|
| E-001 / E-002 | 归档清单、逐文件哈希、方法/导入/段元数据 | `compare.py` |
| E-003 / E-004 | 31 个核心及 15 个底层进程原指令用例 | `replay_new.py` / `check_process.py` |
| E-005 / E-006 | 新安装器与五个包装函数用例 | `check_hooks.py` |
| E-007 / E-008 | 静态引用与配置函数原指令记录 | `inspect_changes.py` / `probe_new.py` |
| E-009 / E-010 | 签名 entitlement、指令字节与旧证据完整性 | `verify_comparison.py` |

| Finding | 状态/置信度 | 证据 | 位置与含义 |
|---|---|---|---|
| F-001 | validated / high / n/a_re | E-001, E-002, E-009 | 包结构、权限和 helper 内容的确定差异/相同 |
| F-002 | validated / high / n/a_re | E-002, E-005, E-006, E-007 | 主程序新增 Foundation 替换代码及已测转发行为 |
| F-003 | validated / high / n/a_re | E-003, E-004, E-010 | 所列基础用例与旧断言相同，不推广到完整按钮链 |
| F-004 | validated / high / n/a_re | E-007, E-008 | 配置对象构造函数存在，不证明 UI 可达或用途 |

以上 category=other，impact 为版本迁移判断；remediation=n/a（普通逆向）；复现步骤为运行相应脚本并核对证据索引及指令清单。ATT&CK 不适用，本轮未作攻击/恶意行为定性。

深挖索引为 [evidence-index.json](work/dgassistant-239-deep/evidence/evidence-index.json)，详细调用图、文件偏移/字节及回调模型边界见 [新版子报告](work/dgassistant-239-deep/DEEP_ANALYSIS_2.3.9.md)。D-E01 至 D-E16 支持以下补充发现：

| Finding | 状态 | 证据 | 含义 |
|---|---|---|---|
| D-F01 | validated / high / n/a_re | D-E02, D-E03, D-E10, D-E12 | 九项 C 重绑定及已测目标筛选/端口改写 |
| D-F02 | validated / high / n/a_re | D-E01, D-E13 | 原始初始化、来源选择、缓存和后缀用例通过 |
| D-F03 | validated / high / n/a_re | D-E11, D-E13 | 配置构造函数在所查静态机制下无入站引用 |
| D-F04 | validated / high / n/a_re | D-E04 至 D-E09 | 显式验证交付前提下的按钮/子进程/失败分支 |
| D-F05 | validated / high / n/a_re | D-E09, D-E16 | 同一结束持久化子命令目标请求由 31 次缩为三次 |

P-001：path_type=callflow。起点为新版安装器，目标为核实新增替换层。
步骤：`0x10037DB68` -> 子安装入口 -> 查询类/方法 -> 保存原 IMP -> `method_setImplementation` -> 包装函数调用原 IMP。
每一步由 E-005/E-007 关联 F-002；普通输入返回由 E-006 补证。
剩余风险为真实类可用性、异常分支和完整启动链未穷举，不把流程图扩展成已验证攻击路径。

## 7. 样本标识与复现

| 样本 | SHA-256 |
|---|---|
| 2.3.7 TIPA | `9dae635ac5604143d8d28f88bc0fb20d96748de3be0112b8bfc7569962575f2f` |
| 2.3.9 TIPA | `891b910e4136630ec933fff9d9085bf7d111a4d19259ec5a2e32fb4752accc3e` |
| 2.3.7 主程序 | `1f39b8894177d709c1c1b7b9dc76bbd8e70cfb3a9f5940e5a536edf1a4116139` |
| 2.3.9 主程序 | `3841f080d158a9a9f942eb0ca7f38ec8ba7e1677c23c1b92054fb82452e5cf78` |
| 两版相同的 trollstorehelper | `1c3bc999bae2e8f735a10421ccea2689d6633a5a7cae4ffba06e66094af39cc9` |

工具为现有 Python、LIEF、Capstone、Unicorn；未安装新工具或向外部 LLM 上传样本。主程序地址均为未滑动 VA，不能与 helper 映像地址混用。
完整复现命令、限制及时间线见 [案例 README](work/dgassistant-237-239-diff/README.md) 与 [timeline.md](work/dgassistant-237-239-diff/timeline.md)。

## 8. 独立 IDA GUI 与 MCP

按用户提供的 IDA 9.3 路径和显式许可证参数启动；不读取或打印许可证内容。先检查实例、复用已开库，未关闭其他 GUI。以下路径是由 2.3.9 样本提取的独立副本，哈希已与分析源核对。

| 文件完整路径 | PID | MCP 端口 | session_id |
|---|---:|---:|---|
| `/Users/tougee/Downloads/DG 管理器/work/dgassistant-239-deep/ida/DGAssistant239` | 56134 | 13338 | `90aee90b`，续审重新接入 |
| `/Users/tougee/Downloads/DG 管理器/work/dgassistant-239-deep/ida/trollstorehelper` | 56135 | 13347 | `4547c7ea`，初轮历史会话，本轮未重新采用 |

两者均由 MCP 列表、各端口身份与健康检查确认，自动分析就绪且 Hex-Rays 可用；不是仅凭启动 PID 宣称成功。旧版 PID 57325 / 13346 保持不动。
初轮55项、深挖79项、授权136项、启动227项及响应426项清单保留作历史快照，旧正文各自存档。最新字段审计后当前正文与新增证据完整性以 `work/dgassistant-239-license/manifest.sha256` 为准，不把有意修订正文造成的历史哈希变化当作样本变化。

## 9. 授权与清理续审：已越过公钥接口边界

详细结果见 [授权/清理子报告](work/dgassistant-239-auth/AUTH_CLEANUP_2.3.9.md)，以及该案例的 `evidence/evidence-index.json`、`evidence/verification.json`。

- **真实加密调用**：八个初始化入口、原种子与原请求构造继续执行；使用真实宿主 Apple JSON/AES/RSA 内存接口。内嵌 RSA 公钥 DER 实际为2048位，block size256；属性字段中的22不是RSA强度。完整初始化后的AES IV非NULL，不能沿用早期半初始化探索的NULL-IV结论。
- **两阶段网络链**：先构造 `https://www.baidu.com/yz` 的POST/nil-body NSURLRequest，再由实际 completion `0x1005BBE48` 解析并发起 `http://45.205.27.120:2/index.php/api/User/logind1`。原 connect 重绑定实际转发到目标端口2。受控100-continue用例还能观察原参数体进入 _send；所有socket均为内存fixture，没有外部请求。
- **真实失败与验签边界**：传输错误、EOF、原始HTTP拒绝响应均追到原失败路径。空JSON实际通过系统JSON解析后读取code并请求退出0。公钥加密并非签名验证；没有有效服务响应，不声称许可或验签成功。静态导入中的其他解密/信任接口也不能自动算作本链已执行。
- **五个清理按钮**：handler分别为系统残留 `0x10029A3C8`、一键新机 `0x10029DC24`、标识符 `0x1002A18D8`、Keychain `0x1002A3B1C`、数据库缓存 `0x1002A5C90`。原 callback 除token比较外还检查运行时字 `==0x34`；当前初始化值2时，五个按钮均未spawn。检查后的清理block、路径、阈值、argv、persona及SQL核心用独立单元补证，不冒充真实许可通过。
- **具体副作用**：缓存组的2048.0KB浮点阈值与3MB整数阈值已区分；系统规则遍历25路径并按名单决定删除。Keychain核心实际对SQLite内存库的agrp及其他TEXT列执行LIKE删除；标识符核心修改lsdidentifiers.plist。spawn请求与子进程核心效果分开记账，不以父进程请求代替子进程执行证明。

续审同时修正仿真器的CF常量绑定、虚拟时钟、Foundation类簇分派及realloc保留旧缓冲。修正前的零字节HTTP头不是样本擦除流量的证据。原二进制、旧2.3.7报告和主证据不改动；授权续审时旧深挖79项清单中仅本报告及新版深挖子报告正文有意更新，当时由 `work/dgassistant-239-auth/manifest.sha256` 记录；最新启动续审见 §10。

## 10. 黑屏启动与剪贴板自动激活

详细证据及新App重建契约见 [启动/激活子报告](work/dgassistant-239-startup/STARTUP_ACTIVATION_2.3.9.md)。本段针对已提供的2.3.9，不自动推广到其他“3.9”样本。

- **先显示窗口壳，不先构造管理UI**：AppDelegate 原 refreshUI 创建窗口/root并makeKeyAndVisible；148字节的 viewDidLoad 只异步进入验证。管理列表、搜索和按钮由后续 `0x10024CBB8` 在主线程构造，符合用户“先黑屏、激活才进去”的观察；本轮不声称已测得黑色像素。
- **启动门不只是token**：`0x10024B014` 检查 `0x1014C2C0C == 0x34`。初始化值2时，匹配token仍不进入第二验证 `0x10080B9CC`；其 callback 另有时间新鲜度和 `0x1014C2C18 == 0xDE` 条件，之后再次验证才派发业务UI。
- **无点击剪贴板路径已执行**：原 `0x1004A4E2C` 读取 UIPasteboard.string，去首尾空白及内部空格/LF/CR，清洗后至少7字符才提交。km2缓存原文，提交入口 `0x1004AAF14` 收到清洗码。写km2发生在网络校验前，不代表授权成功。
- **接口需分三类**：前轮第一授权为logind1，本轮第二启动验证为logind0，兑换/激活为recharged。后两者均保存了原HTTP/send和Host `45.205.27.120:2`；recharge_card来自清洗码，username来自原种子，未用测试常量替代真实身份逻辑。
- **RSA解密来路补齐但不冒称验签成功**：`0x10080B9CC` 在 `0x1008147C0` 调用 `0x10038DAB8`，现已静态接到启动验证链；原负向分支仍没有有效服务响应解密/验签成功证据。

新增31处IDA/文件字节锚点、八个无效剪贴板输入、实际兑换/第二登录负向路径已归档。后续§11已定位状态写入者、执行检查后交付并追到兑换后的重新授权请求；有效响应最终判定及其恢复最初等待任务的同次轨迹仍需补证，未伪造成功、不联网、不改授权字。最新完整性见响应案例清单。

## 11. 响应解码、状态写入和重新授权闭环

详见 [响应/续执行报告](work/dgassistant-239-response/RESPONSE_CONTINUATION_2.3.9.md) 与 [新App授权启动契约](work/dgassistant-239-response/AUTH_STARTUP_CONTRACT.md)。

- **响应类型/分流**：第一响应code的所测有效分流输入是3字符NSString。字符串257进入data解码，606进入剪贴板helper；数值257经原NSString类型检查exit(0)。HTTP200及另一个运行时字写77均不是授权。没有把状态码称作验签。
- **原响应解密已到真实接口**：第二验证经原category到CCCrypt，参数1/0/3/16/IVNULL，与请求0/0/1/16/非NULL IV分开。原NSData Base64函数和真实UTF-8解码继续执行，不可信密文被拒绝，没有授权成功返回替身。
- **52/222写入者与交付已执行**：631内654148/65E354写52，原65DF98调用24B014并进入80B9CC；80B内843D3C/83B020写222，84B748交付T7及时间W2。明确为保留原帧的检查后单元，不是已通过服务器响应；未产出有效时间的后者W2为0。
- **兑换后不是直接开UI**：303/304/305分别提示卡不存在/停封冻结/已使用；306描述子串分支提示充值成功后走 `4AE7B8 → 883894 → 883884 → 4BF660`，重新到第一授权请求边界。未写52/222、未直接调用主UI、未观察到semaphore恢复；各阶段必须分别验收。
- **抓包摘要单列，不作未经核验的真值**：`license-server/dg_capture_reference.md` 已登记SHA-256，内层字段/sign/运行时CBC/suite写入作为候选线索。数字code与当前原第一响应类型要求有差异，NSURL层与实际socket层亦须分清；文中自有后端往返通过不等于旧客户端兼容或验签成功。本轮未执行该文脚本、未复制其密钥、未修改后端。

原227项快照中仅本报告、授权子报告、启动子报告三份旧正文有意修订；其余原证据及旧2.3.7样本/214项清单保持不变。原MASTER_REPORT.md属于旧版审计，本轮不混写新版结论。

## 12. sign、udid/endtime、类型和授权显示缓存

继续复用13338/PID56134/session90aee90b。详细地址与证据见[字段续审报告](work/dgassistant-239-license/LICENSE_PREDICATES_2.3.9.md)，新App契约已同步更新§8。

- **sign算法已恢复**：第一completion的隐藏sign字段经intValue，原5E0A84–94比较本次请求捕获Unix秒+2倍捕获随机数的低32位。原负向分支及7组溢出算术单元已核对；不是CRC32/HMAC/公钥签名，不覆盖整份许可，不以响应自报ss/sss自证请求绑定。
- **udid原比较器已执行**：3AF36C消费响应UTF8String与原provider身份；9组原指令用例确认匹配0、不匹配1，大小写、前后缀不同均拒绝，NUL终止。实际错误ID路径清理返回，未写主授权字。
- **endtime分层核实**：非零检查、ssss关联拒绝、NSDate/延迟消费已有原指令单元。另定位FCMP及过期数值到剪贴板路径，但输入cell+3340上游未闭环，不把它直接命名为完整endtime过期验证，也不混淆启动±22秒。
- **tz0111endtime真实写入口补齐**：隐藏CF键1014CA760在5C60F4写standardUserDefaults，值为endtime.intValue→NSDate→原YYYY-MM-dd HH:mm:ss生成的NSString，随后synchronize。不是NSDate、指定suite或可信授权凭证；固定GMT0仅为离线复现条件。
- **类型与续执行纠正**：原第一外层数字257拒绝、字符串257进入解码，真实Foundation类型复核相符；不能推广所有内层。原5BBE48转交调用者completion到61ACB8，后者628ADC实际调用；其C14=222/C48=52与主UI的C18/C0C不同。完成标记置1后仍可缺data2而abort，不能当作UI放行。

本次没有有效响应生成或成功返回替身，也没有修改后端。合法响应的完整解码与全部接受条件、额外状态到631的真实连接及同次主UI进入仍未标记PASS。原426项清单中的五份报告/契约正文有意修订，其余历史证据及旧版214项逐项复核；最新完整性见字段案例清单。

## 13. 真实endtime→tz0111ct产出及第一回调补采

61ACB8的6270B0取block+48的endtime；61F5AC原格式化对象经627354原加密，6283D0真实setter写tz0111ct。PID60114对象关联、CCCrypt成功参数和原setter返回均已记录。三逻辑路径分别在624444、6281F0、88B578发起write，1281字节/options1/BOOL1，但实际存储位置与外层编码未闭环。该轮ct原时间门及主UI入口早于新产出，不能误写成“写完本次缓存后才开UI”。

第一24B014仍缺实机事件；更早onEnter采集在worker前终止，原Appledebugserver未完成连接。短暂无Frida退出与后续无成功调试附加且用户确认主界面分开记录。完整字节、同次时序、失败证据与离线断言见[产出补证报告](work/dgassistant-239-producer/PRODUCER_CHAIN_2.3.9.md)。未修改旧2.3.7 MASTER_REPORT.md、原样本、授权状态或任何IDA数据库。

## 14. 外层包裹与C字符串写入长度

原629040是writer所调用的两C字符串外层包裹器，不是把UTF8String原文直接塞入NSData。已恢复时间头/循环输入与反馈旋转/第二遍反馈/Base64；原长度经strlen+1包含NUL。原reader调用6B2BB4逆包裹，公开fixture原CPU单元已核对；这些不是新的实机授权接受证据。未动当前DG，原版debugserver无目标端点也提前退出，仍未安装第一callback硬件断点。详见[存储编码续审](work/dgassistant-239-storage/STORAGE_CODEC_2.3.9.md)。
