# DGAssistant 清理与标识符路径：字节级复核

> 2026-10-16，IDA 9.3 / Hex-Rays，直连 `127.0.0.1:13346`。第二轮核心路径见 §1–7；第三轮按钮、子进程和系统策略见 §8。修订前版本分别保存在 `work/dgassistant-byte-audit/evidence/CLEANUP_ANALYSIS.before-paths.md`、`CLEANUP_ANALYSIS.before-control.md`，不把离线回放写成设备实测。
>
> 样本 SHA-256：`1f39b8894177d709c1c1b7b9dc76bbd8e70cfb3a9f5940e5a536edf1a4116139`。授权与范围见 `work/dgassistant-byte-audit/scope.md`。
> 第四轮新增“结束持久化”的非空表匹配、SIGKILL和失败路径，见 §9；此前版本另存为 `CLEANUP_ANALYSIS.before-seed-process.md`。

## 1. 方法与已验证范围

从原 Mach-O 映射字节，用 Unicorn 2.1.4 执行原始 ARM64 指令及 CFF 派发；Foundation/ObjC 对象、目录和文件操作使用显式内存模型，SQLite 调用则真实作用于 Python SQLite 的 `:memory:` 数据库。Capstone 5.0.7 独立解码调用指令。没有在设备上运行清理操作。

第二轮31个回放用例全部正常返回，覆盖本报告与隐藏/恢复子报告。28,562条IDA指令记录与磁盘逐条一致，255个原始BL调用点的目标与回放拦截桩一致。第三轮另有60个按钮/进程/helper用例，详见 §8及总报告 §12。完整原始参数寄存器、调用地址、BR目标、输入/输出状态见各轮fixtures；此处“删除/写入”指已确认的代码请求及模型/内存数据库中的效果，设备最终文件内容仍依赖系统API返回值。

IDA 的已绑定 `__got`/类引用只用于模拟加载器；执行代码来自原文件。每个用例重新建立镜像、栈、对象和文件状态；遇到未建模 API 会中止并使检查失败。隐藏后缀依赖函数的模拟边界另见隐藏子报告。

## 2. 清理器不是一个函数

| 入口 | 真实名称/参数 | 已确认行为 |
|---|---|---|
| `0x1000E3E94` | `+[dfyyDG2 cleanFolderAtURL:]`，X2=URL | 枚举目录、递归进入子目录、删除普通文件；没有扩展名白名单 |
| `0x1000E55E0` | `+[dfyyDG2 deldir2:withSizeInMB:]`，X2=路径/URL，X3=整数 MiB | 完整路径子串分支、plist 处理、指定文件删除、剩余文件大小阈值 |
| `0x1000E9038` | `+[dfyyDG2 delcache52:withMaxFileSizeInKB:]`，X2=路径/URL，D0=double KB | 枚举/递归后对符合前置条件的文件按字节数/1024 与浮点阈值比较 |
| `0x1000EC5AC` | `+[dfyyDG2 deldatlogsql52:]`，X2=路径/URL | 另一个路径匹配删除器；函数名不能当作 SQL 执行证据 |
| `0x100A25188` | `+[dfyyDG deldir:withSizeInMB:]`，X2=URL，W3=整数MiB | 缓存按钮另用的大小筛选器；不能套用deldir2的pak/sig保护规则，见 §8.3 |
| `0x100A2265C` | `+[dfyyDG Resetsj:]`，X2=bundleID | 调用钥匙串删除引擎 |
| `0x100A239C8` | `+[dfyyDG Reuid:idv:ida:]`，X2=bundleID、X3=VID、X4=AV | 选择传入标识符或生成 UUID，查找系统标识符 plist 并修改 |

旧报告把 `0x1000E3E94–0x1000E9000` 内多个带独立序言、栈帧和返回的函数合并为一个清理器，是功能归属错误。

## 3. 递归清空与筛选清理

### 3.1 cleanFolderAtURL：清空目录内容

调用路径：检查路径存在/目录 → `contentsOfDirectoryAtURL:includingPropertiesForKeys:options:error:` → 读取 `NSURLIsDirectoryKey` → 子目录调用自身 → 文件 `removeItemAtURL:error:`。

`clear_directory_recursive` 用例中，一个 `.keep` 文件和子目录里的 `.xyz` 文件均被删除；没有依赖后缀。调用例 `0x1000E47C0`：X0=file manager、X1=`removeItemAtURL:error:`、X2=当前枚举文件 URL、X3=NSError 指针。原先把本入口描述为“按 .db/.sqlite 白名单删除”不正确。

### 3.2 deldir2：包含保护条件的路径筛选

该函数对**完整路径字符串**调用 `containsString:`，不是统一使用 `pathExtension`。

已回放的比较包括：`login`、`functions`、`com.apple.`、`com.tencent.`、`.list`、`.pak`、`.sig`、`SrcVersion.ini`、`.plist`、`.sqlite`、`.db`、`.log`、`db-wal`、`db-shm`、`/Documents/`。这些字符串命中后进入不同分支，不能统称“删除扩展名列表”。

在其余条件一致的合成容器路径中：

| 文件/子串 | X3=0（阈值为0） | 额外验证/含义 |
|---|---|---|
| `.sqlite`、`.db`、`db-wal`、`db-shm`、`.log` | 删除 | `a.sqlite.backup` 也删除，证明是包含匹配 |
| `.plist` 字典 | 先清空重写，随后删除 | 不是旧报告所说的“仅清空不删除” |
| `.pak`、`.sig` | 保留 | 4字节文件、X3=2 时仍保留，是已走通的保护分支 |
| `SrcVersion.ini`、`login`、`functions`、`com.apple.`、`com.tencent.`、`.list` | 保留 | 表示本用例走到保留分支；不代表其他清理器不会删除 |
| 普通 `.keep`、`.jpg` | 保留 | X3=2、大小4字节时删除，属于剩余文件的大小分支 |

函数还构造 `<输入根>/tmp` 并调用删除，回放记录了该删除请求；目录不存在时模型返回失败，不能把请求记成成功删除。

`.plist` 字典路径的真实顺序：

1. `0x1000E7250`：`propertyListWithData:options:format:error:`。
2. `0x1000E7564`：可变副本 `removeAllObjects`。
3. `0x1000E77B4`：`writeToFile:atomically:`，X2=当前 plist 路径、W3=1。
4. `0x1000E7A00`：`removeItemAtPath:error:`，X2=同一路径、X3=0。

这些调用来自同一原始指令回放，不是将相邻地址的独立块任意拼接。

大小分支：X3 保存后在 `0x1000E8D4C` 左移20位，得到 MiB×1,048,576；`0x1000E8648` 比较大小，后续 `CSET LT`。实际回放：2MiB−1 的普通文件被删除，恰好2MiB及2MiB+1 保留，条件为严格小于。

### 3.3 delcache52：浮点 KB 阈值

`0x1000EBB40` 的 `UCVTF D0,X0,#10` 把字节数缩放为 KB；`0x1000EBB44` 与 D8（入口 D0 保存值）作 `FCMP`，随后 `CSET MI`。1.0KB 用例：1023字节删除，1024/1025字节保留。该路径的 `removeItemAtPath:error:` 在 `0x1000EBB70`。

不能把这个参数当 X3 整数，也不能直接改写为“所有小文件都会删除”：函数在大小比较前还有目录与路径条件。

已确认一个上层编排块从目标对象取 `dataContainerURL`：

- `0x10032D06C`：`MOV W3,#2`，在 `0x10032D070` 调 `deldir2:withSizeInMB:`；输入根是目标应用的数据容器 URL。
- `0x10032D0E8`：构造 double 位型 `0x40A0000000000000`（2048.0）；D0 在 `0x10032D100` 传给 `delcache52:withMaxFileSizeInKB:`。其路径表达式为 `[dataContainerPath stringByAppendingPathComponent:@"/Library"]`；同块还装载 `@"/tmp"`。两个明文均由原指令区间 `0x10032F75C → 0x10032FA14` 恢复，CF对象分别为 `0x10150E7D0` 与 `0x10150E7F0`。

这些是字节证明的参数传递；旧报告将所有根目录笼统写成 `/var/mobile` 不适用于这些已确认调用。

### 3.4 deldatlogsql52：名称不等于删除规则

实际回放的同目录文件：`a.dat/a.log/a.db` 删除，`a.sql/a.sqlite` 保留。命中调用分别是 `containsString:@".dat"`（`0x1000EEBAC`）、`@".log"`（`0x1000EEAE4`）、`@".db"`（`0x1000EF310`），删除调用 `0x1000EF6E4`。

因此“所有 SQL 都是钥匙串，数据库缓存只靠一个递归器”也不准确：这里存在多个文件清理器，选择器名中的 `sql` 本身不表示执行 SQL，也不保证匹配 `.sql/.sqlite`。

## 4. 钥匙串 SQL：超出 agrp 的删除范围

### 4.1 入口参数与数据库路径

`Resetsj:` 在长度检查通过后，依次调用 `clkcin2:bundleID:`，模式参数为 `2、0、1、3`；调用点 `0x100A22734/754/768/77C`。X2=模式整数，X3=同一个 bundleID。

删除引擎入口 `0x100A21264` 把 X3 保存为目标字符串；在 `0x100A21914` 调 `sqlite3_open`：X0 指向 `/var/Keychains/keychain-2.db`、X1=数据库句柄输出指针。此路径来自原指令解密，不是根据旧报告猜测。

### 4.2 原始密文已用原指令复原

下表 VA 均在文件支持区；本样本对应文件偏移=VA−`0x100000000`，独立 load command 解析已核验。完整密文、解密后的十六进制及 NUL 记录在 `path-decrypted.json`。

| 数据 VA | 解密内容 |
|---|---|
| `0x1016245D0` | `/var/Keychains/keychain-2.db` |
| `0x1016245F0` | `DELETE FROM %s WHERE agrp like '%%%@%%'` |
| `0x101624660` | `DELETE FROM %@ WHERE agrp like '%%%@%%'` |
| `0x101624620` | `DELETE FROM %s WHERE %s LIKE '%%%@%%'` |
| `0x101624690` | `SELECT name FROM sqlite_master WHERE type='table';` |
| `0x1016246D0` | `PRAGMA table_info(%s)` |
| `0x1016246E6` | `TEXT` |

解密区间 `0x100A212C0 → 0x100A2188C` 不调用外部函数，按原指令执行向量/标量 XOR 即可复原上述内容。例：数据库路径密文以 `81 c3 26 77 ...` 开头，明文以 `2f 76 61 72 ...` 开头。

### 4.3 三阶段删除路径

1. 用模式选取固定表名（`cert/keys/genp/inet/idnt` 表名区域）格式化 agrp DELETE，调用 `sqlite3_exec`；已见 `0x100A219DC`、`0x100A21C1C`。
2. `sqlite_master` 枚举表名；`sqlite3_column_text(stmt,0)` 的返回值作为 `%s`，bundleID 作为 `%@`，在 `0x100A21DD8` 组装 agrp DELETE，经 `UTF8String` 后在 `0x100A21E44` 执行。
3. 再枚举表和 `PRAGMA table_info(table)`；读取第1列列名与第2列类型，类型匹配 `TEXT` 的路径继续生成 `DELETE FROM <table> WHERE <column> LIKE '%<bundleID>%'`，在 `0x100A22140` 执行。

`sqlite3_exec` 的参数在调用点均可追踪为 X0=db、X1=生成 SQL 的 UTF-8 地址、X2=0(callback)、X3=0(context)、X4=0(errmsg)。相关构造寄存器与 Darwin 变参栈参数保存在回放日志。

实际内存数据库验证：每个固定表插入三行 `(目标agrp,x)`、`(unrelated,note-目标bundle)`、`(keep,safe)`，执行原始 `Resetsj:` 指令后只剩第三行。额外 `custom(label TEXT,n INTEGER)` 没有 agrp 列，第一阶段 agrp DELETE 报错，但后续 TEXT 列删除仍删掉 label 匹配行。

因此删除范围不是“仅指定 App 的 access group”。它会尝试删除其他 TEXT 列的包含匹配行；直接格式化且 LIKE 通配符未转义，不能等同于精确身份匹配。

### 4.4 chmod 路径纠正

存在两个独立权限助手：

- 可写助手 `0x10010BD7C`：对同一数据库先 `chmod(...,0600)`，再 `chmod(...,0666)`，调用例 `0x10010BE20/BE2C`。
- 只读助手 `0x10010BC3C`：先0600再0444，调用例 `0x10010BCEC/BCF8`。

中央分派分别在 `0x1002CC214` 和 `0x1002CC21C` 调助手；`Resetsj:` 调用在另一个分派块 `0x1002CC238`。本轮没有证据把它们串成“每次 Resetsj 前自动0666、后自动0444”。0444也是固定模式，并非恢复原权限快照。

## 5. 标识符改写：真实 plist 树和条件

路径解密区间 `0x100A23F34 → 0x100A24018`：

- `0x101624A20` → `/var/containers/Shared/SystemGroup`。
- `0x101624A50` → `com.apple.lsdidentifiers.plist`。

`ffcsd:searchString:` 使用 `enumeratorAtPath:` 枚举 SystemGroup，相对路径通过 `containsString:` 匹配上述文件名，再拼成完整路径。目录 UUID 是运行时枚举结果，不是样本中的一个固定 UUID。

`Reuid:idv:ida:` 在 `0x100A23A80`、`0x100A23B38` 对传入 VID/AV 的 `length` 与18比较；短值才走 `NSUUID.UUID.UUIDString`，长度足够则保留传入值。回放分别得到0次与2次 UUID 请求。旧报告“无条件生成两枚新 UUID、覆盖参数”错误。已确认的上层调用 `0x10032CF80` 把X3/X4都设为 `0x10150E7B0`，其原指令明文为“随机”（长度2），故该具体调用确实触发生成UUID；独立入口仍支持保留足够长的传入值。

`modla:bundleID:newvid:newav:` 的树结构为：

```text
root
  LSVendors
    <vendorKey>
      LSApplications = [bundleID, ...]
      LSVendorIdentifier = newVID
  LSAdvertiserIdentifier = newAV
```

实际路径：读取 root → root[`LSVendors`] 可变副本 → 枚举 vendorKey → 检查该组 `LSApplications` 包含目标 bundleID → 更新组内 `LSVendorIdentifier` → 回写组及 `LSVendors` → 更新 root 的 `LSAdvertiserIdentifier`。

- VID 写入点 `0x100A232B8`：X2=newVID，X3=`LSVendorIdentifier`。
- AV 写入点 `0x100A2331C`：X2=newAV，X3=`LSAdvertiserIdentifier`。
- `0x100A23338` 先用字典 `writeToFile:atomically:YES`；成功路径接着 `dataWithPropertyList`（format=100/XML）并在 `0x100A2342C` 再写同一路径。
- 目标 bundle 不在任何 `LSApplications` 时，回放不写文件；两个 SystemGroup 命中时，首个修改成功后返回，第二个未改。

这纠正了旧的 `LSApplications → bundle → LSVendors` 层级。代码证明修改持久化字段，不能单凭此推出“所有运行中 App 的 IDFA/IDFV 立即生效”；系统服务缓存/重载未做设备验证。AdSupport/Umeng/game plist 不是本次这条已走通路径的写入目标。

## 6. 原始指令锚点

所有调用点还需结合 selref、参数来源与实际分支；单个 `BL objc_msgSend` 不独立证明调用语义。

| VA | 文件偏移 | 原始字节 | 解码 |
|---|---|---|---|
| `0x100a21914` | `0xa21914` | `59280594` | `bl #0x100b6ba78` |
| `0x100a21e44` | `0xa21e44` | `04270594` | `bl #0x100b6ba54` |
| `0x100a22140` | `0xa22140` | `45260594` | `bl #0x100b6ba54` |
| `0x100a23a80` | `0xa23a80` | `1f4800f1` | `cmp x0, #0x12` |
| `0x100a23b38` | `0xa23b38` | `1f4800f1` | `cmp x0, #0x12` |
| `0x100a232b8` | `0xa232b8` | `88200594` | `bl #0x100b6b4d8` |
| `0x100a2331c` | `0xa2331c` | `6f200594` | `bl #0x100b6b4d8` |
| `0x100a2342c` | `0xa2342c` | `2b200594` | `bl #0x100b6b4d8` |
| `0x1000e47c0` | `0xe47c0` | `461b2a94` | `bl #0x100b6b4d8` |
| `0x1000e7a00` | `0xe7a00` | `b60e2a94` | `bl #0x100b6b4d8` |
| `0x1000e82a4` | `0xe82a4` | `8d0c2a94` | `bl #0x100b6b4d8` |
| `0x1000e8d4c` | `0xe8d4c` | `08ad6cd3` | `lsl x8, x8, #0x14` |
| `0x1000e8648` | `0xe8648` | `1f0008eb` | `cmp x0, x8` |
| `0x1000ebb40` | `0xebb40` | `00d8439e` | `ucvtf d0, x0, #0xa` |
| `0x1000ebb44` | `0xebb44` | `0020681e` | `fcmp d0, d8` |
| `0x1000ebb70` | `0xebb70` | `5afe2994` | `bl #0x100b6b4d8` |
| `0x1000ef6e4` | `0xef6e4` | `7def2994` | `bl #0x100b6b4d8` |

## 7. 证据索引与复现

证据目录 `work/dgassistant-byte-audit/evidence/`：

| 证据 | 内容 |
|---|---|
| `path-fixtures.json` | 31用例完整输入、寄存器、API、BR派发和输出；失败分支也要求原函数正常返回 |
| `path-decrypted.json`、`caller-path-plaintext.json` | 四个独立解密区间，含SQL/系统路径及上层随机标记、Library/tmp路径 |
| `path-byte-verification.json` | 指令逐字节比对、调用目标解码、原始 CFString 结构与字符串字节 |
| `paths.asm`、`more-paths.asm`、`tail-paths.asm` | IDA带字节反汇编 |
| `path-callers-data.json`、`dispatch-path-data.json` | 选择器引用、上层参数传递及分派块 |
| `manifest.sha256` | 证据文件哈希 |

```sh
python3 work/dgassistant-byte-audit/path_replay.py decrypt
python3 work/dgassistant-byte-audit/recover_path_literals.py
python3 work/dgassistant-byte-audit/run_path_checks.py
python3 work/dgassistant-byte-audit/verify_paths.py
```

上述回放不连接服务器；重新采集 IDA 记录使用同目录的 `ida_read.py` 和 `ida_*paths.py`，端点固定为已授权13346。

历史日志 `child.log` 能支持 `-Set2cd 隐藏程序 <bundle> 2` 的 argv 曾被提交，`frida_capture.log` 能支持自身二进制 spawn。它们不包含本次路径全部 syscall 的成功结果。旧报告关于650+文件删除、清理 cfurl_cache SQL、反作弊日志含义及root身份的断言，不作为本次已验证副作用保留；原文可在备份中追溯。

## 8. 第三轮：五个按钮到具体函数的完整关联

### 8.1 表格选择、菜单与block捕获

入口 `tableView:didSelectRowAtIndexPath:`@`0x100327B28` 从sectionTitles/groupedApps取得所选LSApplicationProxy，经continuation `0x100328440`、派发块 `0x100329034` 到 `shwmwa:selectedCell:uuid:yxmsresultStr:`@`0x1003306DC`。后续continuation `0x1003354C0` 经 `0x1003363B8/0x100336470` 到菜单构造块 `0x1003368D8`。

五个文字均由原指令解密；下表把CFString、`actionWithTitle:style:handler:`调用点与handler对应，不依赖旧文档猜测。

| 按钮原文 | CFString VA | UIKit调用点 | handler入口 |
|---|---|---|---|
| 清理系统残留 | `0x10150F0D0` | `0x1003385E0` | `0x10033FD7C` |
| 一键新机 | `0x10150F0F0` | `0x1003386D0` | `0x1003408A4` |
| 变更新的标识符 | `0x10150F110` | `0x1003387B8` | `0x100342294` |
| 清理KeyChain残留 | `0x10150F130` | `0x1003388AC` | `0x1003422E4` |
| 清理数据库缓存 | `0x10150F150` | `0x100338990` | `0x100342630` |

一键新机block descriptor=`0x100C1D308`、size=64，+32/+40/+48/+56依次捕获VC/proxy/alert/completion；其余四个descriptor=`0x100C1D358`、size=56，+32/+40/+48捕获proxy/alert/completion。证据 `control-cleanup-labels.json`保存原始CF结构、密文、明文hex、实际构造的action及handler指针、存储指令窗口。

边界：菜单构造用显式状态衔接、回调用原捕获布局建立fixture，completion设nil；校验返回递送使用模型。已闭合的是字节支持的关联及分段执行链，**不是授权校验流程被完整执行或绕过的证明**。

### 8.2 一键新机：父/子进程并存，不能只记一条清理函数

`0x1003408A4`启动activity后安排后台块 `0x100341270`，在 `0x100341290`调用 `-[ViewController yjxj2:]`@`0x100329D80`。设D为所选proxy的dataContainerURL，B为DGAssistant运行时包目录：

| 调用点 | 被调用功能及真实参数 |
|---|---|
| `0x10032DB34` | `sub_1000FBD38`：提交 `[B/DGAssistant,-Callreuid,bundle]` |
| `0x10032DB7C` | 父进程直接 `dfyyDG Reuid:bundle idv:@"随机" ida:@"随机"` |
| `0x10032DBA0` | `sub_1000FA654`：提交 `[B/DGAssistant,-CallResetsj,bundle]` |
| `0x10032DBD8` | 父进程直接 `dfyyDG Resetsj:bundle`，进入 §4的SQL路径 |
| `0x10032DC70` | `dfyyDG2 deldir2:D withSizeInMB:2` |
| `0x10032DCF8` | `dfyyDG2 delcache52:D/Library withMaxFileSizeInKB:2048.0` |
| `0x10032DD84` | 同一KB清理器，D/tmp、D0=2048.0 |
| `0x10032DE18` | `dfyyDG2 dellog52:D/Documents`@`0x1000EFA40` |

D0的原始double位型是 `0x40A0000000000000`；该调用中残留X3不是KB参数。另一等价块的 `0x10032D070/0x10032D100`与第二轮参数结论一致。

后台块在 `0x1003412FC`提交 `stopActivityWithCompletion:`，完成块 `0x100341328`继续检查Library/tmp/Documents等路径，进入 `0x10011F...–0x100123...`目录/系统策略助手；在 `0x100121ECC`请求创建 `D/Library/Preferences`，intermediates=YES。还通过 `sub_100106EA0`在 `0x100107C6C`提交：

```text
[B/DGAssistant, -Set2cd, 结束持久化, bundle, "", "", "", "2", NULL]
```

fixture轨迹中此命令出现两次，不能把完成路径误写为仅dismiss alert。最终一键新机用例在真实内存SQLite中将五表匹配行删除、保留 `(keep,safe)`；目录模型中出现Preferences创建请求。子进程本身不由主机启动，其命令分派另行执行原字节，见 §8.5。

### 8.3 缓存按钮：另一套deldir，3MiB，不保护pak/sig

handler `0x100342630`的实际调用次序：

| 调用点 | 功能/路径/参数 |
|---|---|
| `0x100343A54` | delcache52，D/Library，D0=2048.0KB |
| `0x100343AD0` | delcache52，D/tmp，D0=2048.0KB |
| `0x100343B50` | deldatlogsql52，D/Documents |
| `0x100343CC8` | **dfyyDG.deldir**，D/Library，W3=3 |
| `0x100343D80` | 同一deldir，D/Documents，W3=3 |
| `0x100343E30` | 同一deldir，D/Library/Caches，W3=3 |
| `0x100343EDC` | 同一deldir，整个D，W3=3 |

之后同样提交“结束持久化”八参数命令。deldir入口为 `0x100A25188`，不是 `0x1000E55E0`：原指令枚举URL，读取NSURLFileSizeKey，完整路径分别比较 `.com.apple.mobile_container_manager.metadata.plist`、`.com.apple`、`.com.appl`，命中保护分支时跳过。其余路径比较字节数与MiB阈值，在 `0x100A257E4/7E8`执行CMP/CSET LT，`0x100A25840`请求删除。

补充原指令用例中，3MiB−1普通文件删除，恰好3MiB及3MiB+1保留；4字节的 `.pak/.sig/.plist/.db/.sqlite/.log/.keep`均删除，而上述三个受保护子串文件保留。删除API返回失败时保留原文件，函数仍正常返回。**deldir2保留pak/sig的结论不能推广到缓存按钮**；plist在本函数是大小删除，不是先清空字典。

### 8.4 系统残留按钮：策略筛选、短路径保护与延迟复扫

handler `0x10033FD7C`在 `0x1003401B8`（等价块 `0x1003403B0`）调用 `sub_10027F120`；在 `0x1003401F8/0x1003403F0`提交“结束持久化”。策略从原程序内Base64数据经plist解析得到，含逐根blacklist/whitelist/default及regexp规则，不是无差别清空 `/var`。

`0x10027A628`请求枚举的25个根为：

```text
/var
/var/containers
/var/containers/Bundle
/var/log
/var/mobile
/var/mobile/Documents
/var/mobile/Library
/var/mobile/Library/Application Support
/var/mobile/Library/Application Support/Containers
/var/mobile/Library/Caches
/var/mobile/Library/Cookies
/var/mobile/Library/HTTPStorages
/var/mobile/Library/Logs
/var/mobile/Library/Preferences
/var/mobile/Library/Saved Application State
/var/mobile/Library/SplashBoard/Snapshots
/var/mobile/Library/UserConfigurationProfiles/PublicInfo/
/var/mobile/Library/WebKit
/var/root
/var/root/Library
/var/root/Library/Application Support
/var/root/Library/Caches
/var/root/Library/HTTPStorages
/var/root/Library/Preferences
/var/tmp
```

正向fixture：`/var/stash`命中该根blacklist，并在 `0x10027DB5C`实际发起 `removeItemAtPath:error:`；同为blacklist的 `/var/jb`因路径长度7，被 `0x10027D3A0`的 `<9`保护挡住。`/var/Keychains`（whitelist）和未匹配的 `/var/unknown-fixture`保留。本用例不推导所有regexp/default组合的普遍行为；完整策略对象及枚举结果保存在 `control-fixtures.json`。

`sub_10027F120`还在 `0x10027F2F4/318/33C`构造3、7、12秒dispatch_time，分别安排 `0x10027F384/488/48C`；回放已执行这些排队块。时间只是原始纳秒参数，模型没有按真实墙钟等待。不能将同一策略重复枚举25根记成多个独立文件删除结果。

### 8.5 独立按钮、子命令和提权边界

“变更新的标识符”handler `0x100342294`直接调用 `sub_1000FBD38`；“清理KeyChain残留”handler `0x1003422E4`调用 `sub_1000FA654`。两包装器在 `0x1000FC39C/0x1000FBB74`提交自身命令，前者argv为 `-Callreuid <bundle>`，后者为 `-CallResetsj <bundle>`。

二者原调用均请求 `set_persona_np(attr,99,1)`、UID=0、GID=0，设pgroup=0、spawn flags=2；不能从这些实参认定操作系统已授予root。隐藏与通用helper启动器的不同错误处理详见总报告 §12及隐藏报告 §9.3，不能把一个包装器的返回语义套到另一个。

main `0x1002C2D6C`中：

- `-Callreuid`在 `0x1002C80D0`直接调用Reuid，两个标识符实参均为“随机”。
- `-CallResetsj`在 `0x1002892F0/0x100289324`以目标bundle调用Resetsj两次，随后 `0x100289354/0x10028939C`的X2=0；后两次是nil，不能虚构另一个bundle。已执行前述同一SQL核心，SQL失败不会自动回滚所有已删行。
- 两个子命令尾部还调用 `lrproki:`并枚举 `/var/mobile/Library/Logs/CrashReporter`、`/var/mobile/Library/Logs/AppleSupport`。目录fixture为空，只证明请求枚举，不宣称删除了其中真实日志。
- “结束持久化”在 `0x1002C1578–0x1002C17D0`逐次调用 `+[dfyyDG2 lrproki:]`@`0x1000F404C`，传31个C字符串（logd_helper重复）。原始字符串及调用VA保存于 `child_end_persistence.requested_process_names`；截断形式如MobileGestaltHelp未补成完整进程名。第三轮空表边界已由第四轮非空表及错误矩阵补证，见 §9；该链是短名称子串匹配后的SIGKILL，不等于helper刷新中的backboardd SIGTERM。

### 8.6 第三轮证据与复现

`control-cleanup-extra-data.json`是13346新采集的deldir/策略/结束持久化反汇编；`control-fixtures.json`包含46个主程序最终用例，`helper-fixtures.json`含14个helper用例。新增60个加上原核心31个，共91个用例全部通过。

| 主程序VA / 文件偏移 | 原始字节 | 独立解码/语义关联 |
|---|---|---|
| `0x1003386D0` / `0x3386D0` | `82cb2094` | BL objc_msgSend；一键新机action构造 |
| `0x100341290` / `0x341290` | `92a82094` | BL objc_msgSend；选择器/寄存器确认yjxj2: |
| `0x10032DB34` / `0x32DB34` | `8138f797` | BL `0x1000FBD38`，-Callreuid包装器 |
| `0x10032DBA0` / `0x32DBA0` | `ad32f797` | BL `0x1000FA654`，-CallResetsj包装器 |
| `0x1000FC39C` / `0xFC39C` | `9dbc2994` | BL `0x100B6B610`，posix_spawn桩 |
| `0x1000FBB74` / `0xFBB74` | `a7be2994` | BL同一posix_spawn桩 |

`verify_control.py`逐字节核对184,307条IDA记录（177,746个不同指令地址）、2,518条helper记录，独立解码732个不同直接调用/尾跳点，另核对五个菜单对象/明文/handler及IDA三个完整代码区间哈希。计数不是全程序覆盖率。

```sh
/opt/homebrew/bin/python3 work/dgassistant-byte-audit/recover_control_labels.py
/opt/homebrew/bin/python3 work/dgassistant-byte-audit/run_control_checks.py
/opt/homebrew/bin/python3 work/dgassistant-byte-audit/verify_control.py
```

用例的files、directories、SQL行集、失败注入、队列与寄存器均归档；未执行真实子进程、设备文件删除或服务注销。校验回调/OS/Foundation模型边界详见总报告 §12，不把边界误写为未追到按钮与函数。

## 9. 第四轮：“结束持久化”的进程匹配与失败分支

### 9.1 从命令到非空进程表

沿用 §8.2的真实argv：main `0x1002C2D6C` → 命令比较/分派 → `0x1002C1578–0x1002C17D0`的31次 `dfyyDG2.lrproki:` → `0x1000F404C`原始终止器。此次不再用空表代替核心判断；将明确的原始记录缓冲交给原sysctl后续指令，实际执行遍历、匹配及信号参数设置。

| 位置 | 原始参数/语义 |
|---|---|
| `0x1000F43B4` | `sysctl([1,14,0,0],4,NULL,&size,NULL,0)`查询长度 |
| `0x1000F44DC` | `realloc(old,size+floor(size/10))`，本组648字节表先申请712字节 |
| `0x1000F43F0` | 同一MIB取表到buffer，输出长度用于计算条目数 |
| `0x1000F45FC`及后续MADD | 每条记录步长0x288（648），不是按路径数组遍历 |
| `0x1000F461C` | 从条目+0x28取32位PID |
| `0x1000F462C` | `proc_pidpath(pid,stackBuffer,1024)`；原判断要求返回值>0 |
| `0x1000F47A4` | 把条目+0xF3作为短名称C字符串转NSString |
| `0x1000F47E4` | `containsString:`，参数为该次传入的目标C字符串转成的NSString |
| `0x1000F48E4/0x1000F48E8` | 设置W1=9后 `kill(pid,9)`；同函数另有等价的9信号块 |

关键区别：proc_pidpath返回的**路径文本不参加containsString比较**，只是成功前置条件。原逻辑比较的是进程记录短名称；区分大小写，不是精确相等，也不是全路径匹配。

### 9.2 正向、反向与失败矩阵

目标字符串均为 `securityd`，PID均为fixture，不指向主机实际进程：

| 输入/错误 | 原指令结果 |
|---|---|
| comm=securityd，路径获取成功 | 请求kill(4242,9) |
| comm=mysecuritydX | 仍请求kill，证明是包含匹配 |
| comm=SecurityD | 不请求kill，证明区分大小写 |
| comm=other，路径=/securityd | 不请求kill；路径不能替代名称 |
| comm=securityd，路径=/unrelated且获取成功 | 仍请求kill |
| proc_pidpath返回0或-1 | 跳过该条目，不发信号 |
| kill返回-1 | 不重试、不据此停止遍历；继续处理后续条目 |
| 取表sysctl=-1，errno=5 | 不遍历该表，结束并清理缓冲 |
| 取表sysctl=-1，errno=12 | 在 `0x1000F44A8`命中ENOMEM分支，扩容后重试；先失败后成功用例最终仍匹配发信号 |
| realloc返回NULL | 不遍历，不发信号 |
| 首次查询sysctl=-1 | 原代码没有先以该返回值退出；本组后续调用因容量不足返回ENOMEM，再扩容成功，最终可发信号。不是“首次失败必然成功”的设备断言 |
| 同表两个名称包含目标 | 两项分别请求信号9，不在首个匹配后返回 |
| 表项PID等于fixture getpid=555且名称匹配 | 仍提交kill(555,9)，没有独立排除自身PID的保护 |

17个进程用例包括上述15个独立终止器用例及两个完整子命令用例。完整子命令输入四个表项：104/lsd-helper、101/securityd、102/childsecurityd和103/other（路径含securityd）。原main按lsd→securityd顺序产生 `[104,9]、[101,9]、[102,9]`，103不命中；所有kill返回-1时同样继续调用，main最后仍返回0。

`lrproki:`本身没有汇总成功/失败的BOOL契约；不能把模型_free返回后寄存器X0恰为0解释为成功。main的0退出也不证明任何服务真的退出或重启。信号9只是原程序发出的请求，kernel是否允许、目标是否仍存活由系统决定。

### 9.3 31个原始目标字符串

顺序保留，包含原始截断形式，不把它们擅自扩写成更长名称：

```text
lsd, securityd, keychaind, homed, cfprefsd,
MobileGestaltHelp, MobileGestaltHel, MobileGestalt, mobilegestalt,
logd, diagnosticd, symptomsd, logd_helper, symptomsd-diag, keychaindeleter,
CloudKeychainPro, nanoregistrylaun, nanoprefsyncd, assetsd, mobileassetd,
CacheDeleteAppCo, AssetCacheLocato, ckdiscretionaryd, CMFSyncAgent,
fileproviderd, filecoordination, fseventsd, deleted, deleted_helper,
MobileBackupCach, logd_helper
```

短名称缓冲本身长度有限，结合containsString语义，截断目标并不等于“肯定找不到”。helper `_killall(@"backboardd",1)`则取进程路径的末组件与backboardd精确比较、选择信号15；与这里不同，不能统称一次注销。

### 9.4 字节锚点及证据

| 主程序VA / 文件偏移 | 原始字节 | 解码/关联 |
|---|---|---|
| `0x1000F43B4` / `0xF43B4` | `26de2994` | BL sysctl桩 `0x100B6BC4C` |
| `0x1000F44A8` / `0xF44A8` | `1f310071` | CMP W8,#12，ENOMEM |
| `0x1000F45FC` / `0xF45FC` | `08518052` | MOV W8,#0x288 |
| `0x1000F47A4` / `0xF47A4` | `e2ce0391` | ADD X2,X23,#0xF3，短名称地址 |
| `0x1000F47E4` / `0xF47E4` | `3ddb2994` | BL objc_msgSend；实际selector=containsString: |
| `0x1000F48E4` / `0xF48E4` | `21018052` | MOV W1,#9 |
| `0x1000F48E8` / `0xF48E8` | `66da2994` | BL kill桩 `0x100B6B280` |

`process-fixtures.json`保存进程输入、sysctl原始输出hex、PID/短名称偏移、proc_pidpath结果和kill参数/失败；`seed-process-byte-verification.json`独立核对原字节与调用/尾跳目标。原31+60个用例回归通过，第四轮35个断言（含隐藏子报告中的1个预期空读）通过，共126个。

复现入口为 `run_seed_process_checks.py`、`verify_seed_process.py`；修改前版本、差异与哈希仍在同一案例目录。本轮没有执行真实sysctl取表、proc_pidpath或kill；被建模的是OS输入输出，**不是匹配谓词、循环、错误分支或信号选择**。
