# Work items

| ID | 目标 | 状态 | 证据 / 限制 |
|---|---|---|---|
| WI-001 | 离线范围、来源库存及调用账本 | 本轮完成 | scope.md；库存193份，较窄账本155来源；错误单独记录，不声称全部历史格式完备 |
| WI-002 | 三接口独立 fixture 及请求构造归属 | 本轮完成 | interface-matrix.json；8响应fixture、2构造fixture；非live接受证明 |
| WI-003 | live JSON-resp 真实语义与来源 | 本轮完成 | parser-stages.json；30条解析输出观察；无端点归属 |
| WI-004 | data3 key-length 门与空输入误判 | 局部完成 | data3-branches.json；完整返回、copy活跃状态开放 |
| WI-005 | 百度捕获+20与两次采样 | 局部完成 | callback-gate.json；全路径及省略等价开放 |
| WI-006 | 三接口通用封装和完整live响应解码 | 开放 | 主报告第7节P0；不以fixture或前置crypto替代 |
| WI-007 | 缓存、验证到24B014/UI完整同状态链 | 开放 | 历史观察存在，所有条件/磁盘回读身份未闭合 |
| WI-008 | 独立测试、报告及有限修订发布 | 本轮有限发布完成 | 两轮各50 tests OK；三份共享文档的备份SHA、发布SHA、原前缀和追加差异独立复核通过；冻结项见manifest.json；报告纠正不等于兼容SDK通过 |

Evidence/Finding/Path 见主报告第8节；过程见 timeline.md；脱敏过程日志见 notes/FIELD_JOURNAL.md。未完成项保持开放，不折算虚构百分比。
