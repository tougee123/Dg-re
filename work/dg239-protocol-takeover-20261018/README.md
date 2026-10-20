# DG239 协议离线接手复核

主报告：[协议与接入边界](report/PROTOCOL_REVIEW.md)。状态：局部复核通过，完整客户端/后端兼容未验收。

- 本会话直接处理；不向 Claude、Harness、旧 Codex 或子智能体派发。
- 范围：既有日志和原二进制；不连接手机、不运行 DG、不兑换、不修改授权。
- 三接口逐份区分 fixture 与 live；恢复 logind0 构造体索引；核 data3 门和百度捕获/内存版本。
- 2026-10-19 两轮各 50 项离线测试通过；不把局部验证通过当作完整授权到 UI 闭合。
- 原始敏感日志保留原位置，报告只引用摘要和事件位置；旧 case 不改写。

```sh
python3 -m unittest discover -s work/dg239-protocol-takeover-20261018/evidence -p 'test_*.py'
```

`report/` 保存证据元数据与结论；`publication/` 保存本轮共享报告修订前备份、差异及发布摘要；`manifest.json` 是本轮文件冻结清单（不含自身和 Python 缓存）。
