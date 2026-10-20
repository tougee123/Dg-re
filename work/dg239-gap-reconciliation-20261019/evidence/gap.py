#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""缺口核对(只读):把现有真实采集按 parse 站点 caller **静态归属**到接口,并对每接口各环节标注缺口四分类。
离线推进点:caller(parse 站点返回地址)静态标识接口,强于 ledger 曾用的时序/线程(ledger endpoint=None)。
仅输出地址/行号/长度/哈希/计数;不输出正文。不连设备/不改授权。"""
import sys,os,json
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.abspath(os.path.join(HERE,"../../.."))
sys.path.insert(0,os.path.join(ROOT,"work/dg239-protocol-takeover-20261018/evidence"))
import binary_evidence as BE, capstone
s=BE.Sample(); md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
PS=os.path.join(ROOT,"work/dg239-protocol-takeover-20261018/report/parser-stages.json")
ps=json.load(open(PS))
# caller(返回地址=blr 下一条)-> parse blr -> 接口
CALLER2IFACE={0x1008496b0:"logind0",0x10037c86c:"recharged",0x1005d08ac:"logind1"}
# 校验三 parse 站点(blr 的地址=caller-4)在三个不同 LC_FUNCTION_STARTS 函数内
def fstarts():
    import struct
    for off in [32]:
        pass
    # 用 helper 没有暴露 function_starts;改用:三 blr 地址互不相同 + 分别可反汇编为 blr x8
    return None
R={"sample_sha":s.sha256,"caller_attribution":{},"per_interface":{},"negative_tests":{},"verdict":{}}
# 反汇编确认三 blr 均为 blr x8(parse 调用)
import struct
def is_blr_x8(blr_va):
    i=next(md.disasm(s.read(blr_va,4),blr_va),None); return i is not None and i.mnemonic=="blr" and i.op_str=="x8"
for caller,iface in CALLER2IFACE.items():
    blr=caller-4
    R["caller_attribution"][iface]={"parse_blr":hex(blr),"return_caller":hex(caller),"is_blr_x8":is_blr_x8(blr)}
# 归属真实观测
per={}
for src in ps["sources"]:
    tag=src["sha256"]
    for r in src["rows"]:
        c=r.get("unslid_caller"); cv=int(c,16) if isinstance(c,str) else c
        iface=CALLER2IFACE.get(cv)
        if not iface: continue
        per.setdefault(iface,[]).append({"src_sha12":tag[:12],"line":r.get("event_line"),"call":r.get("call_id"),
            "tid":r.get("event_tid"),"desc_bytes":r.get("description_bytes"),"desc_sha12":(r.get("description_sha256") or "")[:12],
            "options":r.get("options"),"error_out":r.get("error_out"),
            "ledger_endpoint":r.get("endpoint"),"wire_response_proven":r.get("wire_response_proven")})
# 请求构造侧来源(既有,SHA 固定)
REQSRC={"logind0":{"gz":"work/dgassistant-239-startup/evidence/activation-second-json-exploration.json.gz",
                   "sha":"5908d5aff538cc864be31906f3d6837581db1294c2d719e017790d5ffb61a5b5",
                   "events":"/events/19374/args/1..19384","body_len":2456,
                   "body_sha":"fcf2cbae9e512dde841b7df9fdfdb0641a6938e4fdb5cb4464716425bb64740c"},
        "recharged":{"gz":"work/dgassistant-239-startup/evidence/activation-clipboard-final-exploration.json.gz",
                   "sha":"946560b2c77ae7dd7793384e6af1a4459dd6c50de298758d0690e2f2a2c33cbd",
                   "events":"/events/672,734,1947","body_len":374},
        "logind1":{"gz":"(fixture header+body;见 PROTOCOL_REVIEW §3.1/interface-matrix)","sha":"(见 interface-matrix.json)"}}
for iface in ("logind1","logind0","recharged"):
    obs=per.get(iface,[])
    R["per_interface"][iface]={
      "request_construction":{"evidence":REQSRC[iface],"gap_type":"已有记录(构造);通用封装/动态字段类型未证"},
      "actual_send":{"evidence":"fixture 请求头(logind0 174B/recharged 527B);socket 缓冲无正文","gap_type":"记录截断/未证发送成功(send_result_verified=false)"},
      "final_response":{"real_parse_observations":obs,"count":len(obs),
          "offline_advance":"按 caller 静态归属到本接口(ledger 曾 endpoint=None)",
          "gap_type":"已有记录但缺事务/对象关联 + 描述非原字节(wire_response_proven=false;parser-stages.limits:无 receive-buffer→parser 桥、描述≠wire 标量、指针无代次证明)"},
      "decode_in_out":{"evidence":"parse 输入/结果指针与 options=1/err=0 已记录","gap_type":"已有记录但缺关联(输入为 description 级;解码链>parse 未绑定)"},
      "verification_sign_udid_endtime":{"evidence":"ACPDS/intValue/时间比较局部采集(PROTOCOL_REVIEW §6)","gap_type":"已有记录但缺同事务绑定"},
      "persistence_cache":{"evidence":"endtime→tz0111ct setter、ct getter→ACPDS、24B014 事件存在","gap_type":"已有记录但缺磁盘域/写后读回/同事务绑定"},
      "startup_readback":{"evidence":"清剪贴板关 DG 后正常启动进主界面(用户确认)+ 24B014 事件","gap_type":"已有运行观测;逐校验谓词到入口的同状态可达未证"}}
# 负测试:三 caller 互异且均 blr x8(否则归属无效)
callers=list(CALLER2IFACE.keys())
R["negative_tests"]["three_callers_distinct"]=(len(set(callers))==3)
R["negative_tests"]["all_parse_sites_are_blr_x8"]=all(R["caller_attribution"][i]["is_blr_x8"] for i in CALLER2IFACE.values())
# 一致性:同接口跨两次独立运行的 desc 大小是否稳定(支持归属稳健性,非证明)
def sizes(i): return sorted(set(o["desc_bytes"] for o in per.get(i,[])))
R["verdict"]={
  "attribution_method":"caller(parse 站点返回地址)静态归属;比时序/线程强,但仍需确认该 parse 站点为单接口专用(未在本脚本证明站点单接口)",
  "obs_counts":{i:len(per.get(i,[])) for i in ("logind1","logind0","recharged")},
  "desc_size_sets":{i:sizes(i) for i in ("logind1","logind0","recharged")},
  "core_gap":"三接口 final_response 均为「已有记录但缺事务/对象关联」+「描述非 wire 原字节」;非「未采集」。",
  "offline_next":["确认三 parse 站点是否单接口专用(函数内是否仅该接口路径到达)以坐实 caller 归属",
                  "用 desc_sha 跨运行比对与 request body 关联;检索 corpus 是否存在保留了 wire 原字节(而非 description)的采集字段",
                  "receive-buffer→parser 桥(见 dg239-logind0-receive-parser-bridge)"],
  "scope":"离线;caller 归属为静态推进;wire 原字节/代次/同事务绑定仍为既有记录的缺关联项,不虚构闭合。"}
print(json.dumps(R,ensure_ascii=False,indent=2))
json.dump(R,open(os.path.join(HERE,"gap.result.json"),"w"),ensure_ascii=False,indent=2)
ok=(R["negative_tests"]["three_callers_distinct"] and R["negative_tests"]["all_parse_sites_are_blr_x8"]
    and all(len(per.get(i,[]))>0 for i in ("logind1","logind0","recharged")))
sys.exit(0 if ok else 9)
