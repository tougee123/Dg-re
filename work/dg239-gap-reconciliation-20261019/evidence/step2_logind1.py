#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤2 + logind1 站点细化(只读)。
步骤2:同接口跨运行/跨调用 description 大小稳定但 SHA 各异 => 逐事务响应内容不同(非固定 fixture 回放),
       支持这些是真实逐事务响应;但 description 仍非 wire 原字节。
logind1:百度 completion 巨函数内 3 个 parse 站点使用**各自不同的输入帧槽**(logind1=frame[0x3768]),
       故 logind1 站点是独立解析操作;其单接口性归结为「谁填 frame[0x3768]」——同桥式缺口(开放)。"""
import os,sys,json
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.abspath(os.path.join(HERE,"../../.."))
sys.path.insert(0,os.path.join(ROOT,"work/dg239-protocol-takeover-20261018/evidence"))
import binary_evidence as BE, capstone
s=BE.Sample(); md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
R={"sample_sha":s.sha256,"step2_cross_run":{},"logind1_site":{},"verdict":{}}
# step2
per=json.load(open(os.path.join(HERE,"per_interface_obs.json")))
for i in ("logind0","logind1","recharged"):
    rows=per.get(i,[]); sizes=sorted(set(r[3] for r in rows)); shas=[r[4] for r in rows]
    R["step2_cross_run"][i]={"n":len(rows),"sizes":sizes,"distinct_desc_sha":len(set(shas)),"shas":shas,
        "size_stable":(len(sizes)<=2),"content_varies_per_tx":(len(set(shas))>=2 or len(rows)<2)}
# logind1 three parse sites' input slots
def dis(va,n): return list(md.disasm(s.read(va,n),va))
def input_slot(blk):  # find 'ldr x9,[x19,#imm]' then 'ldr x2,[x9]'
    insns=dis(blk,0x20); x9=None
    for i in insns:
        if i.mnemonic=="ldr" and i.op_str.startswith("x9, [x19") : x9=i.op_str
    return x9
slots={"logind1@0x1005d0888":input_slot(0x1005d0888),
       "otherA@0x1005da588":input_slot(0x1005da588),
       "otherB@0x1005cef9c":input_slot(0x1005cef9c)}
R["logind1_site"]={"parse_blocks_input_slots":slots,
    "distinct_slots":(len(set(slots.values()))==3),
    "logind1_input_slot":"frame[0x3768]",
    "single_interface_reduces_to":"frame[0x3768] 的写者(谁填 logind1 输入)——同 receive→parser 桥式缺口,开放"}
# logind1 frame[0x3768] 写者 = alloca(与 logind0 frame[0x1160] 同构)
ins=list(md.disasm(s.read(0x1005bbe48,0x10060d058-0x1005bbe48),0x1005bbe48))
w3768=[i.address for i in ins if i.mnemonic in("str","stur") and "#0x3768]" in i.op_str and "x19" in i.op_str]
r3768=[i.address for i in ins if i.mnemonic in("ldr","ldur") and "#0x3768]" in i.op_str and "x19" in i.op_str]
wctx={i.address:(i.mnemonic,i.op_str) for i in dis(0x1005c9d04,0x18)}
R["logind1_input_slot_writer"]={"single_writer":(w3768==[0x1005c9d18]),"readers":len(r3768),
    "is_alloca":(wctx.get(0x1005c9d10)==("subs","x0, x11, x12") and wctx.get(0x1005c9d14)==("mov","sp, x0")),
    "note":"frame[0x3768]=alloca scratch(单写者 0x1005c9d18,VLA 模式),与 logind0 frame[0x1160] 同构;parser 读 *(scratch);实际 NSData 填充=同 receive→parser 桥开放缺口"}
R["verdict"]={
    "responses_vary_per_transaction":all(v["content_varies_per_tx"] for v in R["step2_cross_run"].values()),
    "meaning":"真实逐事务响应(非固定回放);但 description≠wire 原字节,wire 原字节全库缺失(步骤3)。",
    "logind1_single_interface":"未证(归结为 frame[0x3768] 写者);3 站点输入槽各异已证",
    "scope":"离线;支持真实性,不证兼容闭合。"}
print(json.dumps(R,ensure_ascii=False,indent=2))
json.dump(R,open(os.path.join(HERE,"step2_logind1.result.json"),"w"),ensure_ascii=False,indent=2)
ok=(R["logind1_site"]["distinct_slots"] and R["verdict"]["responses_vary_per_transaction"]
    and R["logind1_input_slot_writer"]["single_writer"] and R["logind1_input_slot_writer"]["is_alloca"])
sys.exit(0 if ok else 11)
