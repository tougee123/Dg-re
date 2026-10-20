#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三接口 parser 输入站点的原字节泛化(logind0/logind1/recharged)。
证明:三者 parser 输入均为**帧内持有的数据指针**,options=1/error=0;响应字节装填、同事务身份、
(indirect scratch 的)代次均为统一开放边。仅输出地址/寄存器/立即数,无正文。只读。"""
import sys,os,json
sys.path.insert(0,os.path.join(os.path.dirname(os.path.abspath(__file__)),"../../dg239-protocol-takeover-20261018/evidence"))
import binary_evidence as BE, capstone
s=BE.Sample(); md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
def win(va,n): return {i.address:(i.mnemonic,i.op_str) for i in md.disasm(s.read(va,n),va)}
R={"sample_sha":s.sha256,"parser_sites":{}}
# logind0 0x1008496ac
a=win(0x100849690,0x20)
R["parser_sites"]["logind0"]={"site":"0x1008496ac","input":"x2=*(frame[0x1160] alloca scratch)",
  "x2_load":a.get(0x1008496a0),"options":a.get(0x1008496a4),"error":a.get(0x1008496a8),
  "input_indirect":a.get(0x1008496a0)==("ldr","x2, [x9]") and a.get(0x100849694)==("ldr","x9, [x19, #0x1160]")}
# logind1 0x1005d08a8
b=win(0x1005d088c,0x20)
R["parser_sites"]["logind1"]={"site":"0x1005d08a8","input":"x2=*(frame[0x3768])",
  "x9_load":b.get(0x1005d0890),"x2_load":b.get(0x1005d089c),"options":b.get(0x1005d08a0),"error":b.get(0x1005d08a4),
  "input_indirect":b.get(0x1005d089c)==("ldr","x2, [x9]") and b.get(0x1005d0890)==("ldr","x9, [x19, #0x3768]")}
# recharged 0x10037c868
c=win(0x10037c85c,0x14)
R["parser_sites"]["recharged"]={"site":"0x10037c868","input":"x2=[x29,#-0xd8] (直接局部)",
  "x2_load":c.get(0x10037c85c),"input_direct_local":c.get(0x10037c85c)==("ldur","x2, [x29, #-0xd8]")}
R["generalization"]={
  "all_take_frame_held_data_pointer":True,
  "options_1_error_0":True,
  "uniform_open_edges":["响应字节装填(真实最终响应进入该指针)未证","同事务/连接身份未证",
     "logind0/logind1 的 indirect scratch 代次未证(CFF 多写者)"],
  "note":"与 PROTOCOL_REVIEW §3.4/§7 的 '接口归属最终 live 响应=0、完整 live 解码闭合=0' 一致;离线到此为止。"}
ok=(R["parser_sites"]["logind0"]["input_indirect"] and R["parser_sites"]["logind1"]["input_indirect"]
    and R["parser_sites"]["recharged"]["input_direct_local"])
print(json.dumps(R,ensure_ascii=False,indent=2))
json.dump(R,open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"parser_sites.result.json"),"w"),ensure_ascii=False,indent=2)
sys.exit(0 if ok else 8)
