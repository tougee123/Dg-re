#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤1:三 parse 站点是否单接口专用(坐实 caller 归属)。只读原字节。
结果:recharged/logind0 各自函数内**仅有该一个 parse 站点**→caller 归属稳固;
logind1 的 parse 站点落在**百度 dataTask completion 巨函数**[0x1005bbe48,0x10060d058) 内,该函数含 3 个 parse 站点
→站点精确但函数非单接口;logind1 响应解析与百度 completion **同函数共处**(跨接口发现)。"""
import sys,os,json,struct,bisect
sys.path.insert(0,os.path.join(os.path.dirname(os.path.abspath(__file__)),"../../dg239-protocol-takeover-20261018/evidence"))
import binary_evidence as BE, capstone
s=BE.Sample(); md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
off=32; TEXT=None; FS=None
for _ in range(struct.unpack_from("<I",s.raw,16)[0]):
    cmd,size=struct.unpack_from("<II",s.raw,off)
    if cmd==0x19 and s.raw[off+8:off+24].split(b"\0")[0]==b"__TEXT": TEXT=struct.unpack_from("<QQQQ",s.raw,off+24)
    elif cmd==0x26: FS=struct.unpack_from("<II",s.raw,off+8)
    off+=size
TVM=TEXT[0]; blob=s.raw[FS[0]:FS[0]+FS[1]]; starts=[]; va=TVM; i=0
while i<len(blob):
    shf=0;d=0
    while True:
        b=blob[i];i+=1;d|=(b&0x7f)<<shf
        if not(b&0x80):break
        shf+=7
    if d==0 and starts:break
    va+=d; starts.append(va)
def func_of(va):
    k=bisect.bisect_right(starts,va)-1
    return (starts[k], starts[k+1] if k+1<len(starts) else None)
ALL_PARSE=[0x1008496ac,0x1005d08a8,0x10037c868,0x10066189c,0x1005da5a8,0x1005cefbc,0x100592be0]
IFACE={0x1008496ac:"logind0",0x1005d08a8:"logind1",0x10037c868:"recharged"}
byfunc={}
for p in ALL_PARSE: byfunc.setdefault(func_of(p),[]).append(p)
R={"sample_sha":s.sha256,"parse_sites":{},"verdict":{}}
for iface_site,iface in IFACE.items():
    f=func_of(iface_site); sibs=byfunc[f]
    R["parse_sites"][iface]={"parse_blr":hex(iface_site),"func":[hex(f[0]),hex(f[1]) if f[1] else None],
        "func_size":(f[1]-f[0]) if f[1] else None,"parse_sites_in_func":[hex(x) for x in sibs],
        "sole_parse_in_func":(len(sibs)==1),
        "func_is_baidu_completion":(f[0]==0x1005bbe48)}
R["verdict"]={
  "recharged_attribution":"solid(own function %s,sole parse)"%hex(func_of(0x10037c868)[0]),
  "logind0_attribution":"solid(function %s,sole parse)"%hex(func_of(0x1008496ac)[0]),
  "logind1_attribution":"site-exact but function NOT single-interface:落在百度 completion 巨函数 0x1005bbe48,内含 3 parse 站点;logind1 站点是否单接口仍需该函数内 CFF 分派分析",
  "cross_finding":"logind1 响应解析(0x1005d08a8)与百度 /yz dataTask completion(invoke 0x1005bbe48)同函数共处——支持'百度前置与真实授权相关'作为调查线索,不作结论",
  "scope":"原字节 + LC_FUNCTION_STARTS;站点归属=代码位置精确;单接口可达性(logind1)未证"}
print(json.dumps(R,ensure_ascii=False,indent=2))
json.dump(R,open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"parse_site_single_interface.result.json"),"w"),ensure_ascii=False,indent=2)
ok=(R["parse_sites"]["recharged"]["sole_parse_in_func"] and R["parse_sites"]["logind0"]["sole_parse_in_func"]
    and R["parse_sites"]["logind1"]["func_is_baidu_completion"])
sys.exit(0 if ok else 10)
