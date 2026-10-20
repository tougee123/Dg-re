#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logind0 接收对象 → parser 因果桥(只读原字节 + 离线 chained-fixup 绑定)。
重建并校验下列边(全部原字节);对无法静态闭合者显式列缺口。仅输出地址/类型/长度/哈希/符号名,不输出敏感正文。
样本 SHA 见 Sample。无联网/设备/IDA 修改。
"""
import sys,os,struct,hashlib
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,os.path.join(HERE,"../../dg239-protocol-takeover-20261018/evidence"))
import binary_evidence as BE
import capstone
s=BE.Sample(); md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
def dis(va,n): return list(md.disasm(s.read(va,n),va))
def one(va): return dis(va,4)[0]
R={"sample_sha":s.sha256,"proven_edges":{},"negative_tests":{},"unresolved_edges":[],"verdict":{}}

# E1 parse site: x2=*(frame[0x1160]); options=1; err=0; result->frame[0xf78]
blk=dis(0x10084968c,0x28)
asm={i.address:(i.mnemonic,i.op_str) for i in blk}
R["proven_edges"]["parse_site"]={
 "x9_eq_frame_0x1160": asm.get(0x100849694)==("ldr","x9, [x19, #0x1160]"),
 "x2_eq_deref_buffer": asm.get(0x1008496a0)==("ldr","x2, [x9]"),
 "options_1": asm.get(0x1008496a4)==("mov","x3, #1"),
 "error_0": asm.get(0x1008496a8)==("mov","x4, #0"),
 "parse_call": asm.get(0x1008496ac)==("blr","x8"),
 "result_to_frame_0xf78": asm.get(0x1008496b0)==("str","x0, [x19, #0xf78]")}

# E2 buffer content writer: *(frame[0x1160]) = frame[0x1158]
w=dis(0x100834be0,0x10); wa={i.address:(i.mnemonic,i.op_str) for i in w}
R["proven_edges"]["buffer_content_writer"]={
 "load_frame_0x1158": wa.get(0x100834be8)==("ldr","x0, [x19, #0x1158]"),
 "load_buffer_0x1160": wa.get(0x100834be4)==("ldr","x9, [x19, #0x1160]"),
 "store_through_buffer": wa.get(0x100834bec)==("str","x0, [x9]")}

# E3 frame[0x1158] single writer + direct-branch write order
LO,HI=0x10080B9CC,0x100851800
ins=list(md.disasm(s.read(LO,HI-LO),LO))
w1158=[i.address for i in ins if i.mnemonic in("str","stur") and "#0x1158]" in i.op_str and "x19" in i.op_str]
R["proven_edges"]["frame_0x1158"]={
 "single_writer": (w1158==[0x100841ff8]),
 "writer_is_wrapper_of_frame_0x6f8": (asm2:={i.address:(i.mnemonic,i.op_str) for i in dis(0x100841ff0,0x10)}) and
    asm2.get(0x100841ff0)==("ldr","x0, [x19, #0x6f8]") and asm2.get(0x100841ff4)==("bl","#0x1008965c8") and asm2.get(0x100841ff8)==("str","x0, [x19, #0x1158]"),
 "direct_branch_to_buffer_block": asm2.get(0x100841ffc)==("b","#0x100834be0")}

# E4 frame[0x6f8] = objc_alloc(frame[0x9f0]); frame[0x9f0] = class *(0x100bc28f8)
a6=dis(0x100842618,0xc); a6a={i.address:(i.mnemonic,i.op_str) for i in a6}
try: alloc_sym=s.stub_symbol(0x100ae00a8).get("name")
except Exception: alloc_sym=None
R["proven_edges"]["alloc"]={
 "load_class_frame_0x9f0": a6a.get(0x100842618)==("ldr","x0, [x19, #0x9f0]"),
 "call_objc_alloc": a6a.get(0x10084261c)==("bl","#0x100ae00a8"),
 "objc_alloc_import": alloc_sym=="_objc_alloc",
 "store_frame_0x6f8": a6a.get(0x100842620)==("str","x0, [x19, #0x6f8]")}
# class bind (offline chained-fixup via lief)
cls=None
try:
    import lief
    b=lief.parse(str(BE.SAMPLE))
    for bi in b.dyld_info.bindings:
        if bi.address==0x100bc28f8 and bi.symbol: cls=bi.symbol.name; break
except Exception as e: cls="lief-unavailable:%s"%str(e)[:30]
R["proven_edges"]["accumulation_class"]={"classref_va":"0x100bc28f8","bind_symbol":cls,
    "is_NSMutableData": cls=="_OBJC_CLASS_$_NSMutableData"}

# NT1 frame[0x1158] 读取指令目的槽字节变异 => 槽号改变(识别来自字节)
w=struct.unpack_from("<I",s.read(0x100834be8,4),0)[0]
mut=(w & ~(0xFFF<<10)) | ((0x1158//8 ^ 1)<<10)   # 改 imm12(scaled)
di=next(iter(md.disasm(struct.pack("<I",mut),0x100834be8)),None)
R["negative_tests"]["frame1158_read_imm_byte_derived"]=(di is not None and "#0x1158]" not in di.op_str)
# NT2 单写者计数为 1(若改一处 glob 会破坏)——此处断言计数真实
R["negative_tests"]["frame1158_single_writer_count_is_1"]=(len(w1158)==1)

R["unresolved_edges"]=[
 "appendData:/appendBytes:length: 的实际调用点是否写入**本 NSMutableData 实例**(frame[0x6f8])——接收累积写经对象指针,不在帧槽拷贝链内;两选择子字符串存在(fileoff 0xb11ae7 / 0xb11ad3),但到本实例的 xref 绑定未闭合。",
 "buffer frame[0x1160] 有 3 个写者(0x10080d0c0 / 0x100810f24 / 0x10084d8b8 alloca);parse 读取的 buffer 代次与内容写(0x100834bec)代次在 CFF br x8 分派下未证相等(frame[0x1158] 单写者使对象身份稳定,但 buffer 代次仍未闭合)。",
 "同事务接收绑定:该 NSMutableData 累积的是 logind0 **服务器响应**(而非请求回显或他连接),需把 appendData 源绑定到 logind0 连接的 didReceiveData 接收回调(连接代次/事务身份)——handoff 的接收登记(选项 10001/20011)核心开放边。"]
# 诚实校正:frame[0x6f8] 在外层函数内仅 2 处访问(alloc 写 + bridge 读),无 appendData/ivar-store
f6f8=[i.address for i in ins if "#0x6f8]" in i.op_str]
R["proven_edges"]["instance_not_filled_in_func"]={
 "frame_0x6f8_access_count": len(f6f8),
 "no_append_or_ivar_store_in_outer_func": (len(f6f8)==2)}  # 仅 0x100842620 写 + 0x100841ff0 读
R["verdict"]={
 "candidate_object_class":"NSMutableData(objc_alloc @0x100842618;classref *(0x100bc28f8)=_OBJC_CLASS_$_NSMutableData)",
 "proven_slot_path":"frame[0x9f0](类) -> frame[0x6f8]=objc_alloc(类) -> (retain 0x1008965c8) frame[0x1158] -> *(alloca scratch frame[0x1160]) @0x100834bec -> parser x2 @0x1008496a0(options=1 err=0 -> frame[0xf78]);frame[0x1158] 写->buffer 写为直接分支(写序已证)",
 "CORRECTED_not_overclaimed":[
   "frame[0x1160] 是 alloca scratch,有 3 个地址写者(0x10080d0c0/0x100810f24/0x10084d8b8);parser 读的 buffer 代次与 0x100834bec 写的代次在 CFF 下未证相等 => 不能断定 parser 读到的就是该 NSMutableData。",
   "frame[0x6f8] 在外层函数仅 2 处访问、无 appendData/无 ivar-store => 本函数内未见该实例被填充;appendData 在独立委托函数(0x100386e3c 等)。",
   "因此'parser 输入==已装填响应字节的接收累积对象'离线未证;这与 handoff 告警一致(frame+0x1160 存分配地址而非响应正文写;登记存对象值而非响应 cell)。"],
 "status":"已原字节定位 parser 输入=*(alloca scratch);候选内容写是一枚新 objc_alloc 的 NSMutableData(类已离线绑定),但 buffer 代次、该实例是否被响应字节装填、同事务接收绑定三者离线未闭合。",
 "scope":"原字节 + 离线 fixup;非实机证明;不声称 parser 读到响应或授权成立。"}
all_proven=all(all(v.values()) if isinstance(v,dict) else v for v in R["proven_edges"].values() if isinstance(v,dict))
import json
print(json.dumps(R,ensure_ascii=False,indent=2))
json.dump(R,open(os.path.join(HERE,"bridge.result.json"),"w"),ensure_ascii=False,indent=2)
ok=(all_proven and R["negative_tests"]["frame1158_read_imm_byte_derived"] and R["negative_tests"]["frame1158_single_writer_count_is_1"]
    and R["proven_edges"]["accumulation_class"]["is_NSMutableData"])
sys.exit(0 if ok else 7)
