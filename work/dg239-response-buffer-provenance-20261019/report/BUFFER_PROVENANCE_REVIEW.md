# DG239 response buffer provenance review

## Result and scope

Accepted only as local file-import and call-argument evidence. This case does not establish a complete endpoint response decoder, a live class/IMP, an actual object lifetime, or compatibility with the legacy server. The original sample, sealed prior cases, authorization state and shared reports are unchanged. No target process, device or network was accessed.

Sample SHA256: `3841f080d158a9a9f942eb0ca7f38ec8ba7e1677c23c1b92054fb82452e5cf78`. Addresses below are unslid virtual addresses mapped through Mach-O segments, not VA-minus-base file offsets.

## New evidence

`report/bindings.json` decodes the original standard dyld bind stream. A separate LIEF parser agrees on the selected symbol, library and ordinal. The stream contains 2,844 emitted pointer bindings. Selected identities are:

| Slot | File import identity | Bind opcode file offset | Boundary |
|---|---|---|---|
| `0x100BC28F8` | `_OBJC_CLASS_$_NSMutableData`, CoreFoundation, ordinal 12 | 23001031 | Not the live loaded class or constructor return |
| `0x100BC2828` | `_OBJC_CLASS_$_NSString`, Foundation, ordinal 5 | 23000179 | Not the live loaded class or constructor return |
| `0x100B942B8` | `_objc_msgSend`, libobjc, ordinal 13 | 23003110 | Not a selected receiver's actual IMP |

The standard bind decoder handles unsigned-64 wrapped address deltas present in this sample. Unsupported bind opcodes/types, malformed LEBs and invalid emitted addresses fail closed. This is not a decoder for arbitrary Mach-O chained fixups.

`report/buffer-arguments.json` pins ten original instruction windows and four selectors:

1. `0x10083CC48` reads the current value of the NSMutableData class-import slot into frame+0x9F0. `0x10084261C` calls `_objc_alloc` with that value. The allocation effect and return are not substituted.
2. `0x100841FEC` prepares the saved allocated receiver and `init` selector before wrapper call `0x100841FF4`. The wrapper's live message-dispatch slot is evidenced, but its actual returned object and intervening CFF reachability remain open.
3. `0x10083E5C8` reads the object through the current response-cell pointer, saves it at frame+0x880 and calls `_objc_retainAutorelease`. At `0x10083E5D8`, the receiver is reloaded from post-call frame memory before `bytes`. A pre-call pointer is not silently carried through the ownership call.
4. `0x100846134` prepares `length` from the then-current response-cell object. This is a separate memory epoch, not an automatic match to the `bytes` receiver.
5. `0x10083652C` reads a live constructor-dispatch global at `0x1015EC3E0` and the NSString import into separate frame slots. The zero-fill global cannot supply a real target from file bytes.
6. `0x1008544F8` prepares the saved allocation receiver, `initWithData:encoding:`, the then-current response-cell object and encoding 4. It stops before the live indirect call at `0x100854514`. No returned NSString, decoded content or successful continuation is invented.

These windows are not a complete CFG. In particular, the prior case's response-cell registration and `_objc_storeStrong` writer windows remain separate evidence. Their actual order, all aliases, wrapping/restoration and endpoint transaction identity must still be bound.

## Validation

`report/tests-combined.txt`: 13 test methods pass with no skips. Seven cover bind decoding and independent LIEF comparison; six cover original-byte/selector pins, call arguments and barriers. Synthetic memory values test the semantics of linear instructions, not actual runtime objects or successful library implementations.

Negative checks reject changed instruction bytes, selector/import identities, missing/unsupported bindings and malformed streams. Post-call tests deliberately provide distinct independent memory states to expose an invalid epoch merge. These examples do not prove such states occur in the original application.

Reproduce without writing the evidence files:

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3 -m unittest discover -s work/dg239-response-buffer-provenance-20261019/evidence -p 'test_*.py' -v
```

The generators print JSON and are not needed for verification. Do not run them against frozen report output paths.

## Protocol delivery gate

New endpoint-attributed live final responses: **0**. New complete response decoders: **0**. The reviewed corpus's absence of attributed final responses is not a claim that the historical activations failed.

Next, trace the current response cell at the candidate logind0 parser call `0x1008496AC` back through its actual writers, handle/context and receiving callback. Then connect that same transaction to the decoder and its accept/reject branches. Noncontiguous slice tests are not that causal edge. Do not restart an unbounded corpus scan.

After one complete response path is established, repeat independently for logind1 and recharged. Keep data3's active parameter source and empty/nil returns open; keep Baidu completion error/cancellation/captured-state dependencies open. Neither an empty-string implementation nor omission of the Baidu request is approved by this case.

Shared `MASTER_REPORT.md`, the startup contract and interface draft remain at their prior accepted versions. This local review is not publication approval for a compatible SDK, a backend capable of issuing legacy codes, or the complete activation-to-UI chain.
