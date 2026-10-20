# DGAssistant (DG 管理器 v2.3.7) — Security Analysis Facts

## Target
- Binary: `extracted/Payload/DGAssistant.app/DGAssistant` (arm64, Mach-O, cryptid=0, ~23MB)
- Purpose: **PUBG Mobile (和平精英 / ShadowTrackerExt / com.tencent.*) cheat/mod tool** delivered via **TrollStore**
- Injects `520.dylib` (payload) into the game; has kernel-helper capability; disguises files as `com.apple.*`

## Helper tooling in this dir
- `macho.py` — complete VA<->file translator (SECTIONS table, read_va, section_of)
- `uni_decrypt2.py` — Unicorn harness (build_uc, decrypt_site) for CFF-obfuscated blocks
- `extracted_rsa_key.pem` — the embedded RSA-1024 private key (PEM)

## Section layout (VA / size / fileoff)
- `__obf` (all real code, CFF-protected): 0x1000044E8 / 0xB660FC / 17640
- `__cstring`: 0x100BA180B / 0x1E4C7 / 12195851
- `__cfstring` (267 CFConstantString structs): 0x100C41438 / 0x2160 / 12850232
- `__data`: 0x100C4B010 / 0xA1E360 / 12890128
- `__objc_selrefs`: 0x100C493D8 / 0x1408 / 12882904

## Layer 0 — Control Flow Flattening (CFF)
- `BR X8/X9/X10` indirect dispatchers; opaque predicates using globals resolve to constant indices.
- Opaque-predicate global values (dword):
  - 0x100C50260=0x0E5B8705 64=0xAB7E17E0 68=0x5F793A0A 6C=0xCA7C333D
  - 0x100C50278=0x17D48128 7C=0xB50E6B06
  - 0x100C50050=0x069781A0 54=0xB8ED0717 58=0xFBDB1CA7 5C=0x94AEE474
- Bypass: D-810 (partial) OR Unicorn emulation with these globals set (works reliably).

## Layer 1 — String encryption
### (a) Per-byte XOR/MBA in-place (60 strings, all recovered)
- Layout: CFString struct at V; str_ptr = V-0x20 (output, in __data); key table at V-0x40.
- flags=0x7C8, 8-bit. All MBA byte transforms reduce to single-byte XOR.
- Decrypted content (representative):
  - "Fatal error, exiting app" (~40x — anti-tamper bail-out message)
  - "trollstorehelper", "com.apple.a%@%@.plist", "com.apple.ayzuid%@.png"
  - "https://www.baidu.com" (connectivity check only)
  - "%08x%08x%08x%08x" (device-id/hash format), "CFBundleIdentifier"

### (b) AES-128-CBC (key == iv), Base64->AES->UTF8
- ObjC selectors: `ACPDS:kaiv:`, `sub_20255tz0111:kaiv:`, `ADASAMGG82:key:`,
  `AES128DecryptWithKey:iv:`, `AES128Operation:key:iv:` (CCCrypt wrapper).
- CCCrypt params: alg=kCCAlgorithmAES128(0), options=kCCOptionPKCS7Padding(1), keyLen=16.
- CommonCrypto NOT a named import — resolved dynamically (XOR-decrypted names + dlsym).
- `ACPDS:kaiv:` has 18 call sites (below). Ciphertext is DYNAMIC (network/property), not static.
- 7 unique AES-128 keys (hex):
  - 758904d765b65e4bb41d080976b63a35
  - b7db0cf0648ac60fc86d83e813f924cf
  - 3b9e61ab64dc8ad1980dd5b30c237767
  - c6f0cad80627f6480140778267d4e0af
  - 503f8b0e3ba750cb90c531bf2c62c9bc
  - b327fe01111cb257ce6484e4be74db98
  - (7th from prior caller map)

## Layer 2 — Embedded RSA-1024 PRIVATE key (FULL BREAK)
- Location: __cstring 0x100BA2911 (812-char base64 PKCS#1), CFString struct 0x100C42DF8.
- n = 0xb3a14a3ab838021b...333a3a25 (1024-bit), e=65537, verified n==p*q.
- Saved to extracted_rsa_key.pem. Enables decrypt (RSA-with-public) + forge signatures.
- Binary statically links **OpenSSL** (RSA/ECDSA/CMS/TS verify available).

## License / verification model
- License expiry stored in **NSUserDefaults** under key **`tz0111endtime`**.
- Read path: `[[NSUserDefaults standardUserDefaults] objectForKey:@"tz0111endtime"]`
  at 0x1002E4970 and 0x1002E5080; compared to current time.
- **TWO baidu URL strings (XOR-encrypted, DECOY host):**
  - 0x10154A3E0 `https://www.baidu.com` (len 21) — connectivity probe:
    `[NSURL URLWithString:] + [NSURLSession sharedSession]` at 0x10052D6FC.
  - 0x10154B940 `https://www.baidu.com/yz` (len 24, str_ptr 0x10154B730) — **the real
    verification request**, inside `sub_100567AC0` (40KB net fn). Method **POST**
    (`POST` @ 0x10154B74E), JSON body via `dataWithJSONObject:`, `setAllHTTPHeaderFields:`,
    `requestWithURL:`. Response fields `code`/`data`; strings `请授[权]`, `endtime`, `tz0111`
    decrypt in the same function. `www.baidu.com` is a decoy — a POST to baidu.com/yz is not
    real; host is domain-fronted (Host via setAllHTTPHeaderFields:) or runtime-resolved.
    Consumer passes the CFString at 0x10056B85C.
- Redemption-code (兑换码) activation: `请复制兑换码` strings; stored in disguised plist at
  `/var/mobile/Library/Preferences/com.apple.*.plist`.

## Jailbreak/tool detection (decrypted XOR bundle-IDs)
com.opa334.TrollStore, com.opa334.Dopamine, com.roothide.manager, com.roothide.patcher,
wiki.qaq.TrollFools, com.Alfie.TrollInstallerX, org.coolstar.SileoStore, com.tigisoftware.Filza.
Paths: /var/jb/bin/jbctl, /private/var/jb, /var/Keychains/keychain-2.db,
System/Library/Caches/com.apple.kernelcaches/kernelcache, com.apple.lsdidentifiers.plist.
PUBG cheat config target: `%@/Documents/ShadowTrackerExtra/Saved/Config/IOS/UserCustom.ini`.

## EXHAUSTIVE host search (Unicorn decrypt of ALL 1528 XOR strings)
Decrypted every XOR string + scanned all cstrings/base64/IPs. Only URL/host/header vocabulary found:
`https://www.baidu.com`, `https://www.baidu.com/yz`, `POST`, `udid`, `.com.apple*` (plist names).
NO `Host` header, NO alternate domain, NO real hostname, NO hardcoded server IP anywhere.
Base64 blobs (0x101513B00 etc `qNNddlUK+B/YlooNoymwgA`) are 16-byte hashes, not hosts (AES=garbage).
=> `www.baidu.com/yz` is a DECOY; the real server host is NOT in static data. It is runtime-resolved
   (AES/ACPDS network-delivered config, or the whole baidu URL is misdirection). Getting the real host
   REQUIRES dynamic traffic capture (HTTPS proxy: Reqable/Charles/mitmproxy on a TrollStore device).
Tools: trace_calls.py (call tracer), global_header_hunt.py (header/host vocab grep).

## Decryption method that WORKS
Unicorn emulation (uni_decrypt2.decrypt_site) follows CFF `br` via the opaque-predicate globals —
static linear interpretation FAILS (misses branched byte-groups). Start emulation at the ADRP ref to
the SOURCE table (str_ptr - 0x20). See global_url_hunt.py / decrypt_region.py.

## ACPDS:kaiv: 18 call-site -> enclosing (camouflaged as DiDi protobuf SDK classes)
0x1006C7644,0x1006CE180,0x1006D32F0,0x1006D6C10,0x1006E6258,0x1006EA5CC,0x10070F404,
0x10071C2D0,0x100721ADC,0x100724734,0x100727A28,0x10072EBB8,0x10076BCE8,0x10076F274,
0x100777B80,0x100788524,0x10078BFA4,0x100791BCC

## Anti-tamper
- "Fatal error, exiting app" triggered on integrity/debug/jailbreak-evasion failure (~40 gate sites).
- Prior session: ptrace/PEB-style anti-debug present.
