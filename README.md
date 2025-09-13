# public_rev_smc
# Extracting the KEY and TABLE with radare2

## 1) Run analysis
```bash
r2 -AA smc
```

## 2) Locate `.rodata`
```bash
iS~.rodata
# idx=17  name=.rodata  size=0x120  vaddr=0x00402000  paddr=0x00002000  type=PROGBITS
```

## 3) Find code that references our constants (`axt`)
```bash
axt 0x004020a0   # TABLE
axt 0x004020f0   # KEY
```

## 4) Dump the bytes (`px`)
```bash
px  8  @ 0x004020f0   # KEY (8 bytes)
px 74  @ 0x004020a0   # TABLE (74 bytes)
```

**KEY @ `0x004020f0`**
```
13 37 c0 de ba ad f0 0d
```

**TABLE @ `0x004020a0`**
```
70 4e a2 bb c8 ce 9f 63 68 0e f4 ba df c9 c5 6b
75 0e f1 e9 8e 9f c2 6f 75 51 f5 e7 82 cf c1 3a
21 03 a1 ba db 9b 92 3f 20 03 f0 ba 82 9f c5 3f
71 54 a6 e7 8a 9d c8 3a 23 01 f8 e8 8c 94 c5 38
27 52 a5 eb 8e 9f 94 68 27 4a
```

---

## Recover the flag (XOR with repeating 8‑byte key)
```python
KEY   = bytes.fromhex("13 37 c0 de ba ad f0 0d".replace(" ", ""))
TABLE = bytes.fromhex(
    "70 4e a2 bb c8 ce 9f 63 68 0e f4 ba df c9 c5 6b "
    "75 0e f1 e9 8e 9f c2 6f 75 51 f5 e7 82 cf c1 3a "
    "21 03 a1 ba db 9b 92 3f 20 03 f0 ba 82 9f c5 3f "
    "71 54 a6 e7 8a 9d c8 3a 23 01 f8 e8 8c 94 c5 38 "
    "27 52 a5 eb 8e 9f 94 68 27 4a"
)
flag = bytes([b ^ KEY[i % 8] for i, b in enumerate(TABLE)]).decode("ascii")
print(flag)
```
**Output**
```
cybercon{94ded5ff917422bff598b1724ada6b2340d8252bcf90087068669554ee542de4}
```
#
