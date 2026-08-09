# How MD5 Works — annotated walkthrough of this implementation

Defense preparation for `ft_ssl`. Every section pairs the specification with the code in
[`src/md5.c`](src/md5.c) that implements it. Read top to bottom and you should be able to
answer any question about the algorithm and about why this code is shaped the way it is.

Companion docs: [STATUS.md](STATUS.md) (what is done / still to do),
[MD5_TRANSFORM.md](MD5_TRANSFORM.md) (deeper notes on the compression function alone).

---

## Contents

1. [What a hash function has to do](#1-what-a-hash-function-has-to-do)
2. [The Merkle–Damgård construction](#2-the-merkledamgård-construction)
3. [The context struct](#3-the-context-struct)
4. [Stage 1 — initialization](#4-stage-1--initialization)
5. [Stage 2 — absorbing the message](#5-stage-2--absorbing-the-message)
6. [Stage 3 — padding](#6-stage-3--padding)
7. [Stage 4 — the compression function](#7-stage-4--the-compression-function)
8. [Stage 5 — producing the digest](#8-stage-5--producing-the-digest)
9. [Worked example: MD5("abc")](#9-worked-example-md5abc)
10. [Defense questions](#10-defense-questions)
11. [Why MD5 is broken](#11-why-md5-is-broken)

---

## 1. What a hash function has to do

MD5 maps a message of **any length** to a fixed **128-bit** digest. The subject lists the
five properties it is supposed to have; three matter for understanding the design:

- **Deterministic** — same input, same output, always.
- **Avalanche** — flipping one input bit should change roughly half the output bits.
- **One-way** — given a digest, finding *any* message that produces it should be infeasible.

Everything in the algorithm exists to serve avalanche and one-wayness. When you see an odd
choice below (why rotate? why add the state back at the end?), the answer is almost always
one of those two.

---

## 2. The Merkle–Damgård construction

MD5 can only handle exactly **64 bytes** at a time. The trick that lets it handle arbitrary
lengths is a chaining loop:

```
                block 0        block 1        block 2
                   |              |              |
                   v              v              v
  IV ──────► [ compress ] ──► [ compress ] ──► [ compress ] ──► digest
           128 bits      128 bits       128 bits        128 bits
```

A fixed 128-bit **initialization vector** enters the first compression. Each block's output
becomes the next block's input. After the last block, the accumulated 128-bit value *is*
the digest. The message is padded beforehand so its length is always an exact multiple of
64 bytes.

That maps onto four functions, and this is the standard three-call API for every streaming
hash:

| Function | Role | Location |
|---|---|---|
| `md5_init` | load the IV | `md5.c:3` |
| `md5_update` | absorb bytes, call `md5_transform` per complete block | `md5.c:114` |
| `md5_final` | pad, append length, extract digest | `md5.c:152` |
| `md5_transform` | **the compression function** — one block, in place | `md5.c:87` |

`md5_digest` (`md5.c:174`) is the driver that reads a file descriptor and calls the three
in order:

```c
md5_init(&ctx);
while ((bytes_read = read(fd, buffer, MAX_SIZE)) > 0) {
    md5_update(&ctx, buffer, bytes_read);
}
...
md5_final(&ctx, digest);
```

Because it streams, a 10 GB file uses the same fixed memory as a 3-byte one.

---

## 3. The context struct

Everything that must survive between `update` calls lives here (`ft_ssl.h:24`):

```c
typedef struct s_hash_ctx {
    unsigned char   data[64];    /* partial block not yet processed  */
    unsigned int    datalen;     /* how many bytes are valid in data */
    unsigned int    state[8];    /* the chaining value (MD5 uses 4)  */
    unsigned long   bitlen;      /* message length in BITS           */
} t_hash_ctx;
```

- **`data[64]`** — one block's worth of holding space. Input arrives in 1 MB chunks that
  almost never end on a 64-byte boundary, so the tail is parked here.
- **`state[8]`** — sized 8 so **SHA-256 can share this struct**; MD5 uses `state[0..3]`,
  SHA-256 uses all eight. One context type means one function-pointer signature in the
  command dispatch table.
- **`bitlen`** — in *bits*, not bytes, because the padding appends a bit count.

**`unsigned` is a correctness requirement, not a style choice.** MD5 is defined over
arithmetic mod 2³², and every `+` in the round function is expected to wrap. In C, *signed*
overflow is undefined behavior; *unsigned* overflow is defined to wrap. Using `int` would be
a real bug.

---

## 4. Stage 1 — initialization

```c
void md5_init(t_hash_ctx *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}
```

Those four words are the IV, conventionally called **A, B, C, D**. They are not random —
read the bytes of each in reverse:

```
0x67452301  ->  01 23 45 67
0xefcdab89  ->  89 ab cd ef
0x98badcfe  ->  fe dc ba 98
0x10325476  ->  76 54 32 10
```

Counting up `0123456789abcdef`, then the same counting down. A deliberately arbitrary
starting point with an obvious origin — the same "nothing up my sleeve" reasoning as the
`K` table in §7.4. **Any** fixed value would work cryptographically; what matters is that
it is fixed and publicly justified.

---

## 5. Stage 2 — absorbing the message

`md5_update` (`md5.c:114`) reconciles arbitrary chunk sizes with fixed 64-byte blocks. It
runs in three phases.

**Phase 1 — finish the leftover block.**

```c
if (ctx->datalen) {
    size_t to_copy = 64 - ctx->datalen;
    if (to_copy > len) to_copy = len;      /* chunk may be too small */
    ft_memcpy(ctx->data + ctx->datalen, data, to_copy);
    ctx->datalen += (unsigned int)to_copy;
    i += to_copy;
    if (ctx->datalen == 64) {
        md5_transform(ctx, ctx->data);
        ctx->bitlen += 512;
        ctx->datalen = 0;
    }
}
```

That clamp is the important line: if the new chunk cannot complete the block, we copy what
exists and the other two phases become no-ops.

**Phase 2 — process whole blocks in place.**

```c
for (; i + 64 <= len; i += 64) {
    md5_transform(ctx, data + i);
    ctx->bitlen += 512;
}
```

Note `data + i` — transform reads the **caller's buffer directly**, no copy. For a 1 MB
chunk that is 16384 compressions with zero memcpy.

**Phase 3 — stash the tail.**

```c
if (i < len) {
    size_t rem = len - i;
    memcpy(ctx->data, data + i, rem);
    ctx->datalen = (unsigned int)rem;
}
```

*Why plain `=` and not `+=`?* Because whenever Phase 3 runs, `datalen` is provably 0:
either Phase 1 was skipped (it was already 0), or Phase 1 flushed (reset to 0), or Phase 1
clamped to `len` — in which case `i == len` and Phase 3 cannot run.

### Trace — 150 bytes arriving as 70 then 80

| call | Phase 1 | Phase 2 | Phase 3 | state after |
|---|---|---|---|---|
| `update(d1, 70)` | skipped | 1 block, `i`→64 | 6 bytes stashed | `bitlen=512, datalen=6` |
| `update(d2, 80)` | +58 → full → flush, `i`=58 | `58+64 > 80`, none | 22 bytes stashed | `bitlen=1024, datalen=22` |

128 bytes compressed + 22 buffered = 150. ✓

> **The contract to remember:** `bitlen` only counts **completed** blocks. The bytes still
> in `data[]` are unaccounted for until `md5_final` adds them. Forget that and every
> message whose length is not a multiple of 64 hashes wrong.

---

## 6. Stage 3 — padding

The message must reach an exact multiple of 64 bytes, and the original length must be
embedded. The scheme is: **append one `1` bit, then `0` bits, then the 64-bit length.**

```c
void md5_final(t_hash_ctx *ctx, unsigned char *digest) {
	unsigned int	i;

	ctx->bitlen += (unsigned long)ctx->datalen * 8;   /* the contract from §5 */
	i = ctx->datalen;
	ctx->data[i++] = 0x80;                            /* 1000 0000 = the "1" bit */
	if (i > 56) {                                     /* no room for the length */
		while (i < 64)
			ctx->data[i++] = 0x00;
		md5_transform(ctx, ctx->data);                /* flush, use a 2nd block */
		i = 0;
	}
	while (i < 56)
		ctx->data[i++] = 0x00;
	for (i = 0; i < 8; i++)                           /* 64-bit length, little-endian */
		ctx->data[56 + i] = (unsigned char)(ctx->bitlen >> (8 * i));
	md5_transform(ctx, ctx->data);
	...
```

**Why `0x80`?** The spec appends a single `1` bit. Since we work in bytes, a `1` followed
by seven `0`s is `1000 0000` = `0x80`.

**Why append the length at all?** Without it, `"a"` and `"a\0"` and `"a\0\0"` would pad to
the same block and collide trivially. Encoding the length makes the padding injective —
this is *Merkle–Damgård strengthening*.

**Why the `i > 56` branch?** The length needs bytes 56–63. If `0x80` lands at index 56 or
beyond, there is no room, so the block is zero-filled and flushed, and the length goes into
a second block that is otherwise all zeros.

### The four cases

| `datalen` | after `0x80`, `i` = | `i > 56`? | blocks emitted |
|---|---|---|---|
| 0 (empty message) | 1 | no | 1 |
| 55 | 56 | no | 1 — exactly fits, zero-fill loop does nothing |
| 56 | 57 | **yes** | 2 |
| 63 | 64 | **yes** | 2 — zero-fill loop does nothing, flush immediately |

The 55→56 transition is the classic bug boundary. This implementation is verified at
55, 56, 57, 63, 64, 65, 119, 120 against `md5sum`.

---

## 7. Stage 4 — the compression function

`md5_transform` (`md5.c:87`) is the cryptographic core: 128-bit state + 512-bit block →
new 128-bit state.

### 7.1 Decode the block into 16 words

```c
for (i = 0; i < 16; i++) {
    m[i] = (unsigned int)block[i * 4]
        | ((unsigned int)block[i * 4 + 1] << 8)
        | ((unsigned int)block[i * 4 + 2] << 16)
        | ((unsigned int)block[i * 4 + 3] << 24);
}
```

Think of a 32-bit word as four byte-slots, where the shift *is* the slot number:

```
        ┌──────────┬──────────┬──────────┬──────────┐
 m[i] = │  slot 3  │  slot 2  │  slot 1  │  slot 0  │
        └──────────┴──────────┴──────────┴──────────┘
  bits:  31 ..  24  23 ..  16  15 ..   8   7 ..   0
            <<24       <<16        <<8      no shift
```

For bytes `'a','b','c','d'` = `61 62 63 64`:

```
  block[0]  0x61  no shift  0x00000061
  block[1]  0x62  << 8      0x00006200
  block[2]  0x63  << 16     0x00630000
  block[3]  0x64  << 24     0x64000000
                       OR = 0x64636261
```

Each shifted byte is zero everywhere outside its slot, so `|` just snaps four pieces into
four holes. **The first byte in memory lands in the lowest bits** — that reversal is
little-endian, and it is correct even though it looks backwards.

*Why not cast the pointer?* `*(unsigned int *)block` gives the same answer on x86 only
because x86 happens to be little-endian. That delegates the byte order to the **CPU**; on a
big-endian machine every hash would be wrong, and it can fault on architectures requiring
aligned reads. The explicit shifts give the same result everywhere. **This is the single
line that differs most from SHA-256**, which is big-endian and simply reverses the shifts.

### 7.2 The 64 rounds

```c
for (i = 0; i < 4; i++)
    v[i] = ctx->state[i];               /* work on a COPY */
for (i = 0; i < 64; i++) {
    r = i / 16;
    tmp = v[0] + g_ops[r](v[1], v[2], v[3]) + m[g_idx[r](i)] + g_k[i];
    v[0] = v[3];
    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[1] + ROTL32(tmp, g_s[i]);
}
```

In spec notation, with `v` = A, B, C, D:

```
tmp = A + F(B,C,D) + M[g] + K[i]
A = D;  D = C;  C = B;  B = B + (tmp <<< s[i])
```

Every round mixes in **one message word** and **one constant**, then shifts the four
registers around by one position. Over 64 rounds each message word is consumed four times,
once per group.

**The assignment order is load-bearing.** `tmp` is computed first, from all four *original*
values. Then note that `v[2] = v[1]` copies B into C without modifying B — so the final
line still reads the **old** B. Reorder these four lines and you get a hash that looks
plausible but is not MD5.

### 7.3 The four round functions

The 64 rounds split into four groups of 16, each with its own mixing function and its own
rule for picking the message word.

| Rounds | `r` | Function | Code (`md5.c:43-57`) | Word index |
|---|---|---|---|---|
| 0–15 | 0 | F | `(b & c) \| (~b & d)` | `i` |
| 16–31 | 1 | G | `(b & d) \| (c & ~d)` | `(5i + 1) % 16` |
| 32–47 | 2 | H | `b ^ c ^ d` | `(3i + 5) % 16` |
| 48–63 | 3 | I | `c ^ (b \| ~d)` | `7i % 16` |

- **F is a multiplexer**: bit by bit, it selects `c` where `b` is 1 and `d` where `b` is 0.
- **G** is the same idea with the roles rotated.
- **H is pure parity** (XOR) — maximally linear, cheap, spreads differences fast.
- **I** is the odd one out, chosen specifically because it is *not* similar to the others.

The point of varying them is that **no single algebraic structure holds across all 64
rounds**, which is what frustrates cryptanalysis.

**The index schedules matter as much as the functions.** Round group 1 reads the block in
order; the others read strided permutations. The multipliers 5, 3 and 7 are all **coprime
to 16**, which guarantees each schedule is a *permutation* — every message word is used
exactly once per group, none skipped, none doubled. That is what spreads each input word
across the entire state.

### 7.4 The K constants — "nothing up my sleeve"

```c
/* K[i] = floor(2^32 * abs(sin(i + 1))), i in radians. */
static const unsigned int	g_k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	...
```

Each round adds a different constant so that identical inputs in different positions do not
produce identical intermediate values. The *values* are derived from `|sin(i+1)|` — a
**nothing-up-my-sleeve number**. Rivest could not have hand-picked them to hide a backdoor,
because anyone can recompute them. Verified:

```
K[0..3] recomputed from sin:  d76aa478 e8c7b756 242070db c1bdceee
K[0..3] in g_k:               d76aa478 e8c7b756 242070db c1bdceee   ✓
```

They are **hardcoded rather than computed** because `sin` would require linking `-lm`, and
the subject's allowed-function list does not include it.

### 7.5 The rotation amounts

```c
static const unsigned int	g_s[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, ...   /* group 1 */
	5,  9, 14, 20, ...                  /* group 2 */
	4, 11, 16, 23, ...                  /* group 3 */
	6, 10, 15, 21, ...                  /* group 4 */
};
```

`ROTL32` (`ft_ssl.h:10`) is a **circular** left shift — bits pushed off the top re-enter at
the bottom:

```c
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
```

**Why rotate at all?** Addition and the bitwise functions only propagate information from
low bits toward high bits (via carries). Without rotation, bit 0 of the output could never
depend on bit 31 of the input. Rotation is what provides **diffusion** in both directions —
it is the mechanism behind the avalanche property.

The amounts vary per round so no bit position is ever privileged. All values are between 4
and 23; note that a rotation of 0 would make `>> (32 - 0)` a shift by 32, which is
undefined behavior in C — the table never produces one.

### 7.6 Feed-forward

```c
for (i = 0; i < 4; i++)
    ctx->state[i] += v[i];
```

The new state is the old state **plus** the round output, not a replacement. This is the
single most important line for one-wayness: every individual round step is *invertible*
(you can run it backwards), so without this addition the whole compression function would
be reversible and MD5 would not be a one-way function. Adding the original state in
destroys that invertibility — this is the **Davies–Meyer** construction.

---

## 8. Stage 5 — producing the digest

```c
for (i = 0; i < 16; i++)
    digest[i] = (unsigned char)(ctx->state[i / 4] >> (8 * (i % 4)));
```

`i / 4` picks the state word (0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3) and `i % 4` picks the byte
within it (0,1,2,3 repeating). The `>> (8 * (i % 4))` extracts **low byte first** — the
same little-endian convention as the decode in §7.1, run in reverse.

`print_hex` (`src/tools.c`) then renders the 16 bytes as 32 lowercase hex characters using
a single `write(1, …)` — no `printf`, which is not on the allowed-function list.

---

## 9. Worked example: MD5("abc")

Input is 3 bytes: `61 62 63`. Length = 24 bits.

**After padding** (one block; `0x80` at index 3, length `0x18` = 24 at byte 56):

```
  [00] 61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00
  [16] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  [32] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  [48] 00 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00
                                ^^ the bit length, little-endian
```

**After decoding**, note `m[0] = 0x80636261` — bytes `61 62 63 80` reversed, exactly as
§7.1 predicts. `m[14] = 0x00000018` holds the length.

**Register evolution** (A, B, C, D):

```
init          A=67452301 B=efcdab89 C=98badcfe D=10325476
round  0 g= 0 A=10325476 B=d6d117b4 C=efcdab89 D=98badcfe
round  1 g= 1 A=98badcfe B=344a8432 C=d6d117b4 D=efcdab89
round  2 g= 2 A=efcdab89 B=2f6fbd72 C=344a8432 D=d6d117b4
round 15 g=15 A=dda9b9a6 B=72aff2e0 C=e396856b D=a1051895   <- end of group 1
round 31 g=12 A=790a77fb B=726342d3 C=a62884aa D=9f47e4f8   <- end of group 2
round 47 g= 2 A=7f2e507b B=7beb9700 C=8fae6399 D=99d9679d   <- end of group 3
round 63 g= 9 A=310ade8f B=c08226b3 C=e484b9d8 D=624d8cb2   <- end of group 4
```

Watch round 0: the old B (`efcdab89`) slides into C, the old C into D, the old D
(`10325476`) into A — and the new B is freshly computed. That is the register rotation.

Notice also how `g` runs `0,1,2…` in group 1 but jumps to 12 and 2 and 9 later — the
strided schedules from §7.3.

**Feed-forward and output:**

```
state + v  =  98500190 b04fd23c 7d3f96d6 727fe128
digest     =  90 01 50 98 | 3c d2 4f b0 | d6 96 3f 7d | 28 e1 7f 72
              900150983cd24fb0d6963f7d28e17f72
```

Each 32-bit word is emitted **low byte first**: `0x98500190` becomes `90 01 50 98`.
That matches the published MD5("abc"). ✓

---

## 10. Defense questions

**Why is `state` sized 8 when MD5 uses 4?**
So SHA-256 shares the struct. One context type means the command dispatch table can hold
one uniform function-pointer signature instead of needing `void *` casts.

**Why function-pointer tables instead of `if/else` in the round loop?**
The subject (p.7) explicitly rejects "a forest of if/else". With `g_ops` and `g_idx`,
`r = i / 16` selects the round and the body stays one expression. The honest tradeoff: two
indirect calls per round is slower than the unrolled macro form reference implementations
use — irrelevant at this scale, and it buys a readable loop.

**Why 64 rounds and not 16?**
Four passes over the message with different functions and different word orders. Fewer
passes leaves statistical relationships between input and output that cryptanalysis can
exploit.

**Where does the message length go, and why?**
Last 8 bytes of the final block, little-endian, in bits. Without it, padding would not be
injective and `"a"` / `"a\0"` would collide.

**What happens with an empty message?**
`datalen = 0`, `0x80` at index 0, zeros to byte 55, length `0` in 56–63, one compression.
Result `d41d8cd98f00b204e9800998ecf8427e`. Tested.

**Why is `unsigned` mandatory?**
MD5 arithmetic is mod 2³² and relies on overflow wrapping. Signed overflow is undefined
behavior in C; unsigned overflow is defined to wrap.

**How do you know this is correct?**
The full RFC 1321 test-vector suite passes, plus randomized comparison against `md5sum` at
25 lengths chosen to straddle every boundary in the code — the 55/56 padding threshold, the
64-byte block boundary, and the 1 MB read-buffer boundary (1048576 ± 1) that exercises
cross-chunk buffering.

---

## 11. Why MD5 is broken

Worth knowing — a peer may well ask why we are implementing a hash nobody should use.

**Collision resistance is completely gone.** Wang et al. published a practical collision
attack in 2004. Today two different messages with the same MD5 can be produced in seconds
on a laptop. In 2008 researchers used a **chosen-prefix** collision to forge a rogue CA
certificate; the 2012 Flame malware used the same technique to fake a Microsoft signature.

**Preimage resistance is weakened but not practically broken.** The best known preimage
attack is around 2¹²³·⁴ versus 2¹²⁸ for brute force — better than brute force on paper,
still far out of reach.

**Practical consequence:** MD5 is fine as a non-adversarial checksum (detecting accidental
corruption), and unusable for signatures, certificates, or password storage.

SHA-256 — the second half of this project — has no known practical collision attack and
remains the sensible default.

---

## References

- **RFC 1321** — The MD5 Message-Digest Algorithm (Rivest, 1992). The specification, and
  the source of the test vectors used here.
- **FIPS 180-4** — the SHA family, for the SHA-256 half of the project.
- `ft_ssl_md5.pdf` — the project subject.
