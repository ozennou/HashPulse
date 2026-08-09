# `md5_transform` — implementation notes

What changed, why it is written the way it is, and how it was verified.
Written as defense prep: every design choice here is one a peer can ask about.

**Scope of the change:** `md5_transform` only. `md5_final` still does not exist, so
`./ft_ssl md5 file` still prints nothing. See [STATUS.md](STATUS.md) for the rest.

---

## 1. Files touched

| File | Change |
|---|---|
| `src/md5.c:23-87` | Added the constant tables, the round functions, and the dispatch tables |
| `src/md5.c:94-121` | Replaced the empty `md5_transform` stub with the real compression function |
| `src/ft_ssl.h:10` | Added the `ROTL32` macro |

`ROTL32` went in the header rather than `md5.c` because SHA-256 rotates too — it will
reuse this.

---

## 2. What the function actually does

`md5_transform` is the **compression function**: it takes the 128-bit running state and
one 512-bit message block, and produces a new 128-bit state. That is the entire
cryptographic core of MD5. Everything else — `update`'s buffering, `final`'s padding — is
bookkeeping that exists to feed this function exactly 64 bytes at a time.

It runs in three stages.

### Stage 1 — decode the block into 16 words (`md5.c:101-106`)

```c
m[i] = (unsigned int)block[i * 4]
    | ((unsigned int)block[i * 4 + 1] << 8)
    | ((unsigned int)block[i * 4 + 2] << 16)
    | ((unsigned int)block[i * 4 + 3] << 24);
```

64 bytes become 16 × 32-bit words, **little-endian**: the first byte is the *least*
significant. MD5 is little-endian throughout — the digest is serialized the same way, and
the length field in the padding is too.

This is the single biggest difference from SHA-256, which is big-endian everywhere. Doing
it byte-by-byte like this (rather than casting the pointer to `unsigned int *`) is
deliberate: a cast would inherit the *host's* endianness and break on a big-endian
machine, and it would be an unaligned read.

### Stage 2 — 64 rounds (`md5.c:109-116`)

```c
for (i = 0; i < 64; i++) {
    r = i / 16;
    tmp = v[0] + g_ops[r](v[1], v[2], v[3]) + m[g_idx[r](i)] + g_k[i];
    v[0] = v[3];
    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[1] + ROTL32(tmp, g_s[i]);
}
```

The rounds work on `v[0..3]` — a *copy* of the state, conventionally named A, B, C, D.
Each round mixes in one message word and one constant, then rotates the four registers.

### Stage 3 — fold back (`md5.c:118-119`)

```c
for (i = 0; i < 4; i++)
    ctx->state[i] += v[i];
```

The new state is the old state **plus** the round output — not a replacement. This
feed-forward is what makes the function one-way; without it the rounds would be
invertible, since every individual step is reversible.

---

## 3. The four rounds

MD5's 64 rounds split into four groups of 16. Each group uses a different bitwise mixing
function and a different pattern for choosing which message word to consume.

| Rounds | `r` | Function | Definition | Word index |
|---|---|---|---|---|
| 0–15 | 0 | F | `(b & c) \| (~b & d)` | `i` |
| 16–31 | 1 | G | `(b & d) \| (c & ~d)` | `(5i + 1) % 16` |
| 32–47 | 2 | H | `b ^ c ^ d` | `(3i + 5) % 16` |
| 48–63 | 3 | I | `c ^ (b \| ~d)` | `7i % 16` |

F is a multiplexer — it selects bit-by-bit between `c` and `d` according to `b`. H is pure
parity. The point of varying them is that no single algebraic structure holds across all
64 rounds, which is what frustrates analysis.

The index schedules matter as much as the functions. Round 1 reads the block in order;
the other three read it in strided permutations. All three multipliers (5, 3, 7) are
coprime to 16, which guarantees each schedule is a **permutation** — every message word
gets consumed exactly once per group, none skipped, none doubled. That is the property
that spreads each input word across the whole state.

### The two constant tables

**`g_k[64]` (`md5.c:23-41`)** — `K[i] = floor(2³² × |sin(i + 1)|)`, with `i` in radians.
These are "nothing-up-my-sleeve" numbers: derived from a fixed mathematical constant so
the designer provably could not have chosen them to hide a backdoor. They are
**precomputed** in the source rather than calculated, which avoids linking `-lm`
(`sin` is not on the subject's allowed-function list).

**`g_s[64]` (`md5.c:43-48`)** — the per-round left-rotation amounts, four repeating
patterns of four (`7,12,17,22` / `5,9,14,20` / `4,11,16,23` / `6,10,15,21`). Rotation is
what provides *diffusion*: without it, bit `n` of the output would depend only on bits
`≤ n` of the input, and a change high in a word could never propagate downward.

---

## 4. Two things a reviewer will ask about

### 4.1 Why function-pointer tables instead of `if/else`?

```c
static unsigned int (*const g_ops[4])(unsigned int, unsigned int, unsigned int)
    = {md5_f, md5_g, md5_h, md5_i};
static unsigned int (*const g_idx[4])(int)
    = {md5_idx_f, md5_idx_g, md5_idx_h, md5_idx_i};
```

The subject is explicit (p.7): *"we won't accept a forest of if/else (think of the
function pointer array for the dispatching part)."* With these tables, `r = i / 16`
selects the round and the loop body stays a single expression — no branching on `i` at
all.

**The tradeoff, stated honestly:** two indirect calls per round is slower than the
hand-unrolled macro form that reference implementations use. At 64 rounds × 16384 blocks
per megabyte that is measurable in principle, but irrelevant at this project's scale, and
it buys a loop body you can read in one line. If profiling ever demanded it, the tables
could be replaced with a `switch` without touching anything else.

`const` on the arrays matters: it puts them in read-only memory and lets the compiler
devirtualize the calls when it can prove the index.

### 4.2 The assignment order in the round body

This is the subtlest part of the function and the most likely thing to be quizzed on:

```c
v[0] = v[3];
v[3] = v[2];
v[2] = v[1];
v[1] = v[1] + ROTL32(tmp, g_s[i]);   /* still the OLD v[1] */
```

Two things make this correct:

1. **`tmp` is computed first**, on line `md5.c:111`, from all four *original* register
   values. Nothing is clobbered before it is read.
2. **The last line still sees the old `v[1]`.** `v[2] = v[1]` copies `v[1]` into `v[2]`;
   it does not modify `v[1]`. So when line 115 reads `v[1]`, it is still B.

Reorder these four lines and the hash is silently wrong — it will still produce
plausible-looking output, just not MD5. This is exactly the kind of bug the test vectors
in §5 exist to catch.

### 4.3 Why `unsigned` is required, not stylistic

MD5 is defined over arithmetic **mod 2³²**, and every `+` in the round body is expected to
wrap on overflow. In C, **signed** overflow is undefined behavior — the compiler may
assume it never happens and optimize accordingly. **Unsigned** overflow is defined to wrap.
So `unsigned int` here is a correctness requirement. Using `int` would be a genuine bug
that `-fsanitize=undefined` would flag.

(`ROTL32` is safe because every value in `g_s` is between 4 and 23. A rotation of 0 would
make the `>> (32 - n)` shift by 32, which *is* undefined.)

---

## 5. Verification

`md5_transform` was tested **in isolation**, before `md5_final` exists. The test harness
calls the real function from `src/md5.c` and performs padding itself, so no production
code was written speculatively.

### Known-answer tests — 10/10 pass

The complete RFC 1321 suite plus project-specific cases:

```
""                                        d41d8cd98f00b204e9800998ecf8427e
"a"                                       0cc175b9c0f1b6a831c399e269772661
"abc"                                     900150983cd24fb0d6963f7d28e17f72
"message digest"                          f96b697d7cb7938d525a2f31aaf161d0
"foo"                                     acbd18db4cc2f85cedef654fccc4a4d8
"abcdefghijklmnopqrstuvwxyz"              c3fcd3d76192e4007dfb496cca67e13b
"A-Za-z0-9" (62 bytes)                    d174ab98d277d9f5a5611c2c9f419d9f
"1234567890" × 8 (80 bytes)               57edf4a22be3c955ac49da2e2107b67a
"And above all,\n"        (subject p.9)   53d53ea94217b259c11a5a2d104ec58a
"42 is nice\n"            (subject p.9)   35f1d6de0302e2086a4e472266efb3a9
```

The 62- and 80-byte cases matter most: both cross the 56-byte threshold and force padding
into a **second** block, exercising multi-block chaining.

### Randomized boundary testing — 19/19 match `md5sum`

Random data at lengths `0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128,
129, 200, 1000, 4096`, each compared against the system `md5sum`.

Those lengths are chosen, not arbitrary. **55 → 56** is the point where padding stops
fitting in the current block; **63 → 64 → 65** is the block boundary itself; **119 → 120**
is the same threshold one block up. A transform that is subtly wrong about block
boundaries passes short tests and fails exactly here.

---

## 6. What this does *not* fix

The compression function is correct, but the program still produces no output:

- **`md5_final` does not exist** — no padding, no length append, no digest extraction.
  When you write it, remember the contract from `md5_update`: `bitlen` counts only
  *complete* blocks, so `final` must start with `bitlen += datalen * 8`.
- **`testfunc` is still wired into `md5_update`** (`md5.c:131, 139`). It dumps 64 raw
  bytes to stdout per block and will destroy your output the moment hashing works.
  Delete it before testing end-to-end.
- **Three `-Wall -Wextra` sign-compare warnings remain** in `md5_update`
  (`md5.c:126, 138, 144`) — `len` is `int`, compared against `size_t`. Still the blocker
  for turning `-Werror` back on in `Makefile:5`.
