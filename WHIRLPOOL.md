# `src/whirlpool.c` — functions mapped to the algorithm

Whirlpool is not a purpose-built compression function like MD5 or SHA-256. It is a
**512-bit block cipher called W**, wrapped in the **Miyaguchi–Preneel** construction so
that it becomes one-way. Every function in this file is either part of W, part of that
wrapper, or part of the one-time table setup that makes W fast.

## The map

| Function | Algorithm concept |
|---|---|
| `wp_mul2` | multiplication by `x` in GF(2⁸) — the field the diffusion layer lives in |
| `wp_sbox` | the S-box, built from two 4-bit mini-boxes rather than hardcoded |
| `wp_build` | fuses SB + SC + MR into eight lookup tables; derives the round constants |
| `wp_round` | one full round of W: **SB → SC → MR → AK**, as 8 lookups and 8 XORs |
| `whirlpool_init` | the all-zero IV, and installing the compression function |
| `whirlpool_transform` | Miyaguchi–Preneel + the key schedule + 10 rounds |
| `whirlpool_final` | padding, the 256-bit length field, big-endian digest |

Two pieces live outside this file, shared with MD5 and SHA-256: **`hash_update`** does
the 64-byte block buffering, and **`hash_pad`** appends the `0x80` and the zero fill.

---

## The four round layers

The specification describes each round as four operations on an **8×8 matrix of bytes**:

| Layer | Spec name | What it does |
|---|---|---|
| **SB** | nonlinear layer | replace every byte with `S[byte]` |
| **SC** | permutation layer | shift column *j* down by *j* |
| **MR** | diffusion layer | multiply each row by the circulant matrix `cir(1,1,4,1,8,5,2,9)` |
| **AK** | key addition | XOR the round key |

In this implementation **none of these appears as its own function.** SB and MR are baked
into the lookup tables, SC is the index arithmetic in `wp_round`, and AK is a single XOR.
That is the standard optimisation, and it is why `wp_round` is eight lines.

---

## `wp_mul2` — GF(2⁸) arithmetic

```c
static unsigned char wp_mul2(unsigned char x) {
    return ((unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1d : 0x00)));
}
```

The diffusion layer multiplies bytes in the finite field GF(2⁸), where a byte is a
polynomial and multiplication is taken modulo Whirlpool's reduction polynomial
`x⁸ + x⁴ + x³ + x² + 1` = `0x11D`.

Multiplying by `x` is a left shift. If bit 7 was set the result overflows 8 bits, so the
polynomial is subtracted — and subtraction in this field is XOR, with the low byte of
`0x11D`, which is `0x1D`.

Everything else follows from this one primitive: `4·a = mul2(mul2(a))`,
`5·a = 4·a ⊕ a`, `9·a = 8·a ⊕ a`, and so on.

---

## `wp_sbox` — the S-box, generated not hardcoded

Most implementations paste in a 256-byte table. This one **derives** it from two 4-bit
mini-boxes, exactly as the specification defines it:

```c
y1 = e[(i >> 4) & 0x0f];        /* high nibble through E     */
y2 = einv[i & 0x0f];            /* low nibble through E⁻¹    */
rr = r[y1 ^ y2];                /* both nibbles through R    */
s[i] = (e[y1 ^ rr] << 4) | einv[y2 ^ rr];
```

The structure is a miniature two-round Feistel network: split the byte into nibbles, push
each through a permutation, mix them with `R`, then push them through again.

**Why generate it?** A 256-byte magic table is unverifiable by inspection. Sixteen entries
of `E` and sixteen of `R` can be checked by eye, and the construction is four lines. It is
the same "nothing up my sleeve" reasoning behind MD5's sine constants.

*Verified:* the output is a bijection over all 256 values, and its first bytes are
`18 23 c6 e8 87 b8 01 4f`, matching the published table.

---

## `wp_build` — one-time table construction

Called once, guarded by `g_ready`. It does two things.

### Fusing SB and MR into `g_c`

```c
g_c[0][i] = (v1 << 56) | (v1 << 48) | (v4 << 40) | (v1 << 32)
          | (v8 << 24) | (v5 << 16) | (v2 << 8) | v9;
```

Reading the multipliers from the most significant byte down gives **1, 1, 4, 1, 8, 5, 2, 9**
— the circulant matrix `cir(1,1,4,1,8,5,2,9)`. So `g_c[0][x]` holds *the S-box output for
`x`, already multiplied by an entire MDS column*. One lookup performs SB **and** MR for one
byte.

```c
for (j = 1; j < 8; j++)
    g_c[j][i] = (g_c[j - 1][i] >> 8) | (g_c[j - 1][i] << 56);
```

The other seven tables are the first rotated right by 8 bits each — one table per column
position. *Verified:* `g_c[j] == rotr(g_c[0], 8j)` holds for all 8 tables × 256 entries.

**Cost:** 8 × 256 × 8 bytes = **16 KB** of tables. That is the trade — 16 KB of cache
pressure in exchange for collapsing three layers into one lookup, and it is why Whirlpool
measured slowest of the three algorithms despite having only 10 rounds.

### Deriving the round constants

```c
g_rc[i] = (g_c[0][k]     & 0xff00000000000000ULL)
        ^ (g_c[1][k + 1] & 0x00ff000000000000ULL)
        ^ ... ;                       /* k = 8 * (i - 1) */
```

This looks cryptic but is just a diagonal extraction. Because `g_c[j]` is `g_c[0]` rotated
by `8j`, masking byte `j` of `g_c[j][x]` recovers the raw S-box value `S[x]`. The result is

> `rc[r]` byte `j` = `S[8(r-1) + j]`

which is precisely the specification's definition: the first row of the round-constant
matrix is eight consecutive S-box entries, the other seven rows are zero.

*Verified:* holds for all 10 rounds. `rc[1] = 1823c6e887b8014f`, which is literally
`S[0..7]`.

---

## `wp_round` — one round of W

```c
out[i] = g_c[0][(in[(i + 8) & 7] >> 56) & 0xff]
       ^ g_c[1][(in[(i + 7) & 7] >> 48) & 0xff]
       ...
       ^ g_c[7][(in[(i + 1) & 7]      ) & 0xff]
       ^ key[i];
```

All four layers, in eight lookups:

- **SB and MR** — inside `g_c`, as shown above.
- **SC** — the index `(i + 8 - j) & 7`. Term `j` takes byte `j` from input row `i - j`.
  That *is* "column `j` shifted down by `j`", expressed as reading from a rotated row.
- **AK** — the final `^ key[i]`.

The `(i + 8 - j) & 7` form is used rather than `(i - j) & 7` because bitwise AND on a
negative `int` is not something to rely on; adding 8 first keeps the index non-negative.

The eight XOR terms are the eight bytes of an input row spread across eight output rows —
the "wide trail" property that guarantees a single input byte change affects the whole
state within two rounds.

---

## `whirlpool_init` — the IV is zero

```c
ctx->transform = whirlpool_transform;
for (i = 0; i < 8; i++)
    ctx->state64[i] = 0;
```

MD5 starts from four magic constants; SHA-256 from square roots of primes. **Whirlpool
starts from all zeros** and needs no justification for its IV, because the asymmetry that
makes the function one-way comes from the Miyaguchi–Preneel wrapper rather than the
starting state.

`state64` is a separate field from `state` because Whirlpool needs 512 bits of state as
eight 64-bit words, while MD5 and SHA-256 use 32-bit words.

---

## `whirlpool_transform` — the wrapper and the key schedule

```c
k[i]  = ctx->state64[i];      /* the hash state becomes the KEY */
st[i] = m[i] ^ k[i];          /* the block, pre-whitened        */

for (r = 1; r <= 10; r++) {
    rc[0] = g_rc[r];
    wp_round(tmp, k, rc);     /* advance the key schedule       */
    ...
    wp_round(tmp, st, k);     /* encrypt, under that round key  */
    ...
}
ctx->state64[i] ^= st[i] ^ m[i];   /* Miyaguchi–Preneel         */
```

**Two chains run in lockstep.** The key chain starts at the current hash state and is
driven by the round constants; the state chain starts at `block ⊕ state` and is driven by
the key chain. Both use the same `wp_round` — the only difference is what is passed as
`key`.

**The last line is the whole security argument.** A block cipher is reversible, which a
hash must not be. Miyaguchi–Preneel fixes that three ways at once: the key is the current
state (so an attacker cannot choose it), and both the plaintext and the key are XORed back
into the ciphertext. Running W backwards gets you nowhere without already knowing the
state. MD5's `state[i] += v[i]` and SHA-256's feed-forward serve the same purpose with a
single addition.

Note `rc[1..7]` stay zero for the whole function — only row 0 of the round-constant matrix
is non-zero, so only `rc[0]` is ever assigned.

---

## `whirlpool_final` — padding and output

```c
hash_pad(ctx, WHIRLPOOL_LENFIELD);              /* 32, not 8 */
for (i = 0; i < 8; i++)
    ctx->data[63 - i] = (unsigned char)(ctx->bitlen >> (8 * i));
ctx->transform(ctx, ctx->data);
for (i = 0; i < WHIRLPOOL_SIZE; i++)
    digest[i] = (unsigned char)(ctx->state64[i / 8] >> (56 - 8 * (i % 8)));
```

Padding is identical to MD5 and SHA-256 — one `1` bit, then zeros — which is why
`hash_pad` is shared. The **only** difference is the width of the length field:
Whirlpool reserves **256 bits** where the others use 64. That is the `WHIRLPOOL_LENFIELD`
argument, and it moves the point where padding spills into a second block from byte 56
down to **byte 32**.

Our counter is 64-bit, so bytes 32–55 are always zero and only the low 8 bytes are
written. This caps messages at 2⁶⁴ bits (2 exabytes) rather than the spec's 2²⁵⁶.

The digest is serialised **big-endian** — `>> (56 - 8*(i%8))` takes the high byte first,
the opposite of MD5's `>> (8*(i%4))`.

---

## Verification

- All eight **ISO/IEC 10118-3** test vectors pass, including the 32-byte case that sits
  exactly on the padding boundary and the 80-byte multi-block case.
- No reference tool exists on this machine (OpenSSL 3.x moved Whirlpool to the legacy
  provider), so the two internal code paths — chunked file reads through `digest_fd`, and
  one-shot in-memory hashing through `digest_buf` — were cross-checked at 15 lengths from
  0 bytes to 5 GB. They agree everywhere.
- The three structural properties documented above (the MDS packing, the table rotation,
  the round-constant diagonal) were each verified independently against the S-box.
