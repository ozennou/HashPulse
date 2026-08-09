# ft_ssl — Project Status

**Where you are:** roughly **1/3 of the mandatory part**. The CLI skeleton (arg parsing,
flag bitmask, input collection, stdin capture, file reading loop) is in place and compiles.
**Zero hashing actually happens** — `md5_transform()` is an empty stub, there is no
finalization/padding, no digest printing, and no SHA-256 at all.

In short: the plumbing exists, the crypto and the output layer do not.

---

## 1. What already works

| Area | State | Where |
|---|---|---|
| Makefile with `all` / `clean` / `fclean` / `re` | Works, builds cleanly | `Makefile` |
| Usage message when `argc < 2` | Matches subject | `src/main.c:167` |
| Command validation (`md5` / `sha256`) + error + command/flag listing | Matches subject | `src/main.c:10` |
| Flag parsing `-p -q -r -s` into a bitmask | Works | `src/main.c:19-31` |
| Rejecting unknown flags | Works | `src/main.c:20-26` |
| Collecting file/string operands into `options->inputs` | Works | `src/main.c:32-35` |
| "Read stdin only when no operands" rule | Correct | `src/main.c:43-45` |
| stdin capture to a temp file, rewound for re-reading | Works | `src/main.c:46-63` |
| Opening files, error on unopenable file | Works | `src/main.c:151-161` |
| Chunked read loop feeding the hash context | Works | `src/main.c:129-131` |
| `md5_init()` with the four correct IV constants | Correct | `src/main.c:67-74` |
| `md5_update()` block-accumulation logic | Logic is sound | `src/main.c:88-116` |
| libft helpers: `ft_strlen`, `ft_strjoin`, `ft_memcpy`, `ft_strcmp`, `ft_error` | Work | `src/libft.c`, `src/tools.c` |

The buffering design in `md5_update()` is the right one: keep a 64-byte residual buffer,
fill it from the incoming chunk, flush whole blocks, stash the remainder. That logic is
worth keeping — it just has nothing to call yet.

---

## 2. What is missing (mandatory)

### 2.1 The MD5 algorithm itself — **the biggest gap**

- `md5_transform()` at `src/main.c:83` is `(void)ctx; (void)block;`. The entire 64-round
  compression function needs to be written: the `K[64]` sine table, the per-round shift
  amounts `S[64]`, the four round functions (F/G/H/I), the message-word index schedule,
  and the little-endian decode of the 64-byte block into 16 words.
- **`md5_final()` does not exist.** You need padding (append `0x80`, then `0x00` up to
  offset 56 mod 64, then the 64-bit **little-endian** bit length) and the little-endian
  serialization of `state[0..3]` into 16 output bytes.
- `md5_digest()` at `src/main.c:118` never calls a finalizer and never returns a digest —
  it reads the file, throws the bytes away, and returns 0.
- `src/md5.c` is empty (one `#include`). All MD5 code currently lives in `main.c` and
  should move here.

### 2.2 SHA-256 — **not started**

No `sha256.c`, no `sha256_init/update/transform/final`. Note the differences from MD5:

- 8 state words instead of 4, 64 round constants, big-endian block decode, big-endian
  length append, big-endian digest output, 32-byte output.
- The `update` buffering logic is *identical* to MD5's — factor it out rather than
  duplicating it.

### 2.3 Output layer — **nothing prints a hash today**

Not a single digest is ever formatted. All four output shapes are needed, and the exact
spacing from the subject matters (note: **no space** before `=` for stdin forms, **a
space** before `=` for the named forms):

| Case | Default | `-r` | `-q` |
|---|---|---|---|
| stdin, no `-p` | `(stdin)= <hash>` | same | `<hash>` |
| stdin, `-p` | `("<content>")= <hash>` | `("<content>")= <hash>` | `<content>`↵`<hash>` |
| file | `MD5 (file) = <hash>` | `<hash> file` | `<hash>` |
| `-s str` | `MD5 ("str") = <hash>` | `<hash> "str"` | `<hash>` |

For `sha256` the prefix is `SHA256` instead of `MD5`; everything else is identical.
You still need the hex-encoding helper (lowercase, zero-padded) — it does not exist yet.

### 2.4 `-s` is completely unimplemented

Right now `-s` only sets a bit; the string after it is swallowed as a *filename*:

```
$ ./ft_ssl md5 -s "hello"
ft_ssl: Error: Unable to open file 'hello'.
```

The subject's argument model (visible in the `-r -p -s "foo" file -s "bar"` example on
p.9) is **positional**: flags are parsed only until the first non-flag operand. After
that, *everything* — including things starting with `-` — is a filename. That is why in
the example the second `-s` and `bar` both produce "No such file or directory".

So `inputs` cannot stay a flat `char **`. It needs to become an ordered list of
`{type: STRING|FILE, value}` so that `-s` strings and files are hashed in argv order.

### 2.5 Dispatch — subject explicitly forbids the current shape

> *"we won't accept a forest of if/else (think of the function pointer array for the
> dispatching part)"*

`process()` at `src/main.c:146` is `if (options->hash == 1)`. Replace it with a command
table:

```c
typedef struct s_command {
    char  *name;
    char  *label;          /* "MD5" / "SHA256" */
    int    digest_size;    /* 16 / 32 */
    void (*init)(t_hash_ctx *);
    void (*update)(t_hash_ctx *, const unsigned char *, size_t);
    void (*final)(t_hash_ctx *, unsigned char *);
} t_command;
```

Then command lookup is a loop over the table, and adding `sha256` (or whirlpool for the
bonus) is one new row. This also directly serves the subject's "you will build onto this
executable in later projects" warning.

### 2.6 Forbidden / debug code to remove

Allowed functions are **only** `open`, `close`, `read`, `write`, `malloc`, `free`
(plus justifiable extras like `exit`).

- `printf` is used in 12 places (`src/main.c:78,80,190-200`, `src/tools.c:23-40`). All
  output must go through `write`.
- `memcpy` at `src/main.c:113` — you already have `ft_memcpy`, use it consistently.
- `testfunc()` (`src/main.c:76`) and `print_binary()` (`src/tools.c:21`) are debug
  scaffolding — delete both.
- The debug block at `src/main.c:189-201` that prints the parsed options must go.
- `mkstemp` / `unlink` / `lseek` for stdin capture are defensible but a peer *will*
  question them. Buffering stdin into a malloc'd growing buffer avoids the argument
  entirely and removes the `/tmp` dependency and the fd leak risk. Recommended.

### 2.7 Smaller bugs to fix along the way

- `md5_update()` takes `int len` but compares it against `size_t to_copy`
  (`src/main.c:93`, `105`, `111`) — signed/unsigned comparison. Make `len` a `size_t`.
- `ctx->bitlen` is `unsigned long`; use `unsigned long long` (or `uint64_t`) to be
  explicit about the 64-bit length field.
- `md5_digest()` calls `exit(1)` on malloc failure (`src/main.c:126`) while every other
  error path returns a code — pick one convention.
- Reading a **directory** as an operand: `open` succeeds, `read` fails with EISDIR. Make
  sure that prints a sensible error instead of looping or crashing. The subject forbids
  unexpected exits.
- `Makefile` has `-fsanitize=address` on and `-Wall -Wextra -Werror` commented out
  (`Makefile:5`). Flip that before defense.
- `.PHONY` lists only `clean` (`Makefile:25`); add `all`, `fclean`, `re`.
- On an invalid command, `verify_args` frees `inputs` and main then prints the command
  list — fine, but a malloc failure takes the same path and prints a misleading
  "Commands:" listing.

---

## 3. Suggested order of work

1. **Restructure input handling** — ordered `{type, value}` operand list, real `-s`
   support, positional flag parsing. Do this first; the output layer depends on its shape.
2. **Finish MD5** — `md5_transform()` + `md5_final()` in `src/md5.c`. Test against
   `md5sum` immediately, before touching output formatting.
3. **Build the output layer** — hex encoder + the four format cases × `-q`/`-r`, driven by
   the command's label. Now `md5` is fully done; verify every example on p.9 of the subject.
4. **Introduce the dispatch table** — refactor `process()` onto function pointers. Doing
   it *now*, with one working algorithm, makes step 5 nearly free.
5. **Add SHA-256** — `src/sha256.c`, register one row in the table. Shared `update`
   buffering, big-endian everywhere. Verify against `sha256sum`.
6. **Cleanup pass** — strip `printf`/debug code, replace `memcpy`, re-enable
   `-Wall -Wextra -Werror`, drop the sanitizer, fix the small bugs in §2.7.
7. **Edge-case hardening** — empty input, exactly 56/64/119/120-byte inputs (padding
   boundaries), binary files, large files, directories, unreadable files, missing files.

---

## 4. Test vectors (verified on this machine)

```
MD5  ""                       d41d8cd98f00b204e9800998ecf8427e
MD5  "foo"                    acbd18db4cc2f85cedef654fccc4a4d8
MD5  "42 is nice"             0029a98ee90fdb85d70924d44d3c9e75
MD5  "And above all,\n"       53d53ea94217b259c11a5a2d104ec58a
SHA256 "42 is nice"           b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
```

Note the subject's `echo "42 is nice" | openssl md5` gives
`35f1d6de0302e2086a4e472266efb3a9` — that is the string **with** the trailing newline that
`echo` adds. `0029a98e...` above is without it. Useful pair for catching off-by-one
length bugs.

The 56-byte boundary is the classic MD5/SHA-256 bug: a message whose length mod 64 is
between 56 and 63 forces the padding into a *second* block. Test it explicitly.

---

## 5. Bonus (only after mandatory is perfect)

The subject is blunt: the bonus is not evaluated at all unless the mandatory part is
flawless. For reference, the bonuses are (a) parsing commands from stdin the way OpenSSL's
interactive mode does, and (b) a hash stronger than MD5 — **whirlpool** is required for
maximum points. Both drop in cleanly if the dispatch table from §2.5 exists.
