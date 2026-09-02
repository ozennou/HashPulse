# ft_ssl_md5

A re-implementation of part of the OpenSSL command line tool, written from scratch in C.
It computes **MD5**, **SHA-256** and **SHA-512** message digests, byte-for-byte identical
to `md5sum`, `sha256sum` and `sha512sum`.

Part of the **42 advanced cursus** — project `ft_ssl_md5`, the entry point to the
Encryption and Security branch.

No cryptographic library is used. Every algorithm is implemented from its specification,
using only `open`, `close`, `read`, `write`, `malloc` and `free`.

---

## Build

```sh
make
```

Produces `./ft_ssl`. Targets: `all`, `clean`, `fclean`, `re`.

Compiled with `-Wall -Wextra -Werror -O3 -funroll-loops` and warning-free.

> **Requires `libreadline`** for the interactive mode (`sudo apt install libreadline-dev`
> on Debian/Ubuntu). The subject permits it for the bonus part.

---

## Usage

```
ft_ssl command [flags] [file/string]
```

| Command | Digest |
|---|---|
| `md5` | 128 bits |
| `sha256` | 256 bits |
| `sha512` | 512 bits |

| Flag | Effect |
|---|---|
| `-p` | echo STDIN to STDOUT and append the checksum |
| `-q` | quiet mode: print only the digest |
| `-r` | reverse the output format: digest first |
| `-s <string>` | compute the digest of the given string |

### Examples

```console
$ ./ft_ssl md5 file
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a

$ ./ft_ssl md5 -r file
53d53ea94217b259c11a5a2d104ec58a file

$ ./ft_ssl md5 -q file
53d53ea94217b259c11a5a2d104ec58a

$ ./ft_ssl md5 -s "42 is nice"
MD5 ("42 is nice") = 0029a98ee90fdb85d70924d44d3c9e75

$ echo "42 is nice" | ./ft_ssl md5
(stdin)= 35f1d6de0302e2086a4e472266efb3a9

$ echo "42 is nice" | ./ft_ssl md5 -p
("42 is nice")= 35f1d6de0302e2086a4e472266efb3a9

$ ./ft_ssl sha256 -s "42 is nice"
SHA256 ("42 is nice") = b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
```

Flags may be combined, and files and strings interleaved. Flags are recognised only until
the first operand — after that everything is a file name, even if it starts with `-`.

```console
$ echo "one more thing" | ./ft_ssl md5 -r -p -s "foo" file -s "bar"
("one more thing")= a0bd1876c6f011dd50fae52827f445f5
acbd18db4cc2f85cedef654fccc4a4d8 "foo"
53d53ea94217b259c11a5a2d104ec58a file
ft_ssl: md5: -s: No such file or directory
ft_ssl: md5: bar: No such file or directory
```

### Interactive mode

Run with no arguments to read commands from standard input, the way `openssl` does.
A prompt is shown when the input is a terminal; piped input runs silently.

```console
$ ./ft_ssl
OpenSSL> md5 -s abc
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
OpenSSL> sha512 -q -s abc
ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a...
OpenSSL> quit
```

```console
$ printf 'md5 -s abc\nsha256 -s abc\n' | ./ft_ssl
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
SHA256 ("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

---

## Design

```
src/
  main.c      argument parsing, operand list, the per-file loop
  repl.c      interactive mode: reads commands and re-enters the same path
  hash.c      the command table, shared block buffering and padding
  md5.c       MD5      compression function and finalisation
  sha256.c    SHA-256  compression function and finalisation
  sha512.c    SHA-512  compression function and finalisation
  output.c    the four output formats and their -q / -r variants
  tools.c     usage, help, error reporting
  libft.c     the handful of libc replacements needed
```

**Commands are dispatched through a table, not a chain of `if`s.** Each row carries the
name, the display label, the help text, the digest size, and pointers to the algorithm's
`init` and `final`:

```c
static const t_command g_commands[] = {
    {"md5",    "MD5",    "compute an MD5 message digest",     MD5_SIZE,    md5_init,    md5_final},
    {"sha256", "SHA256", "compute a SHA-256 message digest",  SHA256_SIZE, sha256_init, sha256_final},
    {"sha512", "SHA512", "compute a SHA-512 message digest",  SHA512_SIZE, sha512_init, sha512_final},
    {NULL, NULL, NULL, 0, NULL, NULL}
};
```

Adding an algorithm is **two edits** — its prototypes in `ft_ssl.h` and one row here —
plus its own file. The help text and the command lookup both read from the table, so
neither needs touching.

**The three algorithms share what they genuinely have in common.** All are
Merkle–Damgård constructions, so `hash_update` (block buffering) and `hash_pad` (the
`0x80` marker and zero fill) are written once. The context carries its own compression
function and block size, so the shared code needs no knowledge of which algorithm is
running:

```c
typedef struct s_hash_ctx {
    unsigned char       data[MAX_BLOCK];
    unsigned int        datalen;
    unsigned int        blocksize;      /* 64 for md5/sha256, 128 for sha512 */
    unsigned int        state[8];
    unsigned long long  state64[8];
    unsigned long       bitlen;
    void (*transform)(struct s_hash_ctx *, const unsigned char *);
} t_hash_ctx;
```

What differs stays per-algorithm: the compression function, the byte order (MD5 is
little-endian, both SHA variants big-endian) and the width of the length field.

**Input is streamed.** Files are read in 1 MB chunks and hashed as they arrive, so memory
stays flat regardless of input size — a 5 GB file peaks under 3 MB of RSS. Only `-p`
buffers, because it has to echo what it read.

**Constants are derived, not transcribed.** The round constants and initial state values
come from their published formulas — `⌊2³²·|sin(i)|⌋` for MD5, and the fractional parts of
the cube and square roots of the first primes for SHA-2 — and were checked against the
specifications before being written into the source.

---

## Testing

Verified against the reference tools at every boundary that matters: message lengths of
0, 1, 55/56/57, 63/64/65, 111/112/113, 127/128/129 bytes, either side of the 1 MB read
buffer, and up to 5 GB.

```sh
diff <(./ft_ssl md5    -q file) <(md5sum    < file | cut -d' ' -f1)
diff <(./ft_ssl sha256 -q file) <(sha256sum < file | cut -d' ' -f1)
diff <(./ft_ssl sha512 -q file) <(sha512sum < file | cut -d' ' -f1)
```

Also checked against the official test vectors — RFC 1321 for MD5, FIPS 180-4 for
SHA-256 and SHA-512 — and against all the examples in the subject.

Errors are reported through `strerror` and never abort the run; remaining operands are
still hashed, and the exit status reflects the failure.

```console
$ ./ft_ssl md5 missing file a_directory
ft_ssl: md5: missing: No such file or directory
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a
ft_ssl: md5: a_directory: Is a directory
```

Clean under AddressSanitizer, UndefinedBehaviorSanitizer and Valgrind, with no memory or
file-descriptor leaks.

---

## Reference material

See [RESOURCES.md](RESOURCES.md) for the specifications and the diagrams written while
working through the algorithms.
