# Resources

Reference material used while building `ft_ssl`, plus the diagrams written for the defence.

## MD5

- [RFC 1321 — The MD5 Message-Digest Algorithm](https://www.rfc-editor.org/info/rfc1321/)
  The specification. Defines the `T` constant table, the shift amounts and the padding, and
  carries the test vectors used to validate this implementation.
- [Inside MD5](https://claude.ai/code/artifact/fb204bc6-8855-4a97-a5b3-f36a5987764b)
  Stage-by-stage walkthrough: the chaining construction, the little-endian byte decode, the
  round shuffle and the 55/56 padding boundary, with a worked `MD5("abc")` trace.

## SHA-256

- [FIPS 180-4 — Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
  The specification for the whole SHA-2 family. Defines the round constants, the sigma
  functions and the padding, and carries the test vectors used to validate this
  implementation.
- [SHA-256 in JavaScript](https://www.movable-type.co.uk/scripts/sha256.html)
  A readable step-by-step implementation. Handy for checking intermediate values by hand.
- [Inside SHA-256](https://claude.ai/code/artifact/e0c4f1e8-dabd-4568-8d33-4577840d3b38)
  The message schedule that expands 16 words into 64, the two registers updated per round,
  the sigma functions, and where the constants come from.

## Bonus — Whirlpool

- [Whirlpool hashing function — seminar paper](https://web.archive.org/web/20240428145421/https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=eae4ca3441b83c14e17c6866d0214b623195bdfd)
  A 19-page walkthrough of the block cipher W and its four round layers (SB, SC, MR, AK),
  written as a university seminar paper. Not the official specification: it does not cover
  the Miyaguchi-Preneel wrapper, the S-box mini-box construction or the test vectors.
- [Inside Whirlpool](https://claude.ai/code/artifact/8e303142-7c59-439e-a45d-cd2280544d1b)
  Why a block cipher can be used as a hash (Miyaguchi–Preneel), the 8×8 byte state, the
  AES-like round, and the 256-bit length field that moves the padding boundary.
