# Resources

Reference material used while building `ft_ssl`, plus the diagrams written for the defence.

## MD5

- [RFC 1321 — The MD5 Message-Digest Algorithm](https://www.rfc-editor.org/info/rfc1321/)
  The specification. Defines the `T` constant table, the shift amounts and the padding, and
  carries the test vectors used to validate this implementation.
- [Inside MD5](https://claude.ai/code/artifact/fb204bc6-8855-4a97-a5b3-f36a5987764b)
  Stage-by-stage walkthrough: the chaining construction, the little-endian byte decode, the
  round shuffle and the 55/56 padding boundary, with a worked `MD5("abc")` trace.

## SHA-256 and SHA-512

- [FIPS 180-4 — Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
  The specification for the whole SHA-2 family, so it covers both algorithms here: SHA-256
  in section 6.2, SHA-512 in section 6.4. Defines the round constants, the sigma functions
  and the padding, and carries the test vectors used to validate both implementations.
- [SHA-256 in JavaScript](https://www.movable-type.co.uk/scripts/sha256.html)
  A readable step-by-step implementation. Handy for checking intermediate values by hand.
- [Inside SHA-256](https://claude.ai/code/artifact/e0c4f1e8-dabd-4568-8d33-4577840d3b38)
  The message schedule that expands 16 words into 64, the two registers updated per round,
  the sigma functions, and where the constants come from. SHA-512 is the same structure
  widened to 64-bit words, 80 rounds and a 128-bit length field.

## Bonus

The bonus is two things: reading commands from standard input, and an extra hash function
stronger than MD5. SHA-512 covers the second, and is specified in FIPS 180-4 above.

- [GNU Readline](https://tiswww.case.edu/php/chet/readline/rltop.html)
  Drives the interactive prompt when standard input is a terminal. The subject permits it
  for the bonus part only.

---

Whirlpool was implemented and then removed from the project. Its notes and diagram remain
in the history at commits `4902ab7` and `0aa59ca`.
