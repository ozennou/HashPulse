#include "ft_ssl.h"

/*
** IV: the first 32 bits of the fractional parts of the square roots of the
** first eight primes (2, 3, 5, 7, 11, 13, 17, 19). Another nothing-up-my-
** sleeve choice, same reasoning as MD5's sine table.
*/
void sha256_init(t_hash_ctx *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->transform = sha256_transform;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

// K[i] = first 32 bits of the fractional part of the cube root of the
// i-th prime. One constant per round, as in MD5.
static const unsigned int	g_k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Choice: bit by bit, take f where e is 1 and g where e is 0. */
static unsigned int	sha256_ch(unsigned int e, unsigned int f, unsigned int g) {
	return ((e & f) ^ (~e & g));
}

/* Majority: each output bit is whichever value at least two inputs agree on. */
static unsigned int	sha256_maj(unsigned int a, unsigned int b, unsigned int c) {
	return ((a & b) ^ (a & c) ^ (b & c));
}

/*
** The four sigma functions. Where MD5 used a single rotation per round,
** SHA-256 XORs three shifted copies together, which diffuses much faster.
** The small ones use a plain shift as the third term, not a rotation.
*/
static unsigned int	big_sigma0(unsigned int x) {
	return (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22));
}

static unsigned int	big_sigma1(unsigned int x) {
	return (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25));
}

static unsigned int	small_sigma0(unsigned int x) {
	return (ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3));
}

static unsigned int	small_sigma1(unsigned int x) {
	return (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10));
}

/*
** Decode the block big-endian (the opposite of MD5), expand the 16 words
** into a 64-word message schedule, then run 64 rounds over a copy of the
** state and fold the result back in.
*/
void sha256_transform(t_hash_ctx *ctx, const unsigned char *block) {
	unsigned int	w[64];
	unsigned int	v[8];
	unsigned int	t1;
	unsigned int	t2;
	int				i;

	for (i = 0; i < 16; i++) {
		w[i] = ((unsigned int)block[i * 4] << 24)
			| ((unsigned int)block[i * 4 + 1] << 16)
			| ((unsigned int)block[i * 4 + 2] << 8)
			| (unsigned int)block[i * 4 + 3];
	}
	/* Every later word is derived from four earlier ones. */
	for (i = 16; i < 64; i++) {
		w[i] = small_sigma1(w[i - 2]) + w[i - 7]
			+ small_sigma0(w[i - 15]) + w[i - 16];
	}
	for (i = 0; i < 8; i++)
		v[i] = ctx->state[i];
	/* v = a b c d e f g h */
	for (i = 0; i < 64; i++) {
		t1 = v[7] + big_sigma1(v[4]) + sha256_ch(v[4], v[5], v[6])
			+ g_k256[i] + w[i];
		t2 = big_sigma0(v[0]) + sha256_maj(v[0], v[1], v[2]);
		v[7] = v[6];
		v[6] = v[5];
		v[5] = v[4];
		v[4] = v[3] + t1;
		v[3] = v[2];
		v[2] = v[1];
		v[1] = v[0];
		v[0] = t1 + t2;
	}
	for (i = 0; i < 8; i++)
		ctx->state[i] += v[i];
}

/*
** Same padding as MD5 (hash_pad), but the length field and the digest are
** both big-endian. That byte order is the only difference in this function.
*/
void sha256_final(t_hash_ctx *ctx, unsigned char *digest) {
	unsigned int	i;

	hash_pad(ctx);
	for (i = 0; i < 8; i++)
		ctx->data[63 - i] = (unsigned char)(ctx->bitlen >> (8 * i));
	ctx->transform(ctx, ctx->data);
	for (i = 0; i < SHA256_SIZE; i++)
		digest[i] = (unsigned char)(ctx->state[i / 4] >> (24 - 8 * (i % 4)));
}
