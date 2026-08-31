#include "ft_ssl.h"

void sha512_init(t_hash_ctx *ctx) {
	ctx->datalen = 0;
	ctx->blocksize = 128;
	ctx->bitlen = 0;
	ctx->transform = sha512_transform;
	ctx->state64[0] = 0x6a09e667f3bcc908ULL;
	ctx->state64[1] = 0xbb67ae8584caa73bULL;
	ctx->state64[2] = 0x3c6ef372fe94f82bULL;
	ctx->state64[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->state64[4] = 0x510e527fade682d1ULL;
	ctx->state64[5] = 0x9b05688c2b3e6c1fULL;
	ctx->state64[6] = 0x1f83d9abfb41bd6bULL;
	ctx->state64[7] = 0x5be0cd19137e2179ULL;
}

static const unsigned long long	g_k512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static unsigned long long	sha512_ch(unsigned long long e, unsigned long long f,
		unsigned long long g) {
	return ((e & f) ^ (~e & g));
}

static unsigned long long	sha512_maj(unsigned long long a, unsigned long long b,
		unsigned long long c) {
	return ((a & b) ^ (a & c) ^ (b & c));
}

static unsigned long long	big_sigma0_512(unsigned long long x) {
	return (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39));
}

static unsigned long long	big_sigma1_512(unsigned long long x) {
	return (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41));
}

static unsigned long long	small_sigma0_512(unsigned long long x) {
	return (ROTR64(x, 1) ^ ROTR64(x, 8) ^ (x >> 7));
}

static unsigned long long	small_sigma1_512(unsigned long long x) {
	return (ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6));
}

void sha512_transform(t_hash_ctx *ctx, const unsigned char *block) {
	unsigned long long	w[80];
	unsigned long long	v[8];
	unsigned long long	t1;
	unsigned long long	t2;
	int					i;
	int					t;

	for (i = 0; i < 16; i++) {
		w[i] = 0;
		for (t = 0; t < 8; t++)
			w[i] = (w[i] << 8) | block[i * 8 + t];
	}
	for (i = 16; i < 80; i++) {
		w[i] = small_sigma1_512(w[i - 2]) + w[i - 7]
			+ small_sigma0_512(w[i - 15]) + w[i - 16];
	}
	for (i = 0; i < 8; i++)
		v[i] = ctx->state64[i];
	for (i = 0; i < 80; i++) {
		t1 = v[7] + big_sigma1_512(v[4]) + sha512_ch(v[4], v[5], v[6])
			+ g_k512[i] + w[i];
		t2 = big_sigma0_512(v[0]) + sha512_maj(v[0], v[1], v[2]);
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
		ctx->state64[i] += v[i];
}

void sha512_final(t_hash_ctx *ctx, unsigned char *digest) {
	unsigned int	i;

	hash_pad(ctx, SHA512_LENFIELD);
	for (i = 0; i < 8; i++)
		ctx->data[127 - i] = (unsigned char)(ctx->bitlen >> (8 * i));
	ctx->transform(ctx, ctx->data);
	for (i = 0; i < SHA512_SIZE; i++)
		digest[i] = (unsigned char)(ctx->state64[i / 8] >> (56 - 8 * (i % 8)));
}
