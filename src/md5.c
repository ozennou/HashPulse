#include "ft_ssl.h"

void md5_init(t_hash_ctx *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->transform = md5_transform;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

static const unsigned int	g_k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const unsigned int	g_s[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static unsigned int	md5_f(unsigned int b, unsigned int c, unsigned int d) {
	return ((b & c) | (~b & d));
}

static unsigned int	md5_g(unsigned int b, unsigned int c, unsigned int d) {
	return ((b & d) | (c & ~d));
}

static unsigned int	md5_h(unsigned int b, unsigned int c, unsigned int d) {
	return (b ^ c ^ d);
}

static unsigned int	md5_i(unsigned int b, unsigned int c, unsigned int d) {
	return (c ^ (b | ~d));
}

static unsigned int	md5_idx_f(int i) {
	return ((unsigned int)i);
}

static unsigned int	md5_idx_g(int i) {
	return ((unsigned int)(5 * i + 1) % 16);
}

static unsigned int	md5_idx_h(int i) {
	return ((unsigned int)(3 * i + 5) % 16);
}

static unsigned int	md5_idx_i(int i) {
	return ((unsigned int)(7 * i) % 16);
}

static unsigned int	(*const g_ops[4])(unsigned int, unsigned int,
		unsigned int) = {md5_f, md5_g, md5_h, md5_i};

static unsigned int	(*const g_idx[4])(int) = {md5_idx_f, md5_idx_g,
		md5_idx_h, md5_idx_i};

void md5_transform(t_hash_ctx *ctx, const unsigned char *block) {
	unsigned int	m[16];
	unsigned int	v[4];
	unsigned int	tmp;
	int				r;
	int				i;

	for (i = 0; i < 16; i++) {
		m[i] = (unsigned int)block[i * 4]
			| ((unsigned int)block[i * 4 + 1] << 8)
			| ((unsigned int)block[i * 4 + 2] << 16)
			| ((unsigned int)block[i * 4 + 3] << 24);
	}
	for (i = 0; i < 4; i++)
		v[i] = ctx->state[i];
	for (i = 0; i < 64; i++) {
		r = i / 16;
		tmp = v[0] + g_ops[r](v[1], v[2], v[3]) + m[g_idx[r](i)] + g_k[i];
		v[0] = v[3];
		v[3] = v[2];
		v[2] = v[1];
		v[1] = v[1] + ROTL32(tmp, g_s[i]);
	}
	for (i = 0; i < 4; i++)
		ctx->state[i] += v[i];
}

void md5_final(t_hash_ctx *ctx, unsigned char *digest) {
	unsigned int	i;

	hash_pad(ctx);
	for (i = 0; i < 8; i++)
		ctx->data[56 + i] = (unsigned char)(ctx->bitlen >> (8 * i));
	ctx->transform(ctx, ctx->data);
	for (i = 0; i < MD5_SIZE; i++)
		digest[i] = (unsigned char)(ctx->state[i / 4] >> (8 * (i % 4)));
}
