#include "ft_ssl.h"

static unsigned long long	g_c[8][256];
static unsigned long long	g_rc[11];
static int					g_ready = 0;

static unsigned char	wp_mul2(unsigned char x) {
	return ((unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1d : 0x00)));
}

static void	wp_sbox(unsigned char *s) {
	static const unsigned char	e[16] = {0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF,
		0x3, 0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0};
	static const unsigned char	r[16] = {0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9,
		0xF, 0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0};
	unsigned char				einv[16];
	unsigned char				y1;
	unsigned char				y2;
	unsigned char				rr;
	int							i;

	for (i = 0; i < 16; i++)
		einv[e[i]] = (unsigned char)i;
	for (i = 0; i < 256; i++) {
		y1 = e[(i >> 4) & 0x0f];
		y2 = einv[i & 0x0f];
		rr = r[y1 ^ y2];
		s[i] = (unsigned char)((e[y1 ^ rr] << 4) | einv[y2 ^ rr]);
	}
}

static void	wp_build(void) {
	unsigned char		s[256];
	unsigned char		a1, a2, a4, a5, a8, a9;
	unsigned long long	v1, v2, v4, v5, v8, v9;
	int					i;
	int					j;
	int					k;

	wp_sbox(s);
	for (i = 0; i < 256; i++) {
		a1 = s[i];
		a2 = wp_mul2(a1);
		a4 = wp_mul2(a2);
		a5 = (unsigned char)(a4 ^ a1);
		a8 = wp_mul2(a4);
		a9 = (unsigned char)(a8 ^ a1);
		v1 = a1; v2 = a2; v4 = a4; v5 = a5; v8 = a8; v9 = a9;
		g_c[0][i] = (v1 << 56) | (v1 << 48) | (v4 << 40) | (v1 << 32)
			| (v8 << 24) | (v5 << 16) | (v2 << 8) | v9;
		for (j = 1; j < 8; j++)
			g_c[j][i] = (g_c[j - 1][i] >> 8) | (g_c[j - 1][i] << 56);
	}
	g_rc[0] = 0;
	for (i = 1; i <= 10; i++) {
		k = 8 * (i - 1);
		g_rc[i] = (g_c[0][k] & 0xff00000000000000ULL)
			^ (g_c[1][k + 1] & 0x00ff000000000000ULL)
			^ (g_c[2][k + 2] & 0x0000ff0000000000ULL)
			^ (g_c[3][k + 3] & 0x000000ff00000000ULL)
			^ (g_c[4][k + 4] & 0x00000000ff000000ULL)
			^ (g_c[5][k + 5] & 0x0000000000ff0000ULL)
			^ (g_c[6][k + 6] & 0x000000000000ff00ULL)
			^ (g_c[7][k + 7] & 0x00000000000000ffULL);
	}
	g_ready = 1;
}

static void	wp_round(unsigned long long *out, const unsigned long long *in,
		const unsigned long long *key) {
	int	i;

	for (i = 0; i < 8; i++) {
		out[i] = g_c[0][(in[(i + 8) & 7] >> 56) & 0xff]
			^ g_c[1][(in[(i + 7) & 7] >> 48) & 0xff]
			^ g_c[2][(in[(i + 6) & 7] >> 40) & 0xff]
			^ g_c[3][(in[(i + 5) & 7] >> 32) & 0xff]
			^ g_c[4][(in[(i + 4) & 7] >> 24) & 0xff]
			^ g_c[5][(in[(i + 3) & 7] >> 16) & 0xff]
			^ g_c[6][(in[(i + 2) & 7] >> 8) & 0xff]
			^ g_c[7][(in[(i + 1) & 7]) & 0xff]
			^ key[i];
	}
}

void	whirlpool_init(t_hash_ctx *ctx) {
	int	i;

	if (!g_ready)
		wp_build();
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->transform = whirlpool_transform;
	for (i = 0; i < 8; i++)
		ctx->state64[i] = 0;
}

void	whirlpool_transform(t_hash_ctx *ctx, const unsigned char *block) {
	unsigned long long	m[8];
	unsigned long long	k[8];
	unsigned long long	st[8];
	unsigned long long	tmp[8];
	unsigned long long	rc[8];
	int					i;
	int					t;
	int					r;

	for (i = 0; i < 8; i++) {
		m[i] = 0;
		for (t = 0; t < 8; t++)
			m[i] = (m[i] << 8) | block[i * 8 + t];
		k[i] = ctx->state64[i];
		st[i] = m[i] ^ k[i];
		rc[i] = 0;
	}
	for (r = 1; r <= 10; r++) {
		rc[0] = g_rc[r];
		wp_round(tmp, k, rc);
		for (i = 0; i < 8; i++)
			k[i] = tmp[i];
		wp_round(tmp, st, k);
		for (i = 0; i < 8; i++)
			st[i] = tmp[i];
	}
	for (i = 0; i < 8; i++)
		ctx->state64[i] ^= st[i] ^ m[i];
}

void	whirlpool_final(t_hash_ctx *ctx, unsigned char *digest) {
	unsigned int	i;

	hash_pad(ctx, WHIRLPOOL_LENFIELD);
	for (i = 0; i < 8; i++)
		ctx->data[63 - i] = (unsigned char)(ctx->bitlen >> (8 * i));
	ctx->transform(ctx, ctx->data);
	for (i = 0; i < WHIRLPOOL_SIZE; i++)
		digest[i] = (unsigned char)(ctx->state64[i / 8] >> (56 - 8 * (i % 8)));
}
