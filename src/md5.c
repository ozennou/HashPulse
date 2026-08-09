#include "ft_ssl.h"

void md5_init(t_hash_ctx *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

void testfunc(const unsigned char *content) { //TODO
	for (int i = 0; i < 64; i++){
		printf("%c", content[i]);
	}
	printf("\n---------------------------------------\n");
}

void md5_transform(t_hash_ctx *ctx, const unsigned char block[64]) {
	(void)ctx;
	(void)block;
}

void md5_update(t_hash_ctx *ctx, const unsigned char *data, int len) {
	size_t i = 0;

	if (ctx->datalen) {
		size_t to_copy = 64 - ctx->datalen;
		if (to_copy > len) to_copy = len;
		ft_memcpy(ctx->data + ctx->datalen, data, to_copy);
		ctx->datalen += (unsigned int)to_copy;
		i += to_copy;
		if (ctx->datalen == 64) {
			testfunc(ctx->data);
			md5_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}

	for (; i + 64 <= len; i += 64) {
		testfunc(data + i);
		md5_transform(ctx, data + i);
		ctx->bitlen += 512;
	}

	if (i < len) {
		size_t rem = len - i;
		memcpy(ctx->data, data + i, rem);
		ctx->datalen = (unsigned int)rem;
	}
}

int md5_digest(int fd) {
	t_hash_ctx		ctx;
	ssize_t			bytes_read;
	unsigned char	*buffer;

	buffer = malloc(MAX_SIZE);
	if (!buffer) {
		ft_error("ft_ssl: Error: Memory allocation failed.\n");
		return 1;
	}
	md5_init(&ctx);
	while ((bytes_read = read(fd, buffer, MAX_SIZE)) > 0) {
		md5_update(&ctx, buffer, bytes_read);
	}
	if (bytes_read < 0) {
		ft_error("ft_ssl: Error: Unable to read input data.\n");
		free(buffer);
		return 1;
	}

	free(buffer);
	return 0;
}
