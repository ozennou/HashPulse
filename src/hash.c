#include "ft_ssl.h"

static const t_command	g_commands[] = {
	{"md5", "MD5", MD5_SIZE, md5_init, md5_final},
	{"sha256", "SHA256", SHA256_SIZE, sha256_init, sha256_final},
	{NULL, NULL, 0, NULL, NULL}
};

const t_command	*find_command(const char *name) {
	int	i = 0;

	while (g_commands[i].name) {
		if (!ft_strcmp((char *)name, g_commands[i].name))
			return (&g_commands[i]);
		i++;
	}
	return (NULL);
}

void hash_update(t_hash_ctx *ctx, const unsigned char *data, size_t len) {
	size_t i = 0;
	if (ctx->datalen) {
		size_t to_copy = 64 - ctx->datalen;
		if (to_copy > len) to_copy = len;
		ft_memcpy(ctx->data + ctx->datalen, data, to_copy);
		ctx->datalen += (unsigned int)to_copy;
		i += to_copy;
		if (ctx->datalen == 64) {
			ctx->transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	for (; i + 64 <= len; i += 64) {
		ctx->transform(ctx, data + i);
		ctx->bitlen += 512;
	}
	if (i < len) {
		size_t rem = len - i;
		ft_memcpy(ctx->data, data + i, rem);
		ctx->datalen = (unsigned int)rem;
	}
}

void hash_pad(t_hash_ctx *ctx, size_t lenfield) {
	unsigned int	i;
	unsigned int	limit = 64 - (unsigned int)lenfield;
	ctx->bitlen += (unsigned long)ctx->datalen * 8;
	i = ctx->datalen;
	ctx->data[i++] = 0x80;
	if (i > limit) {
		while (i < 64)
			ctx->data[i++] = 0x00;
		ctx->transform(ctx, ctx->data);
		i = 0;
	}
	while (i < 64)
		ctx->data[i++] = 0x00;
}

int digest_fd(const t_command *cmd, int fd, unsigned char *digest) {
	t_hash_ctx		ctx;
	ssize_t			bytes_read;
	unsigned char	*buffer;
	buffer = malloc(MAX_SIZE);
	if (!buffer)
		return 1;
	cmd->init(&ctx);
	while ((bytes_read = read(fd, buffer, MAX_SIZE)) > 0)
		hash_update(&ctx, buffer, (size_t)bytes_read);
	if (bytes_read < 0) {
		free(buffer);
		return 1;
	}
	cmd->final(&ctx, digest);
	free(buffer);
	return 0;
}

void digest_buf(const t_command *cmd, const unsigned char *data, size_t len,
		unsigned char *digest) {
	t_hash_ctx	ctx;
	cmd->init(&ctx);
	hash_update(&ctx, data, len);
	cmd->final(&ctx, digest);
}
