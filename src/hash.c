#include "ft_ssl.h"

/*
** The dispatch table the subject asks for. Adding an algorithm is one row
** here plus its own file; nothing in main.c or output.c has to change.
*/
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

/*
** Absorb an arbitrary number of bytes, compressing every complete 64-byte
** block and keeping the remainder for the next call. Identical for MD5 and
** SHA-256 because both have a 512-bit block; the algorithm-specific part is
** ctx->transform, installed by init.
*/
void hash_update(t_hash_ctx *ctx, const unsigned char *data, size_t len) {
	size_t i = 0;

	/* finish the block left over from a previous call */
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

	/* whole blocks straight from the caller's buffer, no copy */
	for (; i + 64 <= len; i += 64) {
		ctx->transform(ctx, data + i);
		ctx->bitlen += 512;
	}

	/* stash the tail */
	if (i < len) {
		size_t rem = len - i;
		ft_memcpy(ctx->data, data + i, rem);
		ctx->datalen = (unsigned int)rem;
	}
}

/*
** Append the mandatory 1 bit (0x80) and zero-fill until only the 8-byte
** length field remains. If 0x80 leaves no room for it, flush this block and
** start a fresh one. Both algorithms pad the same way; only the encoding of
** the length differs, so each final writes that itself.
**
** hash_update counts whole blocks only, so the buffered bytes are added to
** bitlen here.
*/
void hash_pad(t_hash_ctx *ctx) {
	unsigned int	i;

	ctx->bitlen += (unsigned long)ctx->datalen * 8;
	i = ctx->datalen;
	ctx->data[i++] = 0x80;
	if (i > 56) {
		while (i < 64)
			ctx->data[i++] = 0x00;
		ctx->transform(ctx, ctx->data);
		i = 0;
	}
	while (i < 56)
		ctx->data[i++] = 0x00;
}

/*
** Returns 1 and leaves errno set on failure; the caller owns the message
** because only it knows which file the descriptor belongs to.
*/
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

/* Same pipeline for data already in memory: a -s string, or buffered stdin. */
void digest_buf(const t_command *cmd, const unsigned char *data, size_t len,
		unsigned char *digest) {
	t_hash_ctx	ctx;

	cmd->init(&ctx);
	hash_update(&ctx, data, len);
	cmd->final(&ctx, digest);
}
