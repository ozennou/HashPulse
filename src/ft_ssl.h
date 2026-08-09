#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#define CHUNK_SIZE 8192
#define MAX_SIZE (1024 * 1024) // 1 MB

#define FLAG_P (1 << 0)
#define FLAG_Q (1 << 1)
#define FLAG_R (1 << 2)
#define FLAG_S (1 << 3)

typedef struct s_options {
    int     hash; // 1: md5, 2: sha256
    int     flags;
    int     tmp_fd;
    char    **inputs; //list of the inputs
}   t_options;

typedef struct s_hash_ctx {
    unsigned char   data[64];
    unsigned int    datalen;
    unsigned int    state[8];
    unsigned long   bitlen;
} t_hash_ctx;

void    md5_init(t_hash_ctx *ctx);
void    md5_transform(t_hash_ctx *ctx, const unsigned char block[64]);
void    md5_update(t_hash_ctx *ctx, const unsigned char *data, int len);
int     md5_digest(int fd);

void	*ft_memcpy(void *d, const void *s, size_t n);
char	*ft_strjoin(char const *a, char const *b);
size_t	ft_strlen(const char *s);
int     ft_strcmp(char*, char*);
int     ft_error(char*);

//TODO
void print_binary(unsigned char *data, size_t len);
