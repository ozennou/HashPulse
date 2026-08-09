#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define CHUNK_SIZE 8192
#define MAX_SIZE (1024 * 1024) // 1 MB

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define FLAG_P (1 << 0)
#define FLAG_Q (1 << 1)
#define FLAG_R (1 << 2)
#define FLAG_S (1 << 3)

#define MD5_SIZE 16
#define SHA256_SIZE 32
#define MAX_DIGEST 32

typedef enum e_input_type {
    INPUT_FILE,
    INPUT_STRING
}   t_input_type;

/* One operand, in the order it appeared on the command line. */
typedef struct s_input {
    t_input_type    type;
    char            *value;
}   t_input;

/*
** The block buffering in hash_update is identical for both algorithms, so
** the context carries its own compression function and update stays generic.
*/
typedef struct s_hash_ctx {
    unsigned char   data[64];
    unsigned int    datalen;
    unsigned int    state[8];
    unsigned long   bitlen;
    void            (*transform)(struct s_hash_ctx *, const unsigned char *);
} t_hash_ctx;

/* One row per algorithm; adding a hash means adding a row, not a branch. */
typedef struct s_command {
    char    *name;                              /* "md5"  */
    char    *label;                             /* "MD5"  */
    size_t  size;                               /* digest length in bytes */
    void    (*init)(t_hash_ctx *);
    void    (*final)(t_hash_ctx *, unsigned char *);
}   t_command;

typedef struct s_options {
    const t_command *cmd;
    int             flags;
    t_input         *inputs;
    int             count;
}   t_options;

/* hash.c */
void            hash_update(t_hash_ctx *ctx, const unsigned char *data,
                    size_t len);
void            hash_pad(t_hash_ctx *ctx);
const t_command *find_command(const char *name);
int             digest_fd(const t_command *cmd, int fd, unsigned char *digest);
void            digest_buf(const t_command *cmd, const unsigned char *data,
                    size_t len, unsigned char *digest);

/* md5.c */
void    md5_init(t_hash_ctx *ctx);
void    md5_transform(t_hash_ctx *ctx, const unsigned char *block);
void    md5_final(t_hash_ctx *ctx, unsigned char *digest);

/* sha256.c */
void    sha256_init(t_hash_ctx *ctx);
void    sha256_transform(t_hash_ctx *ctx, const unsigned char *block);
void    sha256_final(t_hash_ctx *ctx, unsigned char *digest);

void	*ft_memcpy(void *d, const void *s, size_t n);
char	*ft_strjoin(char const *a, char const *b);
size_t	ft_strlen(const char *s);
int     ft_strcmp(char*, char*);
int     ft_error(char*);
void    print_usage(void);
void    print_help(void);

/* output.c */
void    ft_putstr(const char *s);
void    put_hex(const unsigned char *digest, size_t len);
void    print_result(t_options *o, t_input *in, const unsigned char *digest);
void    print_stdin(t_options *o, const unsigned char *digest);
void    print_stdin_echo(t_options *o, const unsigned char *content,
            size_t len, const unsigned char *digest);
void    print_file_error(t_options *o, const char *name);

unsigned char   *read_all(int fd, size_t *out_len);
