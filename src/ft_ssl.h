#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 8192

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

int ft_error(char*);
int ft_strcmp(char*, char*);
char	*ft_strjoin(char const *a, char const *b);
size_t	ft_strlen(const char *s);

//TODO
void print_binary(unsigned char *data, size_t len);
