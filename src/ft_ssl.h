#include <unistd.h>
#include <stdio.h>

#include "get_next_line/get_next_line.h"

#define FLAG_P (1 << 0)
#define FLAG_Q (1 << 1)
#define FLAG_R (1 << 2)
#define FLAG_S (1 << 3)

int ft_error(char*);
int ft_strcmp(char*, char*);
void print_binary(unsigned char *data, size_t len);
