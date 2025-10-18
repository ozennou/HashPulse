#include "ft_ssl.h"

int	ft_error(char *str)
{
	if (str)
		while (*str)
			write(2, str++, 1);
	return (1);
}

int ft_strcmp(char *s1, char *s2)
{
	while (*s1 && *s2 && *s1 == *s2)
	{
		s1++;
		s2++;
	}
	return (*(unsigned char *)s1 - *(unsigned char *)s2);
}

void print_binary(unsigned char *data, size_t len) // remove later: TODO
{
	printf("Binary representation (%zu bytes):\n", len);
	for (size_t i = 0; i < len; i++)
	{
		if (i % 8 == 0)
			printf("\n[%04zu] ", i);
		
		for (int bit = 7; bit >= 0; bit--)
		{
			printf("%d", (data[i] >> bit) & 1);
		}
		printf(" ");
		
		if (data[i] >= 32 && data[i] <= 126)
			printf("(%c) ", data[i]);
		else
			printf("(.) ");
	}
	printf("\n\n");
}