#include "header.h"
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