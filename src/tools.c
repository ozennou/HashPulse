#include "ft_ssl.h"

int	ft_error(char *str)
{
	if (str)
		while (*str)
			write(2, str++, 1);
	return (1);
}

void	print_usage(void)
{
	ft_error("usage: ft_ssl command [flags] [file/string]\n");
}

void	print_help(void)
{
	ft_error("\nCommands:\n");
	ft_error("  md5         compute an MD5 message digest\n");
	ft_error("  sha256      compute a SHA-256 message digest\n");
	ft_error("\nFlags:\n");
	ft_error("  -p          echo STDIN to STDOUT and append the checksum\n");
	ft_error("  -q          quiet mode: print only the digest\n");
	ft_error("  -r          reverse the output format: digest first\n");
	ft_error("  -s <string> compute the digest of the given string\n");
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
