#include "ft_ssl.h"

void	ft_write(int fd, const void *buf, size_t len)
{
	const char	*p = buf;
	ssize_t		n;

	while (len > 0)
	{
		n = write(fd, p, len);
		if (n <= 0)
			return ;
		p += n;
		len -= (size_t)n;
	}
}

int	ft_error(char *str)
{
	if (str)
		ft_write(2, str, ft_strlen(str));
	return (1);
}

void	print_usage(void)
{
	ft_error("usage: ft_ssl command [flags] [file/string]\n");
}

void	print_help(void)
{
	ft_error("\nCommands:\n");
	print_commands();
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
