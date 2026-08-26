#include "ft_ssl.h"

void	ft_putstr(const char *s)
{
	if (s)
		write(1, s, ft_strlen(s));
}

void	put_hex(const unsigned char *digest, size_t len)
{
	const char	*hex = "0123456789abcdef";
	char		out[128];
	size_t		i;

	i = 0;
	while (i < len && i < MAX_DIGEST)
	{
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 15];
		i++;
	}
	write(1, out, i * 2);
}

static void	put_name(t_input *in)
{
	if (in->type == INPUT_STRING)
		ft_putstr("\"");
	ft_putstr(in->value);
	if (in->type == INPUT_STRING)
		ft_putstr("\"");
}

void	print_result(t_options *o, t_input *in,
		const unsigned char *digest)
{
	if (o->flags & FLAG_Q)
	{
		put_hex(digest, o->cmd->size);
		ft_putstr("\n");
		return ;
	}
	if (o->flags & FLAG_R)
	{
		put_hex(digest, o->cmd->size);
		ft_putstr(" ");
		put_name(in);
		ft_putstr("\n");
		return ;
	}
	ft_putstr(o->cmd->label);
	ft_putstr(" (");
	put_name(in);
	ft_putstr(") = ");
	put_hex(digest, o->cmd->size);
	ft_putstr("\n");
}

void	print_stdin(t_options *o, const unsigned char *digest)
{
	if (!(o->flags & FLAG_Q))
		ft_putstr("(stdin)= ");
	put_hex(digest, o->cmd->size);
	ft_putstr("\n");
}

void	print_stdin_echo(t_options *o, const unsigned char *content,
		size_t len, const unsigned char *digest)
{
	if (o->flags & FLAG_Q)
	{
		write(1, content, len);
		if (len == 0 || content[len - 1] != '\n')
			ft_putstr("\n");
		put_hex(digest, o->cmd->size);
		ft_putstr("\n");
		return ;
	}
	ft_putstr("(\"");
	if (len && content[len - 1] == '\n')
		len--;
	write(1, content, len);
	ft_putstr("\")= ");
	put_hex(digest, o->cmd->size);
	ft_putstr("\n");
}

void	print_file_error(t_options *o, const char *name)
{
	ft_error("ft_ssl: ");
	ft_error(o->cmd->name);
	ft_error(": ");
	ft_error((char *)name);
	ft_error(": ");
	ft_error(strerror(errno));
	ft_error("\n");
}
