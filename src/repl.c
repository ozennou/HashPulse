#include "ft_ssl.h"
#include <readline/readline.h>
#include <readline/history.h>

#define MAX_TOKENS 128

static char	*read_command(void) {
	char	*buf;
	char	*bigger;
	size_t	cap = 128;
	size_t	len = 0;
	char	c;
	ssize_t	n;

	buf = malloc(cap);
	if (!buf)
		return NULL;
	while ((n = read(0, &c, 1)) == 1) {
		if (c == '\n')
			break;
		if (len + 1 >= cap) {
			bigger = malloc(cap * 2);
			if (!bigger) {
				free(buf);
				return NULL;
			}
			ft_memcpy(bigger, buf, len);
			free(buf);
			buf = bigger;
			cap *= 2;
		}
		buf[len++] = c;
	}
	if (n <= 0 && len == 0) {
		free(buf);
		return NULL;
	}
	buf[len] = '\0';
	return buf;
}

static int	tokenize(char *line, char **av) {
	int		ac = 1;
	char	*p = line;
	char	q;

	while (*p && ac < MAX_TOKENS - 1) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (*p == '"' || *p == '\'') {
			q = *p++;
			av[ac++] = p;
			while (*p && *p != q)
				p++;
		}
		else {
			av[ac++] = p;
			while (*p && *p != ' ' && *p != '\t')
				p++;
		}
		if (*p)
			*p++ = '\0';
	}
	av[ac] = NULL;
	return ac;
}

static int	run_line(char *line) {
	char		prog[] = "ft_ssl";
	char		*av[MAX_TOKENS];
	t_options	options = {NULL, 0, NULL, 0};
	int			ac;
	int			status;

	av[0] = prog;
	ac = tokenize(line, av);
	if (ac < 2)
		return 0;
	if (!ft_strcmp(av[1], "quit") || !ft_strcmp(av[1], "exit"))
		return -1;
	if (verify_args(ac, av, &options)) {
		print_help();
		return 1;
	}
	status = process(&options);
	free(options.inputs);
	return status;
}

int	repl(void) {
	char	*line;
	int		tty = isatty(0);
	int		status = 0;
	int		r;

	while (1) {
		if (tty)
			line = readline("OpenSSL> ");
		else
			line = read_command();
		if (!line)
			break;
		if (tty && *line)
			add_history(line);
		r = run_line(line);
		free(line);
		if (r == -1)
			break;
		if (r)
			status = 1;
	}
	if (tty)
		ft_putstr("\n");
	return status;
}
