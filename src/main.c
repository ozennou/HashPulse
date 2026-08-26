#include "ft_ssl.h"

static void add_input(t_options *options, t_input_type type, char *value) {
	options->inputs[options->count].type = type;
	options->inputs[options->count].value = value;
	options->count++;
}

static int invalid_flag(t_options *options, char *flag) {
	ft_error("ft_ssl: Error: '");
	ft_error(flag);
	ft_error("' is an invalid flag.\n");
	free(options->inputs);
	return 1;
}

static int parse_operands(int ac, char **av, t_options *options) {
	int	i = 2;
	int	flags_done = 0;

	while (i < ac) {
		if (!flags_done && av[i][0] == '-' && av[i][1] != '\0') {
			if (!ft_strcmp(av[i], "-p"))
				options->flags |= FLAG_P;
			else if (!ft_strcmp(av[i], "-q"))
				options->flags |= FLAG_Q;
			else if (!ft_strcmp(av[i], "-r"))
				options->flags |= FLAG_R;
			else if (!ft_strcmp(av[i], "-s")) {
				options->flags |= FLAG_S;
				if (i + 1 < ac)
					add_input(options, INPUT_STRING, av[++i]);
				else
					add_input(options, INPUT_FILE, av[i]);
			}
			else
				return invalid_flag(options, av[i]);
		}
		else {
			flags_done = 1;
			add_input(options, INPUT_FILE, av[i]);
		}
		i++;
	}
	return 0;
}

int verify_args(int ac, char **av, t_options *options) {
	options->inputs = malloc(sizeof(t_input) * (ac - 1));
	if (!options->inputs)
		return ft_error("ft_ssl: Error: Memory allocation failed.\n");

	options->cmd = find_command(av[1]);
	if (!options->cmd) {
		ft_error("ft_ssl: Error: '");
		ft_error(av[1]);
		ft_error("' is an invalid command.\n");
		free(options->inputs);
		return 1;
	}
	return parse_operands(ac, av, options);
}

unsigned char *read_all(int fd, size_t *out_len) {
	unsigned char	*buf;
	unsigned char	*bigger;
	size_t			cap = CHUNK_SIZE;
	size_t			used = 0;
	ssize_t			n;

	buf = malloc(cap);
	if (!buf)
		return NULL;
	while ((n = read(fd, buf + used, cap - used)) > 0) {
		used += (size_t)n;
		if (used == cap) {
			bigger = malloc(cap * 2);
			if (!bigger) {
				free(buf);
				return NULL;
			}
			ft_memcpy(bigger, buf, used);
			free(buf);
			buf = bigger;
			cap *= 2;
		}
	}
	if (n < 0) {
		free(buf);
		return NULL;
	}
	*out_len = used;
	return buf;
}

static int process_stdin(t_options *options, unsigned char *digest) {
	unsigned char	*content;
	size_t			len;

	if (options->flags & FLAG_P) {
		content = read_all(0, &len);
		if (!content) {
			ft_error("ft_ssl: Error: Unable to read stdin.\n");
			return 1;
		}
		digest_buf(options->cmd, content, len, digest);
		print_stdin_echo(options, content, len, digest);
		free(content);
		return 0;
	}
	if (digest_fd(options->cmd, 0, digest)) {
		ft_error("ft_ssl: Error: Unable to read stdin.\n");
		return 1;
	}
	print_stdin(options, digest);
	return 0;
}

int process(t_options *options) {
	unsigned char	digest[MAX_DIGEST];
	int				status = 0;
	int				fd;
	int				i;

	if ((options->flags & FLAG_P) || options->count == 0)
		status |= process_stdin(options, digest);
	for (i = 0; i < options->count; i++) {
		if (options->inputs[i].type == INPUT_STRING) {
			digest_buf(options->cmd,
				(unsigned char *)options->inputs[i].value,
				ft_strlen(options->inputs[i].value), digest);
			print_result(options, &options->inputs[i], digest);
			continue;
		}
		fd = open(options->inputs[i].value, O_RDONLY);
		if (fd == -1) {
			print_file_error(options, options->inputs[i].value);
			status = 1;
			continue;
		}
		if (digest_fd(options->cmd, fd, digest)) {
			print_file_error(options, options->inputs[i].value);
			status = 1;
		}
		else
			print_result(options, &options->inputs[i], digest);
		close(fd);
	}
	return status;
}

int	main(int ac, char **av) {
	t_options	options = {NULL, 0, NULL, 0};
	int			status;

	if (ac < 2) {
		print_usage();
		return (1);
	}
	if (verify_args(ac, av, &options)) {
		print_help();
		return (1);
	}
	status = process(&options);
	free(options.inputs);
	return (status);
}
