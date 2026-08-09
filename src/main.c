#include "ft_ssl.h"

int verify_args(int ac, char **av, t_options *options) {
	int j = 0;

	options->inputs = malloc(sizeof(char*) * (ac - 1));
	if (!options->inputs)
		return ft_error("ft_ssl: Error: Memory allocation failed.\n");

	if (ft_strcmp(av[1], "md5") && ft_strcmp(av[1], "sha256")) {
		ft_error("ft_ssl: Error: '");
		ft_error(av[1]);
		ft_error("' is an invalid command.\n");
		free(options->inputs);
		return 1;
	}
	options->hash = ft_strcmp(av[1], "md5") ? 2 : 1; 
	for (int i = 2; i < ac; i++) {
		if (av[i][0] == '-') {
			if (ft_strcmp(av[i], "-p") && ft_strcmp(av[i], "-q") && ft_strcmp(av[i], "-r") && ft_strcmp(av[i], "-s")) {
				ft_error("ft_ssl: Error: '");
				ft_error(av[i]);
				ft_error("' is an invalid flag.\n");
				free(options->inputs);
				return 1;
			}
			if (av[i][1] == 'p') options->flags |= FLAG_P;
			if (av[i][1] == 'q') options->flags |= FLAG_Q;
			if (av[i][1] == 'r') options->flags |= FLAG_R;
			if (av[i][1] == 's') options->flags |= FLAG_S;
		}
		else
			options->inputs[j++] = av[i];
	}
	options->inputs[j] = NULL;
	return 0;
}

int load(t_options *options) {
	char	buffer[CHUNK_SIZE];
	ssize_t	bytes_read;

	options->tmp_fd = -1;
	if (options->inputs[0] == NULL && !(options->flags & FLAG_S)) {
		options->flags |= FLAG_P;
	}
	if (options->flags & FLAG_P) {
		char templates[] = "/tmp/ft_ssl_inputXXXXXX";
		options->tmp_fd = mkstemp(templates);
		if (options->tmp_fd == -1) {
			ft_error("ft_ssl: Error: Unable to create temporary file for stdin input.\n");
			return 1;
		}

		while ((bytes_read = read(0, buffer, CHUNK_SIZE)) > 0) {
			write(options->tmp_fd, buffer, bytes_read);
		}
		if (lseek(options->tmp_fd, 0, SEEK_SET) == -1 || unlink(templates) == -1) {
			ft_error("ft_ssl: Error: Unable to reset temporary file pointer.\n");
			close(options->tmp_fd);
			unlink(templates);
			return 1;
		}
	}
	return 0;
}

int process(t_options *options) {
	ssize_t	bytes_read;
	off_t	tmp_size;

	if (options->hash == 1) {
		if (options->flags & FLAG_P) {
			md5_digest(options->tmp_fd);
			close(options->tmp_fd);
		}
		for (int i = 0; options->inputs[i] != NULL; i++) {
			int fd = open(options->inputs[i], O_RDONLY);
			if (fd == -1) {
				ft_error("ft_ssl: Error: Unable to open file '");
				ft_error(options->inputs[i]);
				ft_error("'.\n");
				return 1;
			}
			if (md5_digest(fd)) {
				close(fd);
				return 1;
			}
			close(fd);
		}	
	}
	return 0;
}

int	main(int ac, char **av) {
	if (ac < 2) {
		ft_error("usage: ft_ssl command [flags] [file/string]\n");
		return (1);
	}

	t_options options = {0, 0, -1, NULL};
	if (verify_args(ac, av, &options)) {
		ft_error("\nCommands:\nmd5\nsha256\n\nFlags:\n-p -q -r -s\n");
		return (1);
	}

	if (load(&options)) {
		free(options.inputs);
		return (1);
	}

	if (process(&options)) {
		free(options.inputs);
		close(options.tmp_fd);
		return (1);
	}

	//////// Debug: print parsed options
	printf("Hash: %s\n", options.hash == 1 ? "md5" : "sha256");
	printf("Flags: %s%s%s%s\n",
		(options.flags & FLAG_P) ? "-p " : "",
		(options.flags & FLAG_Q) ? "-q " : "",
		(options.flags & FLAG_R) ? "-r " : "",
		(options.flags & FLAG_S) ? "-s " : ""
	);
	printf("Inputs:\n");
	for (int i = 0; options.inputs[i] != NULL; i++) {
		printf(" - %s\n", options.inputs[i]);
	}
	/////////

	free(options.inputs);
	return (0);
}
