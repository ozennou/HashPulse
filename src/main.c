#include "ft_ssl.h"

char **verify_args(int ac, char **av, int *flags) {
	char **res = malloc(sizeof(char *) * (ac - 1));
	if (!res)
		return (NULL);
	int j = 0;
	if (ft_strcmp(av[1], "md5") && ft_strcmp(av[1], "sha256")) {
		ft_error("ft_ssl: Error: '");
		ft_error(av[1]);
		ft_error("' is an invalid command.\n");
		free(res);
		return NULL;
	}
	for (int i = 2; i < ac; i++) {
		if (av[i][0] == '-') {
			if (ft_strcmp(av[i], "-p") && ft_strcmp(av[i], "-q") && ft_strcmp(av[i], "-r") && ft_strcmp(av[i], "-s")) {
				ft_error("ft_ssl: Error: '");
				ft_error(av[i]);
				ft_error("' is an invalid flag.\n");
				free(res);
				return NULL;
			}
			if (av[i][1] == 'p') *flags |= FLAG_P;
			if (av[i][1] == 'q') *flags |= FLAG_Q;
			if (av[i][1] == 'r') *flags |= FLAG_R;
			if (av[i][1] == 's') *flags |= FLAG_S;
		}
		else
			res[j++] = av[i];
	}
	res[j] = NULL;
	return (res);
}

int	main(int ac, char **av) {
	if (ac < 2) {
		ft_error("usage: ft_ssl command [flags] [file/string]\n");
		return (1);
	}

	int		flags		= 0;
	char	**file_name	= verify_args(ac, av, &flags);
	if (!file_name) {
		ft_error("\nCommands:\nmd5\nsha256\n\nFlags:\n-p -q -r -s\n");
		return (1);
	}

	char	**content = NULL;
	if (flags & FLAG_S) {
		content = file_name;
		for (int i = 0; content && content[i]; i++) {
			md5_string(content[i], flags);
		}
	}

	// for (int i = 0; file_name && file_name[i]; i++) {
	// 	printf("Processing file: %s\n", file_name[i]);
	// }
	return (0);
}
