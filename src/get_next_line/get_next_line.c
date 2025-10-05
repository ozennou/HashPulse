/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mozennou <mozennou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/02 07:25:36 by mozennou          #+#    #+#             */
/*   Updated: 2023/11/06 21:18:26 by mozennou         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"
#include <string.h>

char	*ft_free(char *res, char *bf, char *bc, int r)
{
	char	*s;

	if (!r)
	{
		s = ft_strjoin(res, bf);
		free(res);
		return (s);
	}
	free(res);
	free(bf);
	free(bc);
	return (NULL);
}

char	*read_fd(int fd, char *bc)
{
	char	*buffer;
	char	*res;
	int		r;

	if (!bc)
		bc = ft_calloc(1, 1);
	if (!bc)
		return (NULL);
	buffer = ft_calloc(BUFFER_SIZE + 1, 1);
	if (!buffer)
		return (NULL);
	r = 1;
	res = ft_strdup(bc);
	while (!ft_strchr(buffer, '\n') && r > 0 && res)
	{
		r = read(fd, buffer, BUFFER_SIZE);
		if (r == -1)
			return (ft_free(res, buffer, bc, 1));
		buffer[r] = 0;
		res = ft_free(res, buffer, bc, 0);
	}
	free(buffer);
	free(bc);
	return (res);
}

char	*get_l(char *bc)
{
	char	*res;
	int		i;

	i = 0;
	if (!bc[i])
		return (NULL);
	while (bc[i] && bc[i] != '\n')
		i++;
	if (bc[i] == '\n')
		res = ft_calloc(i + 2, 1);
	else
		res = ft_calloc(i + 1, 1);
	if (!res)
		return (NULL);
	i = 0;
	while (bc[i] && bc[i] != '\n')
	{
		res[i] = bc[i];
		i++;
	}
	if (bc[i] && bc[i] == '\n')
		res[i++] = '\n';
	res[i] = 0;
	return (res);
}

char	*get_next(char *bc)
{
	int		i;
	int		j;
	char	*res;

	i = 0;
	while (bc[i] && bc[i] != '\n')
		i++;
	if (!bc[i])
	{
		free(bc);
		return (NULL);
	}
	res = ft_calloc(ft_strlen(bc) - i++, 1);
	if (!res)
		return (NULL);
	j = 0;
	while (bc[i])
		res[j++] = bc[i++];
	res[j] = 0;
	free(bc);
	return (res);
}

char	*get_next_line(int fd)
{
	static char	*backup;
	char		*res;

	if (fd < 0 || BUFFER_SIZE <= 0)
		return (NULL);
	backup = read_fd(fd, backup);
	if (!backup)
		return (NULL);
	res = get_l(backup);
	backup = get_next(backup);
	return (res);
}
