/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line_utils.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mozennou <mozennou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/02 07:35:53 by mozennou          #+#    #+#             */
/*   Updated: 2023/11/06 21:59:23 by mozennou         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"

size_t	ft_strlen(const char *s)
{
	int	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

void	*ft_calloc(size_t n, size_t s)
{
	void			*res;
	size_t			i;
	unsigned char	*p;

	res = malloc(n * s);
	if (!res)
		return (NULL);
	i = 0;
	p = (unsigned char *)res;
	while (i < n * s)
		p[i++] = '\0';
	return (res);
}

char	*ft_strjoin(char const *a, char const *b)
{
	int		i;
	int		a_ln;
	int		b_ln;
	char	*res;

	a_ln = ft_strlen((char *)a);
	b_ln = ft_strlen((char *)b);
	res = (char *)malloc(a_ln + b_ln + 1);
	if (!res)
		return (res);
	i = -1;
	while (++i < a_ln)
		res[i] = a[i];
	i = -1;
	while (++i < b_ln)
		res[a_ln + i] = b[i];
	res[a_ln + i] = '\0';
	return (res);
}

char	*ft_strchr(const char *s, int c)
{
	int	i;

	i = 0;
	while (s[i] != (char)c)
	{
		if (s[i] == '\0')
			return (NULL);
		i++;
	}
	return ((char *)&s[i]);
}

char	*ft_strdup(const char *s)
{
	char	*res;
	int		len;
	int		i;

	i = -1;
	len = ft_strlen((char *)s);
	res = (char *)malloc(len + 1);
	if (res == NULL)
		return (NULL);
	while (++i < len)
		res[i] = s[i];
	res[i] = '\0';
	return (res);
}
