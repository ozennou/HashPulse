NAME = ft_ssl

OBJS = $(shell find . -name '*.c' | sed 's/\.c/\.o/g' | tr '\n' ' ')

CC = cc -Wall -Wextra -Werror -O3 -funroll-loops #-fsanitize=address
LDFLAGS = -lreadline

HEADERS = $(shell find . -name '*.h' | tr '\n' ' ')

%.o: %.c Makefile $(HEADERS)
	$(CC) -c $< -o $@

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

all: $(NAME)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
