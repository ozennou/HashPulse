NAME = ft_ssl

OBJS = $(shell find . -name '*.c' | sed 's/\.c/\.o/g' | tr '\n' ' ')

CC = cc #-Wall -Wextra -Werror

HEADERS = $(shell find . -name '*.h' | tr '\n' ' ')

%.o: %.c Makefile $(HEADERS)
	$(CC) -c $< -o $@

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME)

all: $(NAME)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: clean