#MAKEFLAGS += --silent

CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wpedantic 
INC_DIR = includes/

EXE = ft_malcolm

SRC_DIR = ./
SRC =	main.c

LIBRARY_DIR = ./

LIBFT_DIR = $(LIBRARY_DIR)libft/
LIBFT_INC_DIR = $(LIBFT_DIR)includes/
LIBFT_INC = -I $(LIBFT_INC_DIR) $(LIBFT_DIR)libft.a

OBJ = $(SRC:%.c=%.o)

.PHONY : all clean fclean re $(LIBFT_DIR) $(EXE)

all: $(LIBFT_DIR) $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ_DIR)main.o $(LIBFT_INC) -o $(EXE)

$(LIBFT_DIR):
	$(MAKE) -C $(LIBFT_DIR)

%.o: $(SRC_DIR)%.c $(addprefix $(INC_DIR),$(INC))
	$(CC) $(CFLAGS) -c $< -o $@ -I $(LIBFT_INC_DIR) -I $(INC_DIR)

clean:
	/bin/rm -rf *.o
	$(MAKE) -C $(LIBFT_DIR) fclean

fclean: clean
	/bin/rm -f $(EXE)

re: 
	$(MAKE) fclean
	$(MAKE) all
