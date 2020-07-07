OBJS = guess_password.c
CC = aarch64-linux-gnu-gcc
COMPILER_FLAGS = -Wall
OBJ_NAME = guess_password

all : $(OBJS)
	$(CC) $(OBJS) $(COMPILER_FLAGS) -o $(OBJ_NAME)

nopie : $(OBJS)
	$(CC) $(OBJS) $(COMPILER_FLAGS) -no-pie -o $(OBJ_NAME)_nopie
