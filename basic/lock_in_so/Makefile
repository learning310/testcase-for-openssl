# Makefile for building shared library and executable

# Compiler and flags
CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS = -shared -lpthread -ldl

# Shared library
LIBRARY_NAME = libmylib.so
LIBRARY_SRC = mylib.c
LIBRARY_OBJ = mylib.o

# Executable
EXECUTABLE_NAME = main
EXECUTABLE_SRC = main.c

# Build targets
all: $(LIBRARY_NAME) $(EXECUTABLE_NAME)

# Build shared library
$(LIBRARY_NAME): $(LIBRARY_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(LIBRARY_OBJ)

$(LIBRARY_OBJ): $(LIBRARY_SRC)
	$(CC) $(CFLAGS) -c $(LIBRARY_SRC)

# Build executable
$(EXECUTABLE_NAME): $(EXECUTABLE_SRC) $(LIBRARY_NAME)
	$(CC) -o $@ $(EXECUTABLE_SRC) -ldl -lpthread

# Clean up
clean:
	rm -f $(LIBRARY_NAME) $(EXECUTABLE_NAME) $(LIBRARY_OBJ)

.PHONY: all clean
