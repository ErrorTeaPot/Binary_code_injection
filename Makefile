vpath %.c ./src
SRC_FILES := isos_inject.c arg_parser.c
INCLUDE_DIR := include/
CC = gcc
CFLAGS = -Wall -pedantic -Wextra -I$(INCLUDE_DIR) -g -O2
LIBS = -liberty -lz -lbfd

build_dependencies: $(SRC_FILES:%.c=%.dep)
	@cat $^ > make.test
	@rm $^

%.dep: %.c
	@gcc -I$(INCLUDE_DIR) -MM -MF $@ $<

all: objdir copybin bin/isos_inject bin/code_to_inject_entry bin/code_to_inject_got

objdir: 
	@mkdir -p obj

copybin:
	@cp date.backup bin/date

obj/%.o: src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

bin/isos_inject: obj/isos_inject.o obj/arg_parser.o 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

bin/code_to_inject_entry: src/code_to_inject_entry.s
	nasm -f bin src/code_to_inject_entry.s -o bin/code_to_inject_entry

bin/code_to_inject_got: src/code_to_inject_got.s
	nasm -f bin src/code_to_inject_got.s -o bin/code_to_inject_got

clean:
	rm -f obj/*.o bin/*