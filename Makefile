CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter -pthread
LDLIBS ?= -lm -lncursesw

cheat-tool: ds3hp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

test:
	sh ./test.sh

clean:
	rm -f cheat-tool ds3hp

.PHONY: clean test
