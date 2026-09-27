CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter -pthread
LDLIBS ?= -lm -lncursesw

ds3hp: ds3hp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f ds3hp .ds3hp_state

.PHONY: clean
