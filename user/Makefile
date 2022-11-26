######################################################################
# @author      : fw (fw@$HOSTNAME)
# @file        : Makefile
# @created     : שבת נוב 26, 2022 17:53:45 IST
######################################################################

CC=/usr/bin/gcc
CFLAGS=-Wall -pedantic --std=c99
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXEC=main

.PHONY: clean all debug release

debug: CFLAGS += -O0 -g
debug: $(EXEC)

release: CFLAGS += -O3
release: $(EXEC)

all: debug

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

$(EXEC): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)


clean:
	rm -f $(EXEC) $(OBJECTS)

