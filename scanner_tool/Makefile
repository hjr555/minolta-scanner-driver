# Makefile for Minolta DiMAGE Scan Dual III (Model #2889 / FS-V3) Standalone Tool & Tests

CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2
LDFLAGS ?= -lm

all: dimage_scan test_protocol

dimage_scan: dimage_scan.c dimage_scan.h
	$(CC) $(CFLAGS) -o $@ dimage_scan.c $(LDFLAGS)

test_protocol: test_protocol.c dimage_scan.c dimage_scan.h
	$(CC) $(CFLAGS) -DDIMAGE_NO_MAIN -o $@ test_protocol.c dimage_scan.c $(LDFLAGS)

test: test_protocol
	./test_protocol

clean:
	rm -f dimage_scan test_protocol *.o *.exe
