CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99 -g \
           -I../components/ckb_core/include \
           -DPOSIX_TEST
LDFLAGS = -lm

SRCS_CORE = \
    ../components/ckb_core/src/ckb_blake2b.c \
    ../components/ckb_core/src/ckb_types.c   \
    ../components/ckb_core/src/ckb_mmr.c

.PHONY: all clean test

all: test_blake2b test_mmr

test_blake2b: test_blake2b.c $(SRCS_CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_mmr: test_mmr.c $(SRCS_CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: all
	@echo ""
	@echo ">>> Running Blake2b tests..."
	@./test_blake2b
	@echo ""
	@echo ">>> Running MMR tests..."
	@./test_mmr

clean:
	rm -f test_blake2b test_mmr *.o
