CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99 -g \
           -I../components/ckb_core/include \
           -I../components/ckb_transport/include \
           -DPOSIX_TEST
LDFLAGS = -lm

# Phase 4: live connection (needs OpenSSL + libsecp256k1)
CFLAGS_LIVE = $(CFLAGS) \
              -I../components/ckb_protocol/include \
              -Wno-deprecated-declarations \
              $(shell pkg-config --cflags openssl 2>/dev/null) \
              $(shell pkg-config --cflags libsecp256k1 2>/dev/null || echo "-I/usr/include")
LDFLAGS_LIVE = $(LDFLAGS) -lssl -lcrypto -lsecp256k1

SRCS_CORE = \
    ../components/ckb_core/src/ckb_blake2b.c \
    ../components/ckb_core/src/ckb_types.c   \
    ../components/ckb_core/src/ckb_mmr.c

SRCS_TRANSPORT = \
    ../components/ckb_transport/src/ckb_molecule.c \
    ../components/ckb_transport/src/ckb_yamux.c    \
    ../components/ckb_transport/src/ckb_secio.c

SRCS_PROTOCOL = \
    ../components/ckb_protocol/src/ckb_protocol.c

.PHONY: all clean test live

all: test_blake2b test_mmr test_transport test_protocol

test_blake2b: test_blake2b.c $(SRCS_CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_mmr: test_mmr.c $(SRCS_CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_transport: test_transport.c $(SRCS_CORE) $(SRCS_TRANSPORT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_protocol: test_protocol.c $(SRCS_CORE) $(SRCS_TRANSPORT) $(SRCS_PROTOCOL)
	$(CC) $(CFLAGS) \
	    -I../components/ckb_protocol/include \
	    -o $@ $^ $(LDFLAGS)

connect_live: connect_live.c crypto_openssl.c $(SRCS_CORE) $(SRCS_TRANSPORT) $(SRCS_PROTOCOL)
	$(CC) $(CFLAGS_LIVE) -o $@ $^ $(LDFLAGS_LIVE)

live: connect_live
	@echo ""
	@echo ">>> Connecting to CKB node..."
	@./connect_live

test: all
	@echo ""
	@echo ">>> Running Blake2b tests..."
	@./test_blake2b
	@echo ""
	@echo ">>> Running MMR tests..."
	@./test_mmr
	@echo ""
	@echo ">>> Running Transport tests..."
	@./test_transport
	@echo ""
	@echo ">>> Running Protocol tests..."
	@./test_protocol

clean:
	rm -f test_blake2b test_mmr test_transport test_protocol connect_live *.o
