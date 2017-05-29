SIGNAL_DIR=libsignal-protocol-c
SIGNAL_FLAGS=\
	-I$(SIGNAL_DIR)/src \
	-I$(SIGNAL_DIR)/src/curve25519/ed25519 \
	-I$(SIGNAL_DIR)/src/curve25519/ed25519/additions \
	-I$(SIGNAL_DIR)/src/curve25519/ed25519/nacl_includes \
	-I$(SIGNAL_DIR)/tests \
	-I. \
	-L$(SIGNAL_DIR)/build/src \
	-lsignal-protocol-c 
SODIUM_FLAGS=\
	$(shell pkg-config --cflags libsodium) \
	$(shell pkg-config --libs libsodium)


all: check

test_signal: test_signal.c libsignal-protocol-c/tests/test_common_ccrypto.c
	$(CC) -o $@ $^ $(SIGNAL_FLAGS)

test_sodium: test_sodium.c
	$(CC) -o $@ $^ $(SODIUM_FLAGS)

check: test_signal test_sodium
	./test_sodium
	./test_signal

clean:
	-rm -rf test_sodium test_signal
