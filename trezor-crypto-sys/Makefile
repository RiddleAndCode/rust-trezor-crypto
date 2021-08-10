include ./trezor-firmware/crypto/Makefile

BARE_SRCS = $(SRCS:.c=)

EXTRA_HEADERS = options aes/aesopt aes/aes ed25519-donna/ed25519-donna ed25519-donna/ed25519-hash-custom-keccak ed25519-donna/ed25519-hash-custom-sha3 ed25519-donna/ed25519-hash-custom
IGNORE_HEADERS = aes/aescrypt aes/aeskey aes/aes_modes aes/aestab chacha20poly1305/chacha_merged ed25519-donna/ed25519-donna-32bit-tables ed25519-donna/curve25519-donna-32bit ed25519-donna/modm-donna-32bit ed25519-donna/ed25519-donna-basepoint-table monero/xmr
HEADERS = $(EXTRA_HEADERS) $(filter-out $(IGNORE_HEADERS), $(BARE_SRCS))

.PHONY: src-list
src-list:
	@for src in $(BARE_SRCS) ; do \
		echo "\"$$src.c\"," ; \
	done

.PHONY: header-list
header-list:
	@for src in $(HEADERS) ; do \
		echo "#include <$$src.h>" ; \
	done

.PHONY: prune-submodule
prune-submodule:
	cd trezor-firmware && ls | grep -v crypto | xargs rm -rf
	rm -rf trezor-firmware/.git
