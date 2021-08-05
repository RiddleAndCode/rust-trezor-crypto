include ./trezor-firmware/crypto/Makefile

BARE_SRCS = $(SRCS:.c=)

.PHONY: src-list
src-list:
	@for src in $(BARE_SRCS) ; do \
		echo "\"$$src\"," ; \
	done
