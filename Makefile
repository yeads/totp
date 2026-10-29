CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -Iinclude $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
CFLAGS ?= -O2 -g
CFLAGS += -std=c99 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lssl -lcrypto)
PREFIX ?= /usr/local
CORE = src/totp.c src/vault.c
OBJ = build/main.o build/ui.o build/totp.o build/vault.o

.PHONY: all clean test check sanitize install uninstall
all: dostotp

dostotp: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c include/dostotp.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build:
	mkdir -p $@

build/test_core: tests/test_core.c $(CORE) include/dostotp.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_core.c $(CORE) $(LDLIBS)

test check: build/test_core dostotp
	./build/test_core
	python3 tests/test_tui.py ./dostotp

sanitize: | build
	$(CC) $(CPPFLAGS) -std=c99 -g -O1 -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -o build/test_sanitize tests/test_core.c $(CORE) $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 ./build/test_sanitize

install: dostotp
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 dostotp $(DESTDIR)$(PREFIX)/bin/dostotp

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/dostotp

clean:
	rm -rf build dostotp

-include $(OBJ:.o=.d)
