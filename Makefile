CC      ?= cc
CFLAGS  ?= -std=gnu11 -Wall -Wextra -Wpedantic -Wshadow -O1 -g
# Sanitizers stay on while we write parsers: malformed binaries should fail loudly, not corrupt memory.
SAN     ?= -fsanitize=address,undefined -fno-omit-frame-pointer

SRC := $(wildcard src/*.c)
HDR := $(wildcard src/*.h)

build/pry: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(SAN) -o $@ $(SRC)

release: SAN :=
release: CFLAGS := -std=gnu11 -O2
release: clean build/pry

samples: build/samples/crackme0 build/samples/crackme0.stripped

build/samples/crackme0: samples/crackme0.c
	@mkdir -p build/samples
	$(CC) -O0 -o $@ $<

build/samples/crackme0.stripped: build/samples/crackme0
	strip -o $@ $<

# Apple clang ships no libFuzzer runtime; Homebrew's llvm does.
FUZZ_CC ?= $(shell brew --prefix llvm 2>/dev/null)/bin/clang
LIB_SRC := $(filter-out src/main.c,$(SRC))

build/fuzz_macho: fuzz/fuzz_macho.c $(LIB_SRC) $(HDR)
	@mkdir -p build
	$(FUZZ_CC) -std=gnu11 -g -O1 $(EXTRA_CFLAGS) -fsanitize=fuzzer,address,undefined -o $@ fuzz/fuzz_macho.c $(LIB_SRC)

fuzz: build/fuzz_macho samples
	@mkdir -p build/corpus
	cp build/samples/crackme0 build/samples/crackme0.stripped build/corpus/
	build/fuzz_macho -max_total_time=$${FUZZ_SECONDS:-60} build/corpus

test: build/pry samples
	tests/smoke.sh

clean:
	rm -rf build

.PHONY: release samples fuzz test clean
