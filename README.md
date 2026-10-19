# pry

[![CI](https://github.com/JackFurton/c-hackin/actions/workflows/ci.yml/badge.svg)](https://github.com/JackFurton/c-hackin/actions/workflows/ci.yml)

A binary analysis tool written from scratch in C: loaders, disassemblers and
analysis passes, no libbfd/capstone/LIEF. Mach-O on arm64 first, since that's
what this machine runs.

```
make            # debug build with ASan/UBSan
make release    # optimized, no sanitizers
make samples    # crackme targets in build/samples
make test       # smoke tests against nm/otool (macOS)
make fuzz       # libFuzzer, needs brew llvm; FUZZ_SECONDS=600 for longer
```

```
pry [-a arch] <command> <file> [args]

info       header, arch, entry point, linked libraries
lc         every load command, in file order
sections   segments and the sections inside them
syms       symbol table sorted by address, imports with their dylib
funcs      function starts, which survive stripping
strings    C string literals with their addresses
hex        hexdump: hex <file> <addr | symbol | seg,sect> [len]
```

Fat binaries pick the host's slice by default; `-a x86_64` picks another.

## Roadmap

1. Mach-O loader: done
2. ARM64 disassembler, differential-tested against `llvm-objdump`
3. Chained fixups and stubs, so calls resolve to `_printf` rather than an address
4. Function discovery, basic blocks, CFG, xrefs
5. ELF loader, x86-64 decoder
6. IR lifting and a decompiler
