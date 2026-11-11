#ifndef ARM64_H
#define ARM64_H

#include <stdint.h>

typedef struct {
    char     mnemonic[16];
    char     operands[96];
    char     comment[64]; /* llvm-objdump's trailing "; ..." note, e.g. "=1" after a mov */
    int      has_target;  /* operands end with an address worth symbolizing */
    uint64_t target;
} arm64_insn;

/* Decodes one instruction at pc. Returns 0, or -1 for anything not handled yet,
   which comes back as ".word 0x...". Text follows llvm-objdump so the two diff. */
int arm64_decode(uint32_t word, uint64_t pc, arm64_insn *out);

#endif
