#include <stdint.h>
#include <stdlib.h>

#include "../src/arm64.h"
#include "../src/macho.h"

/* Exercise every query a command can make, since those read through parsed offsets. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* The decoder sees every word directly, whether or not the input parses. */
    arm64_insn in;
    for (size_t i = 0; i + 4 <= size; i += 4)
        arm64_decode((uint32_t)data[i] | (uint32_t)data[i + 1] << 8 | (uint32_t)data[i + 2] << 16 |
                         (uint32_t)data[i + 3] << 24,
                     i, &in);

    macho m;
    if (macho_open_mem(&m, data, size, NULL) < 0)
        return 0;

    uint64_t *starts;
    size_t n;
    if (macho_function_starts(&m, &starts, &n) == 0) {
        for (size_t i = 0; i < n; i++) {
            macho_sym_at(&m, starts[i]);
            macho_section_at_vm(&m, starts[i]);
        }
        free(starts);
    }
    for (int i = 1; i <= m.nsects; i++) {
        const uint8_t *d = macho_section_data(&m, m.sects[i]);
        volatile uint8_t sink = 0;
        for (uint64_t j = 0; d && j < m.sects[i]->size; j++)
            sink ^= d[j];
        (void)sink;
    }
    for (size_t i = 0; i < m.nsorted; i++) {
        uint64_t avail;
        macho_vm_bytes(&m, m.syms[i].addr, &avail);
    }
    macho_close(&m);
    return 0;
}
