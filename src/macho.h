#ifndef MACHO_H
#define MACHO_H

#include <stddef.h>
#include <stdint.h>

#include "macho_format.h"

#define MACHO_MAX_SLICES 16
#define MACHO_MAX_SEGS   32
#define MACHO_MAX_DYLIBS 255

typedef struct {
    int32_t  cputype;
    int32_t  cpusubtype;
    uint64_t offset;
    uint64_t size;
} macho_slice;

typedef struct {
    const char *name;
    uint32_t    cmd; /* LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, ... */
    uint32_t    current_version;
    uint32_t    compat_version;
} macho_dylib;

typedef struct {
    const char *name;
    uint64_t    addr;
    uint8_t     type; /* n_type */
    uint8_t     sect; /* 1-based section index, 0 for none */
    uint16_t    desc;
} macho_sym;

typedef struct {
    const char *path;
    const uint8_t *file; /* the whole file, mmap'd or caller-owned */
    size_t         file_size;
    int            mapped;
    uint8_t       *owned; /* aligned copy of the image, when the slice offset wasn't */
    macho_slice slices[MACHO_MAX_SLICES];
    int         nslices; /* 0 for a thin file */
    int         slice;

    /* The selected 64-bit image. Every offset inside a Mach-O, even in a fat
       file, is relative to here. */
    const uint8_t               *base;
    uint64_t                     size;
    const struct mach_header_64 *hdr;

    const struct load_command **lcs;
    uint32_t                    nlcs;

    const struct segment_command_64 *segs[MACHO_MAX_SEGS];
    int                              nsegs;
    const struct segment_command_64 *text;

    /* Indexed the way n_sect and library ordinals are: from 1. */
    const struct section_64 *sects[256];
    int                      nsects;
    macho_dylib              dylibs[MACHO_MAX_DYLIBS + 1];
    int                      ndylibs;

    const uint8_t         *nlist; /* raw nlist_64 array, possibly misaligned */
    uint32_t               nsyms;
    const char            *strtab;
    uint32_t               strsize;
    macho_sym             *syms; /* non-debug symbols, sorted by address */
    size_t                 nsorted;

    int                                 has_entry;
    uint64_t                            entryoff;
    const struct linkedit_data_command *function_starts;

    char err[256];
} macho;

int  macho_open(macho *m, const char *path, const char *arch);
int  macho_open_mem(macho *m, const uint8_t *data, size_t size, const char *arch);
void macho_close(macho *m);

const void    *macho_at(const macho *m, uint64_t off, uint64_t len);
const uint8_t *macho_vm_bytes(const macho *m, uint64_t addr, uint64_t *avail);
int            macho_off_to_vm(const macho *m, uint64_t off, uint64_t *addr);

const struct section_64 *macho_section_at_vm(const macho *m, uint64_t addr);
const struct section_64 *macho_section_named(const macho *m, const char *seg, const char *sect);
const uint8_t           *macho_section_data(const macho *m, const struct section_64 *s);

const macho_sym *macho_sym_at(const macho *m, uint64_t addr);
const macho_sym *macho_sym_named(const macho *m, const char *name);

int macho_function_starts(const macho *m, uint64_t **out, size_t *count);

const char *macho_arch_name(int32_t cputype, int32_t cpusubtype);
const char *macho_lc_str(const struct load_command *lc, uint32_t offset);

#endif
