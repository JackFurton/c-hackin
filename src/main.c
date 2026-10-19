#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macho.h"

static const char *basename_of(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static void print_version(uint32_t v)
{
    printf("%u.%u.%u", v >> 16, (v >> 8) & 0xff, v & 0xff);
}

static const char *filetype_name(uint32_t t)
{
    switch (t) {
    case MH_OBJECT:      return "MH_OBJECT (relocatable .o)";
    case MH_EXECUTE:     return "MH_EXECUTE (executable)";
    case MH_CORE:        return "MH_CORE (core dump)";
    case MH_DYLIB:       return "MH_DYLIB (shared library)";
    case MH_DYLINKER:    return "MH_DYLINKER (dyld itself)";
    case MH_BUNDLE:      return "MH_BUNDLE (loadable plugin)";
    case MH_DSYM:        return "MH_DSYM (debug info only)";
    case MH_KEXT_BUNDLE: return "MH_KEXT_BUNDLE (kernel extension)";
    case MH_FILESET:     return "MH_FILESET (kernel collection)";
    }
    return "unknown";
}

static const char *platform_name(uint32_t p)
{
    static const char *names[] = {
        NULL, "macOS", "iOS", "tvOS", "watchOS", "bridgeOS", "Mac Catalyst",
        "iOS simulator", "tvOS simulator", "watchOS simulator", "DriverKit",
        "visionOS", "visionOS simulator",
    };
    return p < sizeof names / sizeof *names && names[p] ? names[p] : "unknown";
}

static void print_flags(uint32_t flags)
{
    static const struct { uint32_t bit; const char *name; } table[] = {
        {MH_NOUNDEFS, "NOUNDEFS"},
        {MH_DYLDLINK, "DYLDLINK"},
        {MH_TWOLEVEL, "TWOLEVEL"},
        {MH_SUBSECTIONS_VIA_SYMBOLS, "SUBSECTIONS_VIA_SYMBOLS"},
        {MH_WEAK_DEFINES, "WEAK_DEFINES"},
        {MH_BINDS_TO_WEAK, "BINDS_TO_WEAK"},
        {MH_ALLOW_STACK_EXECUTION, "ALLOW_STACK_EXECUTION"},
        {MH_PIE, "PIE"},
        {MH_HAS_TLV_DESCRIPTORS, "HAS_TLV_DESCRIPTORS"},
        {MH_NO_HEAP_EXECUTION, "NO_HEAP_EXECUTION"},
        {MH_APP_EXTENSION_SAFE, "APP_EXTENSION_SAFE"},
        {MH_DYLIB_IN_CACHE, "DYLIB_IN_CACHE"},
    };
    for (size_t i = 0; i < sizeof table / sizeof *table; i++) {
        if (flags & table[i].bit) {
            printf(" %s", table[i].name);
            flags &= ~table[i].bit;
        }
    }
    if (flags)
        printf(" 0x%x", flags);
    putchar('\n');
}

static const char *lc_name(uint32_t cmd)
{
    switch (cmd) {
    case LC_SEGMENT:                  return "LC_SEGMENT";
    case LC_SYMTAB:                   return "LC_SYMTAB";
    case LC_THREAD:                   return "LC_THREAD";
    case LC_UNIXTHREAD:               return "LC_UNIXTHREAD";
    case LC_DYSYMTAB:                 return "LC_DYSYMTAB";
    case LC_LOAD_DYLIB:               return "LC_LOAD_DYLIB";
    case LC_ID_DYLIB:                 return "LC_ID_DYLIB";
    case LC_LOAD_DYLINKER:            return "LC_LOAD_DYLINKER";
    case LC_ID_DYLINKER:              return "LC_ID_DYLINKER";
    case LC_SUB_FRAMEWORK:            return "LC_SUB_FRAMEWORK";
    case LC_LOAD_WEAK_DYLIB:          return "LC_LOAD_WEAK_DYLIB";
    case LC_SEGMENT_64:               return "LC_SEGMENT_64";
    case LC_ROUTINES_64:              return "LC_ROUTINES_64";
    case LC_UUID:                     return "LC_UUID";
    case LC_RPATH:                    return "LC_RPATH";
    case LC_CODE_SIGNATURE:           return "LC_CODE_SIGNATURE";
    case LC_SEGMENT_SPLIT_INFO:       return "LC_SEGMENT_SPLIT_INFO";
    case LC_REEXPORT_DYLIB:           return "LC_REEXPORT_DYLIB";
    case LC_LAZY_LOAD_DYLIB:          return "LC_LAZY_LOAD_DYLIB";
    case LC_ENCRYPTION_INFO:          return "LC_ENCRYPTION_INFO";
    case LC_DYLD_INFO:                return "LC_DYLD_INFO";
    case LC_DYLD_INFO_ONLY:           return "LC_DYLD_INFO_ONLY";
    case LC_LOAD_UPWARD_DYLIB:        return "LC_LOAD_UPWARD_DYLIB";
    case LC_VERSION_MIN_MACOSX:       return "LC_VERSION_MIN_MACOSX";
    case LC_VERSION_MIN_IPHONEOS:     return "LC_VERSION_MIN_IPHONEOS";
    case LC_FUNCTION_STARTS:          return "LC_FUNCTION_STARTS";
    case LC_DYLD_ENVIRONMENT:         return "LC_DYLD_ENVIRONMENT";
    case LC_MAIN:                     return "LC_MAIN";
    case LC_DATA_IN_CODE:             return "LC_DATA_IN_CODE";
    case LC_SOURCE_VERSION:           return "LC_SOURCE_VERSION";
    case LC_DYLIB_CODE_SIGN_DRS:      return "LC_DYLIB_CODE_SIGN_DRS";
    case LC_ENCRYPTION_INFO_64:       return "LC_ENCRYPTION_INFO_64";
    case LC_LINKER_OPTION:            return "LC_LINKER_OPTION";
    case LC_LINKER_OPTIMIZATION_HINT: return "LC_LINKER_OPTIMIZATION_HINT";
    case LC_NOTE:                     return "LC_NOTE";
    case LC_BUILD_VERSION:            return "LC_BUILD_VERSION";
    case LC_DYLD_EXPORTS_TRIE:        return "LC_DYLD_EXPORTS_TRIE";
    case LC_DYLD_CHAINED_FIXUPS:      return "LC_DYLD_CHAINED_FIXUPS";
    case LC_FILESET_ENTRY:            return "LC_FILESET_ENTRY";
    case LC_ATOM_INFO:                return "LC_ATOM_INFO";
    }
    return NULL;
}

static const char *section_type_name(uint32_t flags)
{
    switch (flags & SECTION_TYPE) {
    case S_REGULAR:                  return "regular";
    case S_ZEROFILL:                 return "zerofill";
    case S_CSTRING_LITERALS:         return "cstrings";
    case S_4BYTE_LITERALS:           return "4byte_literals";
    case S_8BYTE_LITERALS:           return "8byte_literals";
    case S_16BYTE_LITERALS:          return "16byte_literals";
    case S_LITERAL_POINTERS:         return "literal_ptrs";
    case S_NON_LAZY_SYMBOL_POINTERS: return "got";
    case S_LAZY_SYMBOL_POINTERS:     return "lazy_ptrs";
    case S_SYMBOL_STUBS:             return "stubs";
    case S_MOD_INIT_FUNC_POINTERS:   return "init_funcs";
    case S_MOD_TERM_FUNC_POINTERS:   return "term_funcs";
    case S_COALESCED:                return "coalesced";
    case S_GB_ZEROFILL:              return "gb_zerofill";
    case S_INTERPOSING:              return "interposing";
    case S_THREAD_LOCAL_REGULAR:     return "tlv_data";
    case S_THREAD_LOCAL_ZEROFILL:    return "tlv_zerofill";
    case S_THREAD_LOCAL_VARIABLES:   return "tlv_vars";
    case S_INIT_FUNC_OFFSETS:        return "init_offsets";
    }
    return "other";
}

static const char *prot_str(int32_t p)
{
    static char buf[4];
    buf[0] = p & VM_PROT_READ ? 'r' : '-';
    buf[1] = p & VM_PROT_WRITE ? 'w' : '-';
    buf[2] = p & VM_PROT_EXECUTE ? 'x' : '-';
    return buf;
}

#define AS(T, v)                                          \
    const T *v = (const T *)(const void *)lc;             \
    if (lc->cmdsize < sizeof(T)) {                        \
        printf("<truncated>");                            \
        return;                                           \
    }

static void lc_details(const struct load_command *lc)
{
    switch (lc->cmd) {
    case LC_SEGMENT_64: {
        AS(struct segment_command_64, s);
        printf("%-16.16s vm 0x%" PRIx64 "-0x%" PRIx64 "  file 0x%" PRIx64 "-0x%" PRIx64 "  %s  %u sects",
               s->segname, s->vmaddr, s->vmaddr + s->vmsize, s->fileoff, s->fileoff + s->filesize,
               prot_str(s->initprot), s->nsects);
        break;
    }
    case LC_SYMTAB: {
        AS(struct symtab_command, s);
        printf("%u symbols at 0x%x, strings 0x%x (%u bytes)", s->nsyms, s->symoff, s->stroff, s->strsize);
        break;
    }
    case LC_DYSYMTAB: {
        AS(struct dysymtab_command, d);
        printf("locals %u, exported %u, imported %u, indirect %u",
               d->nlocalsym, d->nextdefsym, d->nundefsym, d->nindirectsyms);
        break;
    }
    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB:
    case LC_REEXPORT_DYLIB:
    case LC_LAZY_LOAD_DYLIB:
    case LC_LOAD_UPWARD_DYLIB:
    case LC_ID_DYLIB: {
        AS(struct dylib_command, d);
        printf("%s  (", macho_lc_str(lc, d->dylib.name));
        print_version(d->dylib.current_version);
        putchar(')');
        break;
    }
    case LC_LOAD_DYLINKER:
    case LC_ID_DYLINKER: {
        AS(struct dylinker_command, d);
        printf("%s", macho_lc_str(lc, d->name));
        break;
    }
    case LC_RPATH: {
        AS(struct rpath_command, r);
        printf("%s", macho_lc_str(lc, r->path));
        break;
    }
    case LC_UUID: {
        AS(struct uuid_command, u);
        for (int i = 0; i < 16; i++)
            printf("%s%02X", i == 4 || i == 6 || i == 8 || i == 10 ? "-" : "", u->uuid[i]);
        break;
    }
    case LC_MAIN: {
        AS(struct entry_point_command, e);
        printf("entryoff 0x%" PRIx64 "  stacksize 0x%" PRIx64, e->entryoff, e->stacksize);
        break;
    }
    case LC_BUILD_VERSION: {
        AS(struct build_version_command, b);
        printf("%s min ", platform_name(b->platform));
        print_version(b->minos);
        printf("  sdk ");
        print_version(b->sdk);
        break;
    }
    case LC_SOURCE_VERSION: {
        AS(struct source_version_command, s);
        uint64_t v = s->version;
        printf("%" PRIu64 ".%" PRIu64 ".%" PRIu64 ".%" PRIu64 ".%" PRIu64,
               v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff);
        break;
    }
    case LC_ENCRYPTION_INFO_64: {
        AS(struct encryption_info_command_64, e);
        printf("cryptoff 0x%x  cryptsize 0x%x  cryptid %u%s", e->cryptoff, e->cryptsize, e->cryptid,
               e->cryptid ? "  (encrypted!)" : "");
        break;
    }
    case LC_DYLD_INFO:
    case LC_DYLD_INFO_ONLY: {
        AS(struct dyld_info_command, d);
        printf("rebase %u, bind %u, weak %u, lazy %u, export %u bytes",
               d->rebase_size, d->bind_size, d->weak_bind_size, d->lazy_bind_size, d->export_size);
        break;
    }
    case LC_CODE_SIGNATURE:
    case LC_FUNCTION_STARTS:
    case LC_DATA_IN_CODE:
    case LC_SEGMENT_SPLIT_INFO:
    case LC_DYLIB_CODE_SIGN_DRS:
    case LC_LINKER_OPTIMIZATION_HINT:
    case LC_DYLD_EXPORTS_TRIE:
    case LC_DYLD_CHAINED_FIXUPS:
    case LC_ATOM_INFO: {
        AS(struct linkedit_data_command, d);
        printf("__LINKEDIT 0x%x (%u bytes)", d->dataoff, d->datasize);
        break;
    }
    }
}

static int cmd_info(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    const struct mach_header_64 *h = m->hdr;

    printf("file      %s\n", m->path);
    if (m->nslices) {
        printf("format    fat, %d slices:", m->nslices);
        for (int i = 0; i < m->nslices; i++)
            printf(" %s%s", macho_arch_name(m->slices[i].cputype, m->slices[i].cpusubtype),
                   i == m->slice ? "*" : "");
        printf("  (* selected, pick with -a)\n");
    } else {
        printf("format    thin 64-bit Mach-O\n");
    }
    printf("arch      %s\n", macho_arch_name(h->cputype, h->cpusubtype));
    printf("type      %s\n", filetype_name(h->filetype));
    printf("flags    ");
    print_flags(h->flags);
    printf("commands  %u (%u bytes)\n", h->ncmds, h->sizeofcmds);

    uint64_t entry;
    if (m->has_entry && macho_off_to_vm(m, m->entryoff, &entry) == 0) {
        const macho_sym *s = macho_sym_at(m, entry);
        printf("entry     0x%" PRIx64 "%s%s\n", entry, s ? "  " : "", s ? s->name : "");
    }

    for (uint32_t i = 0; i < m->nlcs; i++) {
        const struct load_command *lc = m->lcs[i];
        const char *label = NULL;
        switch (lc->cmd) {
        case LC_UUID:              label = "uuid"; break;
        case LC_BUILD_VERSION:     label = "platform"; break;
        case LC_LOAD_DYLINKER:     label = "loader"; break;
        case LC_RPATH:             label = "rpath"; break;
        case LC_CODE_SIGNATURE:    label = "codesig"; break;
        case LC_ENCRYPTION_INFO_64: label = "crypt"; break;
        }
        if (label) {
            printf("%-9s ", label);
            lc_details(lc);
            putchar('\n');
        }
    }

    printf("symbols   %zu (%u incl. debug stabs)\n", m->nsorted, m->nsyms);
    if (m->ndylibs)
        printf("libraries\n");
    for (int i = 1; i <= m->ndylibs; i++) {
        const macho_dylib *d = &m->dylibs[i];
        printf("  %2d  %s  ", i, d->name);
        print_version(d->current_version);
        if (d->cmd == LC_LOAD_WEAK_DYLIB)
            printf("  (weak)");
        else if (d->cmd == LC_REEXPORT_DYLIB)
            printf("  (re-export)");
        putchar('\n');
    }
    return 0;
}

static int cmd_lc(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    for (uint32_t i = 0; i < m->nlcs; i++) {
        const struct load_command *lc = m->lcs[i];
        const char *name = lc_name(lc->cmd);
        char unknown[24];
        if (!name) {
            snprintf(unknown, sizeof unknown, "LC_0x%x", lc->cmd);
            name = unknown;
        }
        printf("%3u  0x%04tx  %-27s %5u  ", i, (const uint8_t *)lc - m->base, name, lc->cmdsize);
        lc_details(lc);
        putchar('\n');
    }
    return 0;
}

static int cmd_sections(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    int idx = 1;
    for (int i = 0; i < m->nsegs; i++) {
        const struct segment_command_64 *seg = m->segs[i];
        printf("%-16.16s vm 0x%09" PRIx64 "-0x%09" PRIx64 "  file 0x%07" PRIx64 "-0x%07" PRIx64 "  %s\n",
               seg->segname, seg->vmaddr, seg->vmaddr + seg->vmsize, seg->fileoff,
               seg->fileoff + seg->filesize, prot_str(seg->initprot));
        for (uint32_t j = 0; j < seg->nsects; j++, idx++) {
            const struct section_64 *s = m->sects[idx];
            printf("  [%2d] %-18.16s 0x%09" PRIx64 "  size 0x%-7" PRIx64 " off 0x%-7x %-14s%s\n", idx,
                   s->sectname, s->addr, s->size, s->offset, section_type_name(s->flags),
                   s->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) ? " code" : "");
        }
    }
    return 0;
}

static char sym_letter(const macho *m, const macho_sym *s)
{
    char c;
    switch (s->type & N_TYPE) {
    case N_UNDF: c = s->addr ? 'C' : 'U'; break; /* nonzero value: a common symbol */
    case N_ABS:  c = 'A'; break;
    case N_INDR: c = 'I'; break;
    case N_SECT: {
        const struct section_64 *sec = s->sect && s->sect <= m->nsects ? m->sects[s->sect] : NULL;
        if (!sec)
            c = '?';
        else if (sec->flags & S_ATTR_PURE_INSTRUCTIONS)
            c = 'T';
        else if (strncmp(sec->sectname, "__data", 16) == 0)
            c = 'D';
        else if (strncmp(sec->sectname, "__bss", 16) == 0)
            c = 'B';
        else
            c = 'S';
        break;
    }
    default: c = '?';
    }
    return (s->type & N_EXT) || c == '?' ? c : (char)tolower(c);
}

static const char *import_source(const macho *m, const macho_sym *s)
{
    if (!(m->hdr->flags & MH_TWOLEVEL))
        return "flat namespace";
    unsigned ord = GET_LIBRARY_ORDINAL(s->desc);
    switch (ord) {
    case SELF_LIBRARY_ORDINAL:   return "self";
    case DYNAMIC_LOOKUP_ORDINAL: return "dynamic lookup";
    case EXECUTABLE_ORDINAL:     return "main executable";
    }
    return (int)ord <= m->ndylibs ? basename_of(m->dylibs[ord].name) : "bad ordinal";
}

static int cmd_syms(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    if (!m->nsorted) {
        puts("no symbols");
        return 0;
    }
    size_t defined = 0, imported = 0;
    for (size_t i = 0; i < m->nsorted; i++) {
        const macho_sym *s = &m->syms[i];
        int undef = (s->type & N_TYPE) == N_UNDF;
        if (undef)
            printf("%16s  %c %s  (%s)\n", "", sym_letter(m, s), s->name, import_source(m, s));
        else
            printf("%016" PRIx64 "  %c %s\n", s->addr, sym_letter(m, s), s->name);
        undef ? imported++ : defined++;
    }
    printf("\n%zu defined, %zu imported\n", defined, imported);
    return 0;
}

static int cmd_funcs(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    if (!m->function_starts) {
        puts("no LC_FUNCTION_STARTS in this binary");
        return 0;
    }
    uint64_t *starts;
    size_t n;
    if (macho_function_starts(m, &starts, &n) < 0) {
        fprintf(stderr, "pry: malformed LC_FUNCTION_STARTS\n");
        return 1;
    }

    size_t unnamed = 0;
    printf("%-18s %8s  %s\n", "ADDRESS", "SIZE", "NAME");
    for (size_t i = 0; i < n; i++) {
        /* A function runs to the next start or the end of its section, whichever is first. */
        const struct section_64 *sec = macho_section_at_vm(m, starts[i]);
        uint64_t end = sec ? sec->addr + sec->size : starts[i];
        if (i + 1 < n && starts[i + 1] < end)
            end = starts[i + 1];

        const macho_sym *s = macho_sym_at(m, starts[i]);
        printf("0x%016" PRIx64 " %8" PRIu64 "  ", starts[i], end - starts[i]);
        if (s) {
            puts(s->name);
        } else {
            printf("sub_%" PRIx64 "\n", starts[i]);
            unnamed++;
        }
    }
    printf("\n%zu functions, %zu without a symbol\n", n, unnamed);
    free(starts);
    return 0;
}

static void print_escaped(const uint8_t *s, size_t n)
{
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        switch (c) {
        case '\n': fputs("\\n", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        default:
            if (c >= 0x20 && c < 0x7f)
                putchar(c);
            else
                printf("\\x%02x", c);
        }
    }
    putchar('"');
}

static int cmd_strings(const macho *m, int argc, char **argv)
{
    (void)argc, (void)argv;
    for (int i = 1; i <= m->nsects; i++) {
        const struct section_64 *sec = m->sects[i];
        if ((sec->flags & SECTION_TYPE) != S_CSTRING_LITERALS)
            continue;
        const uint8_t *d = macho_section_data(m, sec);
        if (!d)
            continue;
        for (uint64_t off = 0; off < sec->size;) {
            uint64_t start = off;
            while (off < sec->size && d[off])
                off++;
            if (off > start) {
                printf("0x%09" PRIx64 "  %.16s,%-12.16s ", sec->addr + start, sec->segname, sec->sectname);
                print_escaped(d + start, off - start);
                putchar('\n');
            }
            off++;
        }
    }
    return 0;
}

static void hexdump(const uint8_t *p, uint64_t len, uint64_t addr)
{
    for (uint64_t i = 0; i < len; i += 16) {
        printf("%016" PRIx64 "  ", addr + i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", p[i + j]);
            else
                fputs("   ", stdout);
            if (j == 7)
                putchar(' ');
        }
        fputs(" |", stdout);
        for (uint64_t j = 0; j < 16 && i + j < len; j++)
            putchar(p[i + j] >= 0x20 && p[i + j] < 0x7f ? p[i + j] : '.');
        puts("|");
    }
}

static int cmd_hex(const macho *m, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "usage: pry hex <file> <addr | symbol | seg,sect> [len]\n");
        return 2;
    }
    const char *t = argv[0];
    uint64_t addr, len = 128;
    int have_len = argc > 1;
    if (have_len)
        len = strtoull(argv[1], NULL, 0);

    const char *comma = strchr(t, ',');
    if (comma) {
        char seg[17] = {0};
        size_t sl = (size_t)(comma - t);
        if (sl > 16) {
            fprintf(stderr, "pry: segment name too long\n");
            return 1;
        }
        memcpy(seg, t, sl);
        const struct section_64 *s = macho_section_named(m, seg, comma + 1);
        if (!s) {
            fprintf(stderr, "pry: no section %s\n", t);
            return 1;
        }
        addr = s->addr;
        if (!have_len)
            len = s->size;
    } else if (isdigit((unsigned char)t[0])) {
        char *end;
        addr = strtoull(t, &end, 0);
        if (*end) {
            fprintf(stderr, "pry: bad address %s\n", t);
            return 1;
        }
    } else {
        const macho_sym *s = macho_sym_named(m, t);
        if (!s || (s->type & N_TYPE) != N_SECT) {
            fprintf(stderr, "pry: no defined symbol %s\n", t);
            return 1;
        }
        addr = s->addr;
    }

    uint64_t avail;
    const uint8_t *p = macho_vm_bytes(m, addr, &avail);
    if (!p) {
        fprintf(stderr, "pry: 0x%" PRIx64 " has no file bytes (unmapped or zero-fill)\n", addr);
        return 1;
    }
    if (len > avail)
        len = avail;
    hexdump(p, len, addr);
    return 0;
}

static const struct {
    const char *name;
    int (*fn)(const macho *, int, char **);
    const char *help;
} commands[] = {
    {"info",     cmd_info,     "header, arch, entry point, linked libraries"},
    {"lc",       cmd_lc,       "every load command, in file order"},
    {"sections", cmd_sections, "segments and the sections inside them"},
    {"syms",     cmd_syms,     "symbol table sorted by address, imports with their dylib"},
    {"funcs",    cmd_funcs,    "function starts, which survive stripping"},
    {"strings",  cmd_strings,  "C string literals with their addresses"},
    {"hex",      cmd_hex,      "hexdump: hex <file> <addr | symbol | seg,sect> [len]"},
};

static void usage(FILE *f)
{
    fprintf(f, "usage: pry [-a arch] <command> <file> [args]\n\ncommands:\n");
    for (size_t i = 0; i < sizeof commands / sizeof *commands; i++)
        fprintf(f, "  %-9s %s\n", commands[i].name, commands[i].help);
}

int main(int argc, char **argv)
{
    const char *arch = NULL;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if ((!strcmp(argv[i], "-a") || !strcmp(argv[i], "--arch")) && i + 1 < argc) {
            arch = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
    }
    if (argc - i < 2) {
        usage(stderr);
        return 2;
    }

    const char *name = argv[i];
    for (size_t c = 0; c < sizeof commands / sizeof *commands; c++) {
        if (strcmp(commands[c].name, name) != 0)
            continue;
        macho m;
        if (macho_open(&m, argv[i + 1], arch) < 0) {
            fprintf(stderr, "pry: %s\n", m.err);
            return 1;
        }
        int rc = commands[c].fn(&m, argc - i - 2, argv + i + 2);
        macho_close(&m);
        return rc;
    }
    fprintf(stderr, "pry: unknown command '%s'\n", name);
    usage(stderr);
    return 2;
}
