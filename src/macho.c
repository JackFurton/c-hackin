#include "macho.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__aarch64__) || defined(__arm64__)
#define HOST_CPUTYPE CPU_TYPE_ARM64
#else
#define HOST_CPUTYPE CPU_TYPE_X86_64
#endif

static int fail(macho *m, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m->err, sizeof m->err, fmt, ap);
    va_end(ap);
    return -1;
}

/* The fat header is big-endian on every host, so assemble it a byte at a time. */
static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint64_t be64(const uint8_t *p)
{
    return (uint64_t)be32(p) << 32 | be32(p + 4);
}

/* Every read of file data goes through a bounds check: binaries are hostile input. */
const void *macho_at(const macho *m, uint64_t off, uint64_t len)
{
    if (off > m->size || len > m->size - off)
        return NULL;
    return m->base + off;
}

const char *macho_arch_name(int32_t cputype, int32_t cpusubtype)
{
    uint32_t sub = (uint32_t)cpusubtype & ~CPU_SUBTYPE_MASK;
    switch (cputype) {
    case CPU_TYPE_ARM64:  return sub == CPU_SUBTYPE_ARM64E ? "arm64e" : "arm64";
    case CPU_TYPE_X86_64: return sub == CPU_SUBTYPE_X86_64_H ? "x86_64h" : "x86_64";
    case CPU_TYPE_ARM:    return "arm";
    case CPU_TYPE_X86:    return "i386";
    }
    return "unknown";
}

const char *macho_lc_str(const struct load_command *lc, uint32_t off)
{
    if (off < sizeof *lc || off >= lc->cmdsize)
        return "<bad offset>";
    const char *s = (const char *)lc + off;
    return memchr(s, 0, lc->cmdsize - off) ? s : "<unterminated>";
}

/*
 * fat_header  { magic, nfat_arch }                                     8 bytes
 * fat_arch    { cputype, cpusubtype, offset, size, align }            20 bytes
 * fat_arch_64 { cputype, cpusubtype, offset64, size64, align, pad }   32 bytes
 */
static int pick_slice(macho *m, const char *want)
{
    const uint8_t *f = m->file;
    uint32_t magic = be32(f);

    if (magic != FAT_MAGIC && magic != FAT_MAGIC_64) {
        m->base = f;
        m->size = m->file_size;
        return 0;
    }
    if (m->file_size < 8)
        return fail(m, "truncated fat header");

    uint32_t n = be32(f + 4);
    /* Java .class files also start with 0xcafebabe; there this word is the class version (45+). */
    if (n == 0 || n > MACHO_MAX_SLICES)
        return fail(m, "fat magic but nfat_arch=%u, probably not a Mach-O", n);
    size_t entsz = magic == FAT_MAGIC_64 ? 32 : 20;
    if (8 + n * entsz > m->file_size)
        return fail(m, "truncated fat arch table");

    int pick = -1;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *a = f + 8 + i * entsz;
        macho_slice *s = &m->slices[i];
        s->cputype = (int32_t)be32(a);
        s->cpusubtype = (int32_t)be32(a + 4);
        s->offset = magic == FAT_MAGIC_64 ? be64(a + 8) : be32(a + 8);
        s->size = magic == FAT_MAGIC_64 ? be64(a + 16) : be32(a + 12);
        if (s->offset > m->file_size || s->size > m->file_size - s->offset)
            return fail(m, "fat slice %u lies outside the file", i);
        if (pick < 0 && (want ? strcmp(want, macho_arch_name(s->cputype, s->cpusubtype)) == 0
                              : s->cputype == HOST_CPUTYPE))
            pick = (int)i;
    }
    m->nslices = (int)n;
    if (pick < 0) {
        if (want)
            return fail(m, "no %s slice in this fat file", want);
        pick = 0;
    }
    m->slice = pick;
    m->base = f + m->slices[pick].offset;
    m->size = m->slices[pick].size;
    return 0;
}

static int parse_header(macho *m, const char *want)
{
    const struct mach_header_64 *h = macho_at(m, 0, sizeof *h);
    if (!h)
        return fail(m, "too small for a Mach-O header");
    switch (h->magic) {
    case MH_MAGIC_64: break;
    case MH_MAGIC:    return fail(m, "32-bit Mach-O, only 64-bit is supported");
    case MH_CIGAM:
    case MH_CIGAM_64: return fail(m, "byte-swapped Mach-O, not supported");
    default:          return fail(m, "not a Mach-O file (magic 0x%08x)", h->magic);
    }
    const char *arch = macho_arch_name(h->cputype, h->cpusubtype);
    if (want && !m->nslices && strcmp(want, arch) != 0)
        return fail(m, "file is %s, not %s", arch, want);
    m->hdr = h;
    return 0;
}

#define NEED(type)                                                                   \
    do {                                                                             \
        if (lc->cmdsize < sizeof(type))                                              \
            return fail(m, "%s is too small (%u bytes)", #type, lc->cmdsize);       \
    } while (0)

static int index_load_command(macho *m, const struct load_command *lc)
{
    switch (lc->cmd) {
    case LC_SEGMENT_64: {
        NEED(struct segment_command_64);
        const struct segment_command_64 *seg = (const void *)lc;
        if (seg->nsects > (lc->cmdsize - sizeof *seg) / sizeof(struct section_64))
            return fail(m, "segment %.16s claims %u sections, cmdsize only fits fewer",
                        seg->segname, seg->nsects);
        if (seg->fileoff > m->size || seg->filesize > m->size - seg->fileoff)
            return fail(m, "segment %.16s extends past end of file", seg->segname);
        if (m->nsegs == MACHO_MAX_SEGS)
            return fail(m, "more than %d segments", MACHO_MAX_SEGS);
        m->segs[m->nsegs++] = seg;
        if (strncmp(seg->segname, "__TEXT", sizeof seg->segname) == 0)
            m->text = seg;
        const struct section_64 *sec = (const void *)(seg + 1);
        for (uint32_t j = 0; j < seg->nsects; j++) {
            if (m->nsects == 255)
                return fail(m, "more than 255 sections");
            m->sects[++m->nsects] = &sec[j];
        }
        return 0;
    }
    case LC_SYMTAB: {
        NEED(struct symtab_command);
        const struct symtab_command *st = (const void *)lc;
        m->nlist = macho_at(m, st->symoff, (uint64_t)st->nsyms * sizeof(struct nlist_64));
        m->strtab = macho_at(m, st->stroff, st->strsize);
        if (!m->nlist || !m->strtab)
            return fail(m, "symbol or string table extends past end of file");
        m->nsyms = st->nsyms;
        m->strsize = st->strsize;
        return 0;
    }
    /* Order matters: an import's library ordinal is its dylib's position in this list. */
    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB:
    case LC_REEXPORT_DYLIB:
    case LC_LAZY_LOAD_DYLIB:
    case LC_LOAD_UPWARD_DYLIB: {
        NEED(struct dylib_command);
        const struct dylib_command *d = (const void *)lc;
        if (m->ndylibs == MACHO_MAX_DYLIBS)
            return fail(m, "more than %d dylibs", MACHO_MAX_DYLIBS);
        macho_dylib *dl = &m->dylibs[++m->ndylibs];
        dl->name = macho_lc_str(lc, d->dylib.name);
        dl->cmd = lc->cmd;
        dl->current_version = d->dylib.current_version;
        dl->compat_version = d->dylib.compatibility_version;
        return 0;
    }
    case LC_MAIN:
        NEED(struct entry_point_command);
        m->has_entry = 1;
        m->entryoff = ((const struct entry_point_command *)(const void *)lc)->entryoff;
        return 0;
    case LC_FUNCTION_STARTS: {
        NEED(struct linkedit_data_command);
        const struct linkedit_data_command *ld = (const void *)lc;
        if (!macho_at(m, ld->dataoff, ld->datasize))
            return fail(m, "LC_FUNCTION_STARTS data extends past end of file");
        m->function_starts = ld;
        return 0;
    }
    }
    return 0;
}

static int parse_load_commands(macho *m)
{
    const struct mach_header_64 *h = m->hdr;
    uint64_t off = sizeof *h;
    uint64_t end = off + h->sizeofcmds;

    if (end > m->size)
        return fail(m, "load commands extend past end of file");
    if (h->ncmds > h->sizeofcmds / sizeof(struct load_command))
        return fail(m, "ncmds=%u cannot fit in sizeofcmds=%u", h->ncmds, h->sizeofcmds);
    m->lcs = calloc(h->ncmds ? h->ncmds : 1, sizeof *m->lcs);
    if (!m->lcs)
        return fail(m, "out of memory");

    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (end - off < sizeof(struct load_command))
            return fail(m, "load command %u starts past sizeofcmds", i);
        const struct load_command *lc = (const void *)(m->base + off);
        /* dyld rejects 64-bit load commands whose size isn't a multiple of 8 */
        if (lc->cmdsize < sizeof *lc || lc->cmdsize > end - off || lc->cmdsize % 8)
            return fail(m, "load command %u has bad cmdsize %u", i, lc->cmdsize);
        m->lcs[m->nlcs++] = lc;
        if (index_load_command(m, lc) < 0)
            return -1;
        off += lc->cmdsize;
    }
    return 0;
}

static const char *strtab_name(const macho *m, uint32_t strx)
{
    if (strx >= m->strsize)
        return "<bad strx>";
    const char *s = m->strtab + strx;
    return memchr(s, 0, m->strsize - strx) ? s : "<unterminated>";
}

static int cmp_sym(const void *a, const void *b)
{
    const macho_sym *x = a, *y = b;
    if (x->addr != y->addr)
        return x->addr < y->addr ? -1 : 1;
    return strcmp(x->name, y->name);
}

static int build_symbols(macho *m)
{
    if (!m->nsyms)
        return 0;
    m->syms = malloc(m->nsyms * sizeof *m->syms);
    if (!m->syms)
        return fail(m, "out of memory");
    for (uint32_t i = 0; i < m->nsyms; i++) {
        struct nlist_64 n; /* symoff is file-controlled and need not be 8-aligned */
        memcpy(&n, m->nlist + i * sizeof n, sizeof n);
        if (n.n_type & N_STAB)
            continue;
        macho_sym *s = &m->syms[m->nsorted++];
        s->name = strtab_name(m, n.n_strx);
        s->addr = n.n_value;
        s->type = n.n_type;
        s->sect = n.n_sect;
        s->desc = n.n_desc;
    }
    qsort(m->syms, m->nsorted, sizeof *m->syms, cmp_sym);
    return 0;
}

/* Hostile fat offsets can leave the image misaligned for our struct casts; copy it rather than reject it. */
static int align_image(macho *m)
{
    if (((uintptr_t)m->base & 7) == 0)
        return 0;
    uint8_t *copy = malloc(m->size ? m->size : 1);
    if (!copy)
        return fail(m, "out of memory");
    memcpy(copy, m->base, m->size);
    m->owned = copy;
    m->base = copy;
    return 0;
}

static int parse(macho *m, const char *arch)
{
    if (pick_slice(m, arch) < 0 || align_image(m) < 0 || parse_header(m, arch) < 0 ||
        parse_load_commands(m) < 0 || build_symbols(m) < 0) {
        macho_close(m);
        return -1;
    }
    return 0;
}

int macho_open(macho *m, const char *path, const char *arch)
{
    memset(m, 0, sizeof *m);
    m->path = path;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return fail(m, "%s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int e = errno;
        close(fd);
        return fail(m, "%s: %s", path, strerror(e));
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 4) {
        close(fd);
        return fail(m, "%s: not a regular file big enough to be a binary", path);
    }
    void *p = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return fail(m, "%s: mmap: %s", path, strerror(errno));
    m->file = p;
    m->file_size = (size_t)st.st_size;
    m->mapped = 1;
    return parse(m, arch);
}

int macho_open_mem(macho *m, const uint8_t *data, size_t size, const char *arch)
{
    memset(m, 0, sizeof *m);
    m->path = "<memory>";
    if (size < 4)
        return fail(m, "too small to be a binary");
    m->file = data;
    m->file_size = size;
    return parse(m, arch);
}

void macho_close(macho *m)
{
    if (m->mapped)
        munmap((void *)m->file, m->file_size);
    free(m->owned);
    free(m->lcs);
    free(m->syms);
    m->file = NULL;
    m->mapped = 0;
    m->owned = NULL;
    m->lcs = NULL;
    m->syms = NULL;
}

const uint8_t *macho_vm_bytes(const macho *m, uint64_t addr, uint64_t *avail)
{
    for (int i = 0; i < m->nsegs; i++) {
        const struct segment_command_64 *s = m->segs[i];
        if (addr >= s->vmaddr && addr - s->vmaddr < s->filesize) {
            uint64_t delta = addr - s->vmaddr;
            *avail = s->filesize - delta;
            return m->base + s->fileoff + delta;
        }
    }
    *avail = 0;
    return NULL;
}

int macho_off_to_vm(const macho *m, uint64_t off, uint64_t *addr)
{
    for (int i = 0; i < m->nsegs; i++) {
        const struct segment_command_64 *s = m->segs[i];
        if (off >= s->fileoff && off - s->fileoff < s->filesize) {
            *addr = s->vmaddr + (off - s->fileoff);
            return 0;
        }
    }
    return -1;
}

const struct section_64 *macho_section_at_vm(const macho *m, uint64_t addr)
{
    for (int i = 1; i <= m->nsects; i++) {
        const struct section_64 *s = m->sects[i];
        if (addr >= s->addr && addr - s->addr < s->size)
            return s;
    }
    return NULL;
}

const struct section_64 *macho_section_named(const macho *m, const char *seg, const char *sect)
{
    for (int i = 1; i <= m->nsects; i++) {
        const struct section_64 *s = m->sects[i];
        if (strncmp(s->segname, seg, sizeof s->segname) == 0 &&
            strncmp(s->sectname, sect, sizeof s->sectname) == 0)
            return s;
    }
    return NULL;
}

const uint8_t *macho_section_data(const macho *m, const struct section_64 *s)
{
    switch (s->flags & SECTION_TYPE) {
    case S_ZEROFILL:
    case S_GB_ZEROFILL:
    case S_THREAD_LOCAL_ZEROFILL:
        return NULL;
    }
    return macho_at(m, s->offset, s->size);
}

/* Several symbols can share an address; prefer the exported one. */
const macho_sym *macho_sym_at(const macho *m, uint64_t addr)
{
    size_t lo = 0, hi = m->nsorted;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->syms[mid].addr < addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    const macho_sym *best = NULL;
    for (size_t i = lo; i < m->nsorted && m->syms[i].addr == addr; i++) {
        const macho_sym *s = &m->syms[i];
        if ((s->type & N_TYPE) != N_SECT)
            continue;
        if (!best || ((s->type & N_EXT) && !(best->type & N_EXT)))
            best = s;
    }
    return best;
}

const macho_sym *macho_sym_named(const macho *m, const char *name)
{
    for (size_t i = 0; i < m->nsorted; i++)
        if (strcmp(m->syms[i].name, name) == 0)
            return &m->syms[i];
    return NULL;
}

static int uleb128(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    for (const uint8_t *p = *pp; p < end;) {
        uint8_t b = *p++;
        if (shift > 63 || (shift == 63 && (b & 0x7e)))
            return -1;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *pp = p;
            *out = v;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

/*
 * LC_FUNCTION_STARTS is a run of ULEB128 deltas: the first is relative to the
 * start of __TEXT, each later one to the previous function. The linker emits
 * it so tools can unwind and symbolicate, and `strip` leaves it in place.
 */
int macho_function_starts(const macho *m, uint64_t **out, size_t *count)
{
    *out = NULL;
    *count = 0;
    if (!m->function_starts || !m->text)
        return 0;

    const uint8_t *p = m->base + m->function_starts->dataoff;
    const uint8_t *end = p + m->function_starts->datasize;
    uint64_t addr = m->text->vmaddr;
    size_t cap = 0;

    while (p < end) {
        uint64_t delta;
        if (uleb128(&p, end, &delta) < 0) {
            free(*out);
            *out = NULL;
            *count = 0;
            return -1;
        }
        if (delta == 0) /* zero padding up to pointer alignment */
            break;
        addr += delta;
        if (*count == cap) {
            cap = cap ? cap * 2 : 64;
            uint64_t *grown = realloc(*out, cap * sizeof **out);
            if (!grown) {
                free(*out);
                *out = NULL;
                *count = 0;
                return -1;
            }
            *out = grown;
        }
        (*out)[(*count)++] = addr;
    }
    return 0;
}
