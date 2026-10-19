#ifndef MACHO_FORMAT_H
#define MACHO_FORMAT_H

#include <stdint.h>

/*
 * On-disk Mach-O structures, transcribed from Apple's <mach-o/loader.h>,
 * <mach-o/nlist.h> and <mach-o/fat.h>. Defined here rather than included so
 * every field is in front of you and the tool also builds on Linux.
 * All of these are little-endian on disk except the fat header.
 */

/* ---- fat (universal) files: several Mach-Os glued together, one per arch ---- */

#define FAT_MAGIC    0xcafebabeu
#define FAT_MAGIC_64 0xcafebabfu

/* ---- the Mach-O header ---- */

#define MH_MAGIC    0xfeedfaceu /* 32-bit */
#define MH_CIGAM    0xcefaedfeu /* 32-bit, other byte order */
#define MH_MAGIC_64 0xfeedfacfu
#define MH_CIGAM_64 0xcffaedfeu

#define CPU_ARCH_ABI64       0x01000000
#define CPU_TYPE_X86         7
#define CPU_TYPE_ARM         12
#define CPU_TYPE_X86_64      (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64       (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_SUBTYPE_MASK     0xff000000u /* capability bits, e.g. arm64e ptrauth ABI version */
#define CPU_SUBTYPE_ARM64E   2
#define CPU_SUBTYPE_X86_64_H 8

#define MH_OBJECT      0x1
#define MH_EXECUTE     0x2
#define MH_CORE        0x4
#define MH_DYLIB       0x6
#define MH_DYLINKER    0x7
#define MH_BUNDLE      0x8
#define MH_DSYM        0xa
#define MH_KEXT_BUNDLE 0xb
#define MH_FILESET     0xc

#define MH_NOUNDEFS                0x1
#define MH_DYLDLINK                0x4
#define MH_TWOLEVEL                0x80
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000
#define MH_WEAK_DEFINES            0x8000
#define MH_BINDS_TO_WEAK           0x10000
#define MH_ALLOW_STACK_EXECUTION   0x20000
#define MH_PIE                     0x200000
#define MH_HAS_TLV_DESCRIPTORS     0x800000
#define MH_NO_HEAP_EXECUTION       0x1000000
#define MH_APP_EXTENSION_SAFE      0x2000000
#define MH_DYLIB_IN_CACHE          0x80000000u

struct mach_header_64 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;      /* load commands follow the header back to back */
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

/* ---- load commands: a tagged list describing everything else in the file ---- */

#define LC_REQ_DYLD 0x80000000u /* dyld must refuse the binary if it doesn't understand this one */

#define LC_SEGMENT                 0x1
#define LC_SYMTAB                  0x2
#define LC_THREAD                  0x4
#define LC_UNIXTHREAD              0x5
#define LC_DYSYMTAB                0xb
#define LC_LOAD_DYLIB              0xc
#define LC_ID_DYLIB                0xd
#define LC_LOAD_DYLINKER           0xe
#define LC_ID_DYLINKER             0xf
#define LC_SUB_FRAMEWORK           0x12
#define LC_LOAD_WEAK_DYLIB         (0x18 | LC_REQ_DYLD)
#define LC_SEGMENT_64              0x19
#define LC_ROUTINES_64             0x1a
#define LC_UUID                    0x1b
#define LC_RPATH                   (0x1c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE          0x1d
#define LC_SEGMENT_SPLIT_INFO      0x1e
#define LC_REEXPORT_DYLIB          (0x1f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB         0x20
#define LC_ENCRYPTION_INFO         0x21
#define LC_DYLD_INFO               0x22
#define LC_DYLD_INFO_ONLY          (0x22 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB       (0x23 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX      0x24
#define LC_VERSION_MIN_IPHONEOS    0x25
#define LC_FUNCTION_STARTS         0x26
#define LC_DYLD_ENVIRONMENT        0x27
#define LC_MAIN                    (0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE            0x29
#define LC_SOURCE_VERSION          0x2a
#define LC_DYLIB_CODE_SIGN_DRS     0x2b
#define LC_ENCRYPTION_INFO_64      0x2c
#define LC_LINKER_OPTION           0x2d
#define LC_LINKER_OPTIMIZATION_HINT 0x2e
#define LC_NOTE                    0x31
#define LC_BUILD_VERSION           0x32
#define LC_DYLD_EXPORTS_TRIE       (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS     (0x34 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY           (0x35 | LC_REQ_DYLD)
#define LC_ATOM_INFO               0x36

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize; /* includes any trailing strings or section headers */
};

#define VM_PROT_READ    0x1
#define VM_PROT_WRITE   0x2
#define VM_PROT_EXECUTE 0x4

/* A segment maps [fileoff, fileoff+filesize) to [vmaddr, vmaddr+vmsize).
   vmsize > filesize means the tail is zero-filled (that's how .bss works). */
struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16]; /* not NUL-terminated if all 16 bytes are used */
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects; /* this many section_64 follow immediately */
    uint32_t flags;
};

#define SECTION_TYPE              0xff
#define S_REGULAR                 0x0
#define S_ZEROFILL                0x1
#define S_CSTRING_LITERALS        0x2
#define S_4BYTE_LITERALS          0x3
#define S_8BYTE_LITERALS          0x4
#define S_LITERAL_POINTERS        0x5
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define S_LAZY_SYMBOL_POINTERS    0x7
#define S_SYMBOL_STUBS            0x8
#define S_MOD_INIT_FUNC_POINTERS  0x9
#define S_MOD_TERM_FUNC_POINTERS  0xa
#define S_COALESCED               0xb
#define S_GB_ZEROFILL             0xc
#define S_INTERPOSING             0xd
#define S_16BYTE_LITERALS         0xe
#define S_THREAD_LOCAL_REGULAR    0x11
#define S_THREAD_LOCAL_ZEROFILL   0x12
#define S_THREAD_LOCAL_VARIABLES  0x13
#define S_INIT_FUNC_OFFSETS       0x16
#define S_ATTR_PURE_INSTRUCTIONS  0x80000000u
#define S_ATTR_SOME_INSTRUCTIONS  0x00000400u

struct section_64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset; /* file offset; meaningless for zero-fill sections */
    uint32_t align;  /* power of two */
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;  /* low byte is the type, high bits are attributes */
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff; /* array of nsyms nlist_64 */
    uint32_t nsyms;
    uint32_t stroff; /* blob of NUL-terminated names, indexed by n_strx */
    uint32_t strsize;
};

/* The symbol table is sorted into three runs: locals, exported, then imported. */
struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym, nlocalsym;
    uint32_t iextdefsym, nextdefsym;
    uint32_t iundefsym, nundefsym;
    uint32_t tocoff, ntoc;
    uint32_t modtaboff, nmodtab;
    uint32_t extrefsymoff, nextrefsyms;
    uint32_t indirectsymoff, nindirectsyms;
    uint32_t extreloff, nextrel;
    uint32_t locreloff, nlocrel;
};

struct dylib {
    uint32_t name; /* offset of the path string from the start of the load command */
    uint32_t timestamp;
    uint32_t current_version;       /* packed as xxxx.yy.zz */
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t     cmd;
    uint32_t     cmdsize;
    struct dylib dylib;
};

struct dylinker_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name;
};

struct rpath_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t path;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff; /* file offset of main(), not a virtual address */
    uint64_t stacksize;
};

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t  uuid[16];
};

/* Generic "there's a blob in __LINKEDIT at this offset" command. */
struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct build_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos; /* xxxx.yy.zz */
    uint32_t sdk;
    uint32_t ntools;
};

struct source_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t version; /* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
};

struct encryption_info_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid; /* nonzero means the range is still FairPlay-encrypted */
    uint32_t pad;
};

struct dyld_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t rebase_off, rebase_size;
    uint32_t bind_off, bind_size;
    uint32_t weak_bind_off, weak_bind_size;
    uint32_t lazy_bind_off, lazy_bind_size;
    uint32_t export_off, export_size;
};

/* ---- symbols ---- */

#define N_STAB 0xe0 /* any of these bits set: a debugger entry, not a real symbol */
#define N_PEXT 0x10 /* private extern: was global in its .o, hidden after linking */
#define N_TYPE 0x0e
#define N_EXT  0x01

#define N_UNDF 0x0 /* imported, n_sect == NO_SECT */
#define N_ABS  0x2
#define N_INDR 0xa
#define N_PBUD 0xc
#define N_SECT 0xe /* defined in section n_sect (1-based, across all segments) */

/* Imports record which dylib they come from in the high byte of n_desc. */
#define GET_LIBRARY_ORDINAL(desc) (((desc) >> 8) & 0xff)
#define SELF_LIBRARY_ORDINAL   0x0
#define DYNAMIC_LOOKUP_ORDINAL 0xfe
#define EXECUTABLE_ORDINAL     0xff

struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value; /* the address, for defined symbols */
};

_Static_assert(sizeof(struct mach_header_64) == 32, "mach_header_64 layout");
_Static_assert(sizeof(struct segment_command_64) == 72, "segment_command_64 layout");
_Static_assert(sizeof(struct section_64) == 80, "section_64 layout");
_Static_assert(sizeof(struct nlist_64) == 16, "nlist_64 layout");
_Static_assert(sizeof(struct dysymtab_command) == 80, "dysymtab_command layout");
_Static_assert(sizeof(struct entry_point_command) == 24, "entry_point_command layout");

#endif
