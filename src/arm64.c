#include "arm64.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Field extraction, named the way the Arm ARM writes encodings: BITS(w, 9, 5) is w<9:5>. */
#define BIT(w, n)       (((w) >> (n)) & 1u)
#define BITS(w, hi, lo) (((w) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1u))

static int64_t sext(uint64_t v, int bits)
{
    uint64_t m = 1ull << (bits - 1);
    v &= (m << 1) - 1;
    return (int64_t)((v ^ m) - m);
}

#define REGS(p)                                                                          \
    p "0", p "1", p "2", p "3", p "4", p "5", p "6", p "7", p "8", p "9", p "10", p "11",  \
    p "12", p "13", p "14", p "15", p "16", p "17", p "18", p "19", p "20", p "21", p "22", \
    p "23", p "24", p "25", p "26", p "27", p "28", p "29", p "30"

static const char *const xregs[31] = {REGS("x")};
static const char *const wregs[31] = {REGS("w")};

/* Register 31 means the stack pointer or the zero register depending on the
   operand, and the encoding doesn't say which: each instruction's spec does. */
enum { ZR = 0, SP = 1 };

static const char *gpr(unsigned n, int is64, int sp)
{
    if (n == 31)
        return sp ? (is64 ? "sp" : "wsp") : (is64 ? "xzr" : "wzr");
    return is64 ? xregs[n] : wregs[n];
}

static const char *const conds[16] = {
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
};

static void mn(arm64_insn *o, const char *s)
{
    snprintf(o->mnemonic, sizeof o->mnemonic, "%s", s);
}

static void op(arm64_insn *o, const char *fmt, ...)
{
    size_t len = strlen(o->operands);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(o->operands + len, sizeof o->operands - len, fmt, ap);
    va_end(ap);
}

static void imm(arm64_insn *o, int64_t v)
{
    if (v < 0)
        op(o, "#-0x%" PRIx64, 0 - (uint64_t)v);
    else
        op(o, "#0x%" PRIx64, (uint64_t)v);
}

static void target(arm64_insn *o, uint64_t addr)
{
    op(o, "0x%" PRIx64, addr);
    o->has_target = 1;
    o->target = addr;
}

/* ---- data processing, immediate ---- */

/* Logical immediates are a repeating element of 2..64 bits holding a rotated
   run of ones. N:imms encodes the element size and run length, immr the rotation.
   That's why 0x5555555555555555 fits in 13 bits but 0x1234 doesn't fit at all. */
static int decode_bit_masks(unsigned n, unsigned imms, unsigned immr, int width, uint64_t *out)
{
    unsigned combined = (n << 6) | (~imms & 0x3f);
    int len = -1;
    for (int i = 6; i >= 0; i--)
        if (combined & (1u << i)) {
            len = i;
            break;
        }
    if (len < 1)
        return 0;
    unsigned esize = 1u << len, levels = esize - 1;
    unsigned s = imms & levels, r = immr & levels;
    if (s == levels) /* all ones is not encodable */
        return 0;
    if ((int)esize > width)
        return 0;

    uint64_t emask = esize == 64 ? ~0ull : (1ull << esize) - 1;
    uint64_t welem = (1ull << (s + 1)) - 1;
    if (r)
        welem = ((welem >> r) | (welem << (esize - r))) & emask;
    uint64_t v = 0;
    for (int i = 0; i < width; i += (int)esize)
        v |= welem << i;
    *out = width == 64 ? v : v & 0xffffffffull;
    return 1;
}

/* Could movz or movn build this value alone? Then llvm prints the logical
   immediate as orr, keeping "mov" for the move-wide form. */
static int any_movz(uint64_t v, int width)
{
    for (int sh = 0; sh <= width - 16; sh += 16)
        if ((v & ~(0xffffull << sh)) == 0)
            return 1;
    return 0;
}

static int any_movw(uint64_t v, int width)
{
    uint64_t inv = ~v;
    if (width == 32)
        inv &= 0xffffffffull;
    return any_movz(v, width) || any_movz(inv, width);
}

static void mov_imm(arm64_insn *o, unsigned rd, int sf, int sp, uint64_t v)
{
    int64_t s = sext(v, sf ? 64 : 32);
    mn(o, "mov");
    op(o, "%s, ", gpr(rd, sf, sp));
    imm(o, s);
    snprintf(o->comment, sizeof o->comment, "=%" PRId64, s);
}

static int dec_dp_imm(uint32_t w, uint64_t pc, arm64_insn *o)
{
    unsigned sf = BIT(w, 31), rd = BITS(w, 4, 0), rn = BITS(w, 9, 5);
    int width = sf ? 64 : 32;

    switch (BITS(w, 25, 23)) {
    case 0:
    case 1: { /* adr, adrp: 21-bit offset split into immhi:immlo */
        int64_t off = sext((BITS(w, 23, 5) << 2) | BITS(w, 30, 29), 21);
        mn(o, sf ? "adrp" : "adr");
        op(o, "%s, ", gpr(rd, 1, ZR));
        target(o, sf ? (pc & ~0xfffull) + ((uint64_t)off << 12) : pc + (uint64_t)off);
        return 1;
    }
    case 2: { /* add/sub immediate */
        unsigned sub = BIT(w, 30), s = BIT(w, 29), sh = BIT(w, 22), imm12 = BITS(w, 21, 10);
        if (!sub && !s && !sh && !imm12 && (rd == 31 || rn == 31)) {
            mn(o, "mov");
            op(o, "%s, %s", gpr(rd, sf, SP), gpr(rn, sf, SP));
            return 1;
        }
        if (s && rd == 31) {
            mn(o, sub ? "cmp" : "cmn");
            op(o, "%s, ", gpr(rn, sf, SP));
        } else {
            static const char *names[] = {"add", "adds", "sub", "subs"};
            mn(o, names[sub << 1 | s]);
            op(o, "%s, %s, ", gpr(rd, sf, !s), gpr(rn, sf, SP));
        }
        imm(o, imm12);
        if (sh) {
            op(o, ", lsl #12");
            snprintf(o->comment, sizeof o->comment, "=0x%x", imm12 << 12);
        }
        return 1;
    }
    case 4: { /* logical immediate */
        unsigned opc = BITS(w, 30, 29), n = BIT(w, 22), immr = BITS(w, 21, 16), imms = BITS(w, 15, 10);
        uint64_t v;
        if ((!sf && n) || !decode_bit_masks(n, imms, immr, width, &v))
            return 0;
        if (opc == 3 && rd == 31) {
            mn(o, "tst");
            op(o, "%s, #0x%" PRIx64, gpr(rn, sf, ZR), v);
            return 1;
        }
        if (opc == 1 && rn == 31 && !any_movw(v, width)) {
            mov_imm(o, rd, sf, SP, v);
            return 1;
        }
        static const char *names[] = {"and", "orr", "eor", "ands"};
        mn(o, names[opc]);
        op(o, "%s, %s, #0x%" PRIx64, gpr(rd, sf, opc != 3), gpr(rn, sf, ZR), v);
        return 1;
    }
    case 5: { /* move wide: movn, movz, movk */
        unsigned opc = BITS(w, 30, 29), hw = BITS(w, 22, 21), imm16 = BITS(w, 20, 5);
        if (opc == 1 || (!sf && hw >= 2))
            return 0;
        unsigned shift = hw * 16;
        uint64_t mask = sf ? ~0ull : 0xffffffffull;
        uint64_t v = ((uint64_t)imm16 << shift) & mask;
        int lsl0 = imm16 == 0 && hw; /* "#0, lsl #16" stays literal */
        if (opc == 2 && !lsl0) {
            mov_imm(o, rd, sf, ZR, v);
            return 1;
        }
        if (opc == 0 && !lsl0 && !any_movz(~v & mask, width)) {
            mov_imm(o, rd, sf, ZR, ~v & mask);
            return 1;
        }
        static const char *names[] = {"movn", NULL, "movz", "movk"};
        mn(o, names[opc]);
        op(o, "%s, #0x%x", gpr(rd, sf, ZR), imm16);
        if (shift)
            op(o, ", lsl #%u", shift);
        return 1;
    }
    case 6: { /* bitfield: sbfm, bfm, ubfm and their many aliases */
        unsigned opc = BITS(w, 30, 29), n = BIT(w, 22), immr = BITS(w, 21, 16), imms = BITS(w, 15, 10);
        if (opc == 3 || n != sf || (!sf && (immr >= 32 || imms >= 32)))
            return 0;
        const char *d = gpr(rd, sf, ZR), *s = gpr(rn, sf, ZR);

        if (opc == 1) {
            if (imms < immr) {
                mn(o, "bfi");
                op(o, "%s, %s, #%u, #%u", d, s, (width - immr) % width, imms + 1);
            } else {
                mn(o, "bfxil");
                op(o, "%s, %s, #%u, #%u", d, s, immr, imms - immr + 1);
            }
            return 1;
        }

        int sgn = opc == 0;
        if (immr == 0) {
            const char *ext = NULL;
            if (imms == 7 && (sgn || !sf))
                ext = sgn ? "sxtb" : "uxtb";
            else if (imms == 15 && (sgn || !sf))
                ext = sgn ? "sxth" : "uxth";
            else if (imms == 31 && sgn && sf)
                ext = "sxtw";
            if (ext) {
                mn(o, ext);
                op(o, "%s, %s", d, gpr(rn, 0, ZR));
                return 1;
            }
        }
        unsigned top = (unsigned)width - 1;
        if (!sgn && imms != top && imms + 1 == immr) {
            mn(o, "lsl");
            op(o, "%s, %s, #%u", d, s, top - imms);
            return 1;
        }
        if (imms == top) {
            mn(o, sgn ? "asr" : "lsr");
            op(o, "%s, %s, #%u", d, s, immr);
            return 1;
        }
        if (immr > imms) {
            mn(o, sgn ? "sbfiz" : "ubfiz");
            op(o, "%s, %s, #%u, #%u", d, s, width - immr, imms + 1);
        } else {
            mn(o, sgn ? "sbfx" : "ubfx");
            op(o, "%s, %s, #%u, #%u", d, s, immr, imms - immr + 1);
        }
        return 1;
    }
    case 7: { /* extr, and ror when both sources match */
        unsigned n = BIT(w, 22), rm = BITS(w, 20, 16), imms = BITS(w, 15, 10);
        if (BITS(w, 30, 29) || BIT(w, 21) || n != sf || (!sf && imms >= 32))
            return 0;
        if (rn == rm) {
            mn(o, "ror");
            op(o, "%s, %s, ", gpr(rd, sf, ZR), gpr(rn, sf, ZR));
        } else {
            mn(o, "extr");
            op(o, "%s, %s, %s, ", gpr(rd, sf, ZR), gpr(rn, sf, ZR), gpr(rm, sf, ZR));
        }
        imm(o, imms);
        return 1;
    }
    }
    return 0;
}

/* ---- branches, exceptions, system ---- */

static const char *hint_name(unsigned n)
{
    switch (n) {
    case 0:  return "nop";
    case 1:  return "yield";
    case 2:  return "wfe";
    case 3:  return "wfi";
    case 4:  return "sev";
    case 5:  return "sevl";
    case 7:  return "xpaclri";
    case 8:  return "pacia1716";
    case 10: return "pacib1716";
    case 12: return "autia1716";
    case 14: return "autib1716";
    case 24: return "paciaz";
    case 25: return "paciasp";
    case 26: return "pacibz";
    case 27: return "pacibsp";
    case 28: return "autiaz";
    case 29: return "autiasp";
    case 30: return "autibz";
    case 31: return "autibsp";
    case 32: return "bti";
    case 34: return "bti\tc";
    case 36: return "bti\tj";
    case 38: return "bti\tjc";
    }
    return NULL;
}

static const char *barrier_opt(unsigned crm)
{
    static const char *names[16] = {
        NULL, "oshld", "oshst", "osh", NULL, "nshld", "nshst", "nsh",
        NULL, "ishld", "ishst", "ish", NULL, "ld", "st", "sy",
    };
    return names[crm];
}

/* System registers user code actually touches. Others stay a .word rather than
   printing a generic S3_x_Cx_Cx_x name that llvm knows a better name for. */
static const char *sysreg_name(unsigned enc)
{
    switch (enc) {
    case 0xda10: return "NZCV";
    case 0xda20: return "FPCR";
    case 0xda21: return "FPSR";
    case 0xde82: return "TPIDR_EL0";
    case 0xde83: return "TPIDRRO_EL0";
    case 0xdf00: return "CNTFRQ_EL0";
    case 0xdf01: return "CNTPCT_EL0";
    case 0xdf02: return "CNTVCT_EL0";
    case 0xd801: return "CTR_EL0";
    case 0xd807: return "DCZID_EL0";
    }
    return NULL;
}

static int dec_system(uint32_t w, arm64_insn *o)
{
    unsigned l = BIT(w, 21), op0 = BITS(w, 20, 19), op1 = BITS(w, 18, 16), crn = BITS(w, 15, 12);
    unsigned crm = BITS(w, 11, 8), op2 = BITS(w, 7, 5), rt = BITS(w, 4, 0);

    if (op0 >= 2) { /* mrs / msr (register) */
        char generic[24];
        const char *name = sysreg_name(BITS(w, 20, 5) | 0x8000);
        if (!name) {
            /* CRn 11 and 15 are IMPLEMENTATION DEFINED: Apple's own registers
               live there and have no architectural name. */
            if (op0 != 3 || (crn != 11 && crn != 15))
                return 0;
            snprintf(generic, sizeof generic, "S3_%u_C%u_C%u_%u", op1, crn, crm, op2);
            name = generic;
        }
        mn(o, l ? "mrs" : "msr");
        if (l)
            op(o, "%s, %s", gpr(rt, 1, ZR), name);
        else
            op(o, "%s, %s", name, gpr(rt, 1, ZR));
        return 1;
    }
    if (op0 || l || op1 != 3 || rt != 31)
        return 0;

    if (crn == 2) {
        unsigned n = crm << 3 | op2;
        const char *h = hint_name(n);
        if (h) {
            const char *tab = strchr(h, '\t');
            if (tab) {
                snprintf(o->mnemonic, sizeof o->mnemonic, "%.*s", (int)(tab - h), h);
                op(o, "%s", tab + 1);
            } else {
                mn(o, h);
            }
        } else {
            mn(o, "hint");
            imm(o, n);
        }
        return 1;
    }
    if (crn == 3) {
        switch (op2) {
        case 2:
            mn(o, "clrex");
            if (crm != 15)
                imm(o, crm);
            return 1;
        case 4:
            if (crm == 0 || crm == 4) {
                mn(o, crm ? "pssbb" : "ssbb");
                return 1;
            }
            /* fallthrough */
        case 5:
            mn(o, op2 == 4 ? "dsb" : "dmb");
            if (barrier_opt(crm))
                op(o, "%s", barrier_opt(crm));
            else
                imm(o, crm);
            return 1;
        case 6:
            mn(o, "isb");
            if (crm != 15)
                imm(o, crm);
            return 1;
        }
    }
    return 0;
}

static int dec_exception(uint32_t w, arm64_insn *o)
{
    unsigned opc = BITS(w, 23, 21), imm16 = BITS(w, 20, 5), ll = BITS(w, 1, 0);
    const char *name = NULL;
    if (BITS(w, 4, 2))
        return 0;
    switch (opc) {
    case 0: name = (const char *[]){NULL, "svc", "hvc", "smc"}[ll]; break;
    case 1: name = ll ? NULL : "brk"; break;
    case 2: name = ll ? NULL : "hlt"; break;
    case 5: name = (const char *[]){NULL, "dcps1", "dcps2", "dcps3"}[ll]; break;
    }
    if (!name)
        return 0;
    mn(o, name);
    if (opc != 5 || imm16)
        imm(o, imm16);
    return 1;
}

static int dec_branch_reg(uint32_t w, arm64_insn *o)
{
    unsigned opc = BITS(w, 24, 21), op3 = BITS(w, 15, 10), rn = BITS(w, 9, 5), op4 = BITS(w, 4, 0);
    if (BITS(w, 20, 16) != 31)
        return 0;
    int pac = op3 == 2 || op3 == 3; /* key A or B */
    const char *key = op3 == 3 ? "ab" : "aa"; /* authenticate with key A or B */

    switch (opc) {
    case 0:
    case 1: {
        const char *base = opc ? "blr" : "br";
        if (op3 == 0 && op4 == 0) {
            mn(o, base);
        } else if (pac && op4 == 31) {
            snprintf(o->mnemonic, sizeof o->mnemonic, "%s%sz", base, key);
        } else {
            return 0;
        }
        op(o, "%s", gpr(rn, 1, ZR));
        return 1;
    }
    case 2:
        if (op3 == 0 && op4 == 0) {
            mn(o, "ret");
            if (rn != 30)
                op(o, "%s", gpr(rn, 1, ZR));
            return 1;
        }
        if (pac && rn == 31 && op4 == 31) {
            snprintf(o->mnemonic, sizeof o->mnemonic, "ret%s", key);
            return 1;
        }
        return 0;
    case 4:
        if (op3 == 0 && rn == 31 && op4 == 0) {
            mn(o, "eret");
            return 1;
        }
        if (pac && rn == 31 && op4 == 31) {
            snprintf(o->mnemonic, sizeof o->mnemonic, "eret%s", key);
            return 1;
        }
        return 0;
    case 5:
        if (op3 == 0 && rn == 31 && op4 == 0) {
            mn(o, "drps");
            return 1;
        }
        return 0;
    case 8:
    case 9:
        if (!pac)
            return 0;
        snprintf(o->mnemonic, sizeof o->mnemonic, "%s%s", opc == 8 ? "br" : "blr", key);
        op(o, "%s, %s", gpr(rn, 1, ZR), gpr(op4, 1, SP));
        return 1;
    }
    return 0;
}

static int dec_branch_sys(uint32_t w, uint64_t pc, arm64_insn *o)
{
    unsigned op0 = BITS(w, 31, 29);

    if ((op0 & 3) == 0) { /* b, bl: 26-bit word offset, +-128MB */
        mn(o, op0 ? "bl" : "b");
        target(o, pc + (uint64_t)(sext(BITS(w, 25, 0), 26) * 4));
        return 1;
    }
    if ((op0 & 3) == 1) {
        unsigned rt = BITS(w, 4, 0), nz = BIT(w, 24);
        if (!BIT(w, 25)) {
            mn(o, nz ? "cbnz" : "cbz");
            op(o, "%s, ", gpr(rt, BIT(w, 31), ZR));
            target(o, pc + (uint64_t)(sext(BITS(w, 23, 5), 19) * 4));
        } else { /* the bit number's top bit doubles as the register width */
            unsigned bit = BIT(w, 31) << 5 | BITS(w, 23, 19);
            mn(o, nz ? "tbnz" : "tbz");
            op(o, "%s, ", gpr(rt, BIT(w, 31), ZR));
            imm(o, bit);
            op(o, ", ");
            target(o, pc + (uint64_t)(sext(BITS(w, 18, 5), 14) * 4));
        }
        return 1;
    }
    if (op0 == 2) {
        if (BITS(w, 25, 24))
            return 0;
        snprintf(o->mnemonic, sizeof o->mnemonic, "%s.%s", BIT(w, 4) ? "bc" : "b", conds[BITS(w, 3, 0)]);
        target(o, pc + (uint64_t)(sext(BITS(w, 23, 5), 19) * 4));
        return 1;
    }
    if (op0 == 6) {
        if (BIT(w, 25))
            return dec_branch_reg(w, o);
        if (!BIT(w, 24))
            return dec_exception(w, o);
        if (BITS(w, 23, 22) == 0)
            return dec_system(w, o);
    }
    return 0;
}

/* ---- data processing, register ---- */

static const char *const shifts[4] = {"lsl", "lsr", "asr", "ror"};

static void shifted(arm64_insn *o, unsigned type, unsigned amount)
{
    if (type || amount)
        op(o, ", %s #%u", shifts[type], amount);
}

static int dec_dp_reg(uint32_t w, arm64_insn *o)
{
    unsigned sf = BIT(w, 31), o30 = BIT(w, 30), s = BIT(w, 29), op2 = BITS(w, 24, 21);
    unsigned rm = BITS(w, 20, 16), rn = BITS(w, 9, 5), rd = BITS(w, 4, 0);
    const char *d = gpr(rd, sf, ZR), *n = gpr(rn, sf, ZR), *m = gpr(rm, sf, ZR);

    if (!BIT(w, 28)) {
        unsigned type = BITS(w, 23, 22), imm6 = BITS(w, 15, 10);
        if (!(op2 & 8)) { /* logical, shifted register */
            static const char *names[] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};
            unsigned opc = BITS(w, 30, 29), inv = BIT(w, 21);
            if (!sf && imm6 >= 32)
                return 0;
            if (opc == 1 && !inv && rn == 31 && !type && !imm6) {
                mn(o, "mov");
                op(o, "%s, %s", d, m);
            } else if (opc == 1 && inv && rn == 31) {
                mn(o, "mvn");
                op(o, "%s, %s", d, m);
                shifted(o, type, imm6);
            } else if (opc == 3 && !inv && rd == 31) {
                mn(o, "tst");
                op(o, "%s, %s", n, m);
                shifted(o, type, imm6);
            } else {
                mn(o, names[opc << 1 | inv]);
                op(o, "%s, %s, %s", d, n, m);
                shifted(o, type, imm6);
            }
            return 1;
        }
        static const char *names[] = {"add", "adds", "sub", "subs"};
        if (!(op2 & 1)) { /* add/sub, shifted register */
            if (type == 3 || (!sf && imm6 >= 32))
                return 0;
            if (s && rd == 31) {
                mn(o, o30 ? "cmp" : "cmn");
                op(o, "%s, %s", n, m);
            } else if (o30 && rn == 31) {
                mn(o, s ? "negs" : "neg");
                op(o, "%s, %s", d, m);
            } else {
                mn(o, names[o30 << 1 | s]);
                op(o, "%s, %s, %s", d, n, m);
            }
            shifted(o, type, imm6);
            return 1;
        }
        /* add/sub, extended register: Rm is widened (and optionally shifted
           left 0-4) before the add, which is how array indexing by an int works. */
        static const char *exts[] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
        unsigned option = BITS(w, 15, 13), amount = BITS(w, 12, 10);
        if (type || amount > 4)
            return 0;
        const char *rmname = gpr(rm, sf && (option & 3) == 3, ZR);
        if (s && rd == 31) {
            mn(o, o30 ? "cmp" : "cmn");
            op(o, "%s, %s", gpr(rn, sf, SP), rmname);
        } else {
            mn(o, names[o30 << 1 | s]);
            op(o, "%s, %s, %s", gpr(rd, sf, !s), gpr(rn, sf, SP), rmname);
        }
        int sp_involved = rn == 31 || (rd == 31 && !s);
        if (sp_involved && option == (sf ? 3u : 2u)) {
            if (amount)
                op(o, ", lsl #%u", amount);
        } else {
            op(o, ", %s", exts[option]);
            if (amount)
                op(o, " #%u", amount);
        }
        return 1;
    }

    switch (op2) {
    case 0: { /* adc, sbc */
        if (BITS(w, 15, 10))
            return 0;
        if (o30 && rn == 31) {
            mn(o, s ? "ngcs" : "ngc");
            op(o, "%s, %s", d, m);
        } else {
            static const char *names[] = {"adc", "adcs", "sbc", "sbcs"};
            mn(o, names[o30 << 1 | s]);
            op(o, "%s, %s, %s", d, n, m);
        }
        return 1;
    }
    case 2: { /* ccmp, ccmn: compare only if cond holds, else set flags to nzcv */
        if (!s || BIT(w, 10) || BIT(w, 4))
            return 0;
        mn(o, o30 ? "ccmp" : "ccmn");
        op(o, "%s, ", n);
        if (BIT(w, 11))
            imm(o, rm);
        else
            op(o, "%s", m);
        op(o, ", ");
        imm(o, BITS(w, 3, 0));
        op(o, ", %s", conds[BITS(w, 15, 12)]);
        return 1;
    }
    case 4: { /* csel family. cset is csinc with the inverted condition */
        if (s || BIT(w, 11))
            return 0;
        unsigned kind = o30 << 1 | BIT(w, 10), cond = BITS(w, 15, 12);
        const char *inv = conds[cond ^ 1];
        if (cond < 14 && (kind == 1 || kind == 2) && rn == 31 && rm == 31) {
            mn(o, kind == 1 ? "cset" : "csetm");
            op(o, "%s, %s", d, inv);
            return 1;
        }
        if (cond < 14 && kind && rn == rm) {
            mn(o, (const char *[]){NULL, "cinc", "cinv", "cneg"}[kind]);
            op(o, "%s, %s, %s", d, n, inv);
            return 1;
        }
        mn(o, (const char *[]){"csel", "csinc", "csinv", "csneg"}[kind]);
        op(o, "%s, %s, %s, %s", d, n, m, conds[cond]);
        return 1;
    }
    case 6: {
        unsigned opcode = BITS(w, 15, 10);
        if (s)
            return 0;
        if (!o30) { /* two sources */
            const char *name = NULL;
            switch (opcode) {
            case 2:  name = "udiv"; break;
            case 3:  name = "sdiv"; break;
            case 8:  name = "lsl"; break;
            case 9:  name = "lsr"; break;
            case 10: name = "asr"; break;
            case 11: name = "ror"; break;
            case 12:
                if (!sf)
                    return 0;
                mn(o, "pacga");
                op(o, "%s, %s, %s", d, n, gpr(rm, 1, SP));
                return 1;
            }
            if (opcode >= 16 && opcode <= 23) {
                static const char *crc[] = {"crc32b", "crc32h", "crc32w", "crc32x",
                                            "crc32cb", "crc32ch", "crc32cw", "crc32cx"};
                if (sf != ((opcode & 3) == 3))
                    return 0;
                mn(o, crc[opcode - 16]);
                op(o, "%s, %s, %s", gpr(rd, 0, ZR), gpr(rn, 0, ZR), m);
                return 1;
            }
            if (!name)
                return 0;
            mn(o, name);
            op(o, "%s, %s, %s", d, n, m);
            return 1;
        }
        /* one source */
        if (rm == 0) {
            static const char *names[] = {"rbit", "rev16", "rev", "rev", "clz", "cls"};
            if (opcode > 5 || (opcode == 3 && !sf))
                return 0;
            mn(o, opcode == 2 && sf ? "rev32" : names[opcode]);
            op(o, "%s, %s", d, n);
            return 1;
        }
        if (rm == 1 && sf) { /* pointer authentication */
            static const char *names[] = {"pacia", "pacib", "pacda", "pacdb",
                                          "autia", "autib", "autda", "autdb"};
            if (opcode < 8) {
                mn(o, names[opcode]);
                op(o, "%s, %s", d, gpr(rn, 1, SP));
                return 1;
            }
            if (rn != 31)
                return 0;
            if (opcode < 16) {
                snprintf(o->mnemonic, sizeof o->mnemonic, "%.4sz%c", names[opcode - 8], names[opcode - 8][4]);
                op(o, "%s", d);
                return 1;
            }
            if (opcode == 16 || opcode == 17) {
                mn(o, opcode == 16 ? "xpaci" : "xpacd");
                op(o, "%s", d);
                return 1;
            }
        }
        return 0;
    }
    }

    if (op2 & 8) { /* three sources: multiply-add and the long multiplies */
        unsigned op31 = BITS(w, 23, 21), o0 = BIT(w, 15), ra = BITS(w, 14, 10);
        if (BITS(w, 30, 29))
            return 0;
        if (op31 == 0) {
            if (ra == 31) {
                mn(o, o0 ? "mneg" : "mul");
                op(o, "%s, %s, %s", d, n, m);
            } else {
                mn(o, o0 ? "msub" : "madd");
                op(o, "%s, %s, %s, %s", d, n, m, gpr(ra, sf, ZR));
            }
            return 1;
        }
        if (!sf)
            return 0;
        if (op31 == 1 || op31 == 5) {
            static const char *names[] = {"smaddl", "smsubl", "smull", "smnegl",
                                          "umaddl", "umsubl", "umull", "umnegl"};
            mn(o, names[(op31 == 5) << 2 | (ra == 31) << 1 | o0]);
            op(o, "%s, %s, %s", d, gpr(rn, 0, ZR), gpr(rm, 0, ZR));
            if (ra != 31)
                op(o, ", %s", gpr(ra, 1, ZR));
            return 1;
        }
        if ((op31 == 2 || op31 == 6) && !o0 && ra == 31) {
            mn(o, op31 == 2 ? "smulh" : "umulh");
            op(o, "%s, %s, %s", d, n, m);
            return 1;
        }
    }
    return 0;
}

/* ---- loads and stores ---- */

/* What a load/store moves: integer registers, or b/h/s/d/q views of the SIMD file. */
typedef struct {
    const char *name; /* "ldr", "strb", "ldrsw", "prfm", ... */
    char        rclass; /* 'w', 'x', or 'b'/'h'/'s'/'d'/'q' */
    unsigned    scale;  /* log2 of the access size */
} ldst_kind;

static int ldst_reg_kind(unsigned size, unsigned v, unsigned opc, ldst_kind *k)
{
    if (v) {
        static const char fp[] = "bhsdq";
        if (opc >= 2 && size)
            return 0;
        k->scale = opc >= 2 ? 4 : size;
        k->rclass = fp[k->scale];
        k->name = opc & 1 ? "ldr" : "str";
        return 1;
    }
    static const char *names[4][4] = {
        {"strb", "ldrb", "ldrsb", "ldrsb"},
        {"strh", "ldrh", "ldrsh", "ldrsh"},
        {"str", "ldr", "ldrsw", NULL},
        {"str", "ldr", "prfm", NULL},
    };
    k->name = names[size][opc];
    k->scale = size;
    if (!k->name)
        return 0;
    if (opc == 2)
        k->rclass = size == 3 ? 'p' : 'x'; /* 'p': prefetch operation, not a register */
    else
        k->rclass = opc == 3 || size < 3 ? 'w' : 'x';
    return 1;
}

static void prfop(arm64_insn *o, unsigned rt)
{
    static const char *types[] = {"pld", "pli", "pst"};
    static const char *targets[] = {"l1", "l2", "l3", "slc"};
    unsigned type = rt >> 3;
    if (type < 3)
        op(o, "%s%s%s", types[type], targets[(rt >> 1) & 3], rt & 1 ? "strm" : "keep");
    else if (rt == 24)
        op(o, "ir");
    else
        imm(o, rt);
}

static void ldst_rt(arm64_insn *o, const ldst_kind *k, unsigned rt)
{
    if (k->rclass == 'p')
        prfop(o, rt);
    else if (k->rclass == 'w' || k->rclass == 'x')
        op(o, "%s", gpr(rt, k->rclass == 'x', ZR));
    else
        op(o, "%c%u", k->rclass, rt);
}

/* Unscaled and unprivileged forms splice a letter into the name: ldrsb -> ldursb. */
static void ldst_name(arm64_insn *o, const char *base, char infix)
{
    if (!strcmp(base, "prfm"))
        mn(o, "prfum");
    else
        snprintf(o->mnemonic, sizeof o->mnemonic, "%.2s%c%s", base, infix, base + 2);
}

static void mem_imm(arm64_insn *o, unsigned rn, int64_t off, int mode)
{
    const char *base = gpr(rn, 1, SP);
    switch (mode) {
    case 0: /* signed or unsigned offset, nothing written back */
        op(o, "[%s", base);
        if (off) {
            op(o, ", ");
            imm(o, off);
        }
        op(o, "]");
        break;
    case 1: /* post-index */
        op(o, "[%s], ", base);
        imm(o, off);
        break;
    case 2: /* pre-index */
        op(o, "[%s, ", base);
        imm(o, off);
        op(o, "]!");
        break;
    }
}

static int dec_ldst_reg(uint32_t w, arm64_insn *o)
{
    unsigned size = BITS(w, 31, 30), v = BIT(w, 26), opc = BITS(w, 23, 22);
    unsigned rn = BITS(w, 9, 5), rt = BITS(w, 4, 0);
    ldst_kind k;

    if (BIT(w, 24)) { /* unsigned 12-bit offset, scaled by the access size */
        if (!ldst_reg_kind(size, v, opc, &k))
            return 0;
        mn(o, k.name);
        ldst_rt(o, &k, rt);
        op(o, ", ");
        mem_imm(o, rn, (int64_t)BITS(w, 21, 10) << k.scale, 0);
        return 1;
    }

    if (!BIT(w, 21)) { /* 9-bit signed offset, unscaled */
        unsigned idx = BITS(w, 11, 10);
        int64_t off = sext(BITS(w, 20, 12), 9);
        if (!ldst_reg_kind(size, v, opc, &k))
            return 0;
        if (k.rclass == 'p' && idx != 0)
            return 0;
        if (idx == 2 && v)
            return 0;
        if (idx == 0 || idx == 2)
            ldst_name(o, k.name, idx ? 't' : 'u');
        else
            mn(o, k.name);
        ldst_rt(o, &k, rt);
        op(o, ", ");
        mem_imm(o, rn, off, idx == 1 ? 1 : idx == 3 ? 2 : 0);
        return 1;
    }

    unsigned idx = BITS(w, 11, 10), rs = BITS(w, 20, 16);
    if (idx == 2) { /* register offset: base + extend(Rm) << (S ? scale : 0) */
        unsigned option = BITS(w, 15, 13), shift = BIT(w, 12);
        if (!(option & 2) || !ldst_reg_kind(size, v, opc, &k))
            return 0;
        if (k.rclass == 'p' && (rt >> 3) == 3) { /* range prefetch, operation spread over three fields */
            static const char *rops[8] = {"pldkeep", "pstkeep", NULL, NULL, "pldstrm", "pststrm"};
            unsigned rop = (option >> 2) << 5 | (option & 1) << 4 | shift << 3 | (rt & 7);
            mn(o, "rprfm");
            if (rop < 8 && rops[rop])
                op(o, "%s", rops[rop]);
            else
                imm(o, rop);
            op(o, ", %s, [%s]", gpr(rs, 1, ZR), gpr(rn, 1, SP));
            return 1;
        }
        mn(o, k.name);
        ldst_rt(o, &k, rt);
        op(o, ", [%s, %s", gpr(rn, 1, SP), gpr(rs, option & 1, ZR));
        if (option == 3) {
            if (shift)
                op(o, ", lsl #%u", k.scale);
        } else {
            op(o, ", %cxt%c", option & 4 ? 's' : 'u', option & 1 ? 'x' : 'w');
            if (shift)
                op(o, " #%u", k.scale);
        }
        op(o, "]");
        return 1;
    }

    if (idx == 0 && !v) { /* LSE atomics: ldadd, swp, ... */
        static const char *ops[] = {"add", "clr", "eor", "set", "smax", "smin", "umax", "umin"};
        static const char *sfx[] = {"b", "h", "", ""};
        unsigned a = BIT(w, 23), r = BIT(w, 22), o3 = BIT(w, 15), aop = BITS(w, 14, 12);
        int x = size == 3;
        if (o3 && aop == 4 && a && !r) {
            if (rs != 31)
                return 0;
            snprintf(o->mnemonic, sizeof o->mnemonic, "ldapr%s", sfx[size]);
            op(o, "%s, [%s]", gpr(rt, x, ZR), gpr(rn, 1, SP));
            return 1;
        }
        if (o3 && aop)
            return 0;
        const char *name = o3 ? "swp" : ops[aop];
        if (!o3 && rt == 31 && !a) { /* result discarded: the store-only alias */
            snprintf(o->mnemonic, sizeof o->mnemonic, "st%s%s%s", name, r ? "l" : "", sfx[size]);
            op(o, "%s, [%s]", gpr(rs, x, ZR), gpr(rn, 1, SP));
            return 1;
        }
        snprintf(o->mnemonic, sizeof o->mnemonic, "%s%s%s%s%s", o3 ? "" : "ld", name, a ? "a" : "",
                 r ? "l" : "", sfx[size]);
        op(o, "%s, %s, [%s]", gpr(rs, x, ZR), gpr(rt, x, ZR), gpr(rn, 1, SP));
        /* The acquire is tied to the load half, and a load into zr isn't ordered. */
        if (rt == 31 && a)
            snprintf(o->comment, sizeof o->comment, "acquire semantics dropped since destination is zero");
        return 1;
    }
    return 0;
}

static int dec_ldst_pair(uint32_t w, arm64_insn *o)
{
    unsigned opc = BITS(w, 31, 30), v = BIT(w, 26), mode = BITS(w, 24, 23), l = BIT(w, 22);
    unsigned rt2 = BITS(w, 14, 10), rn = BITS(w, 9, 5), rt = BITS(w, 4, 0);
    const char *name = mode ? (l ? "ldp" : "stp") : (l ? "ldnp" : "stnp");
    char rc;
    unsigned scale;

    if (opc == 3)
        return 0;
    if (v) {
        rc = "sdq"[opc];
        scale = 2 + opc;
    } else if (opc == 1) {
        if (!l || !mode)
            return 0;
        name = "ldpsw";
        rc = 'x';
        scale = 2;
    } else {
        rc = opc ? 'x' : 'w';
        scale = opc ? 3 : 2;
    }

    mn(o, name);
    if (v)
        op(o, "%c%u, %c%u, ", rc, rt, rc, rt2);
    else
        op(o, "%s, %s, ", gpr(rt, rc == 'x', ZR), gpr(rt2, rc == 'x', ZR));
    mem_imm(o, rn, sext(BITS(w, 21, 15), 7) * (1 << scale), mode == 1 ? 1 : mode == 3 ? 2 : 0);
    return 1;
}

/* Exclusives, load-acquire/store-release, compare-and-swap. */
static int dec_ldst_excl(uint32_t w, arm64_insn *o)
{
    static const char *sfx[] = {"b", "h", "", ""};
    unsigned size = BITS(w, 31, 30), o2 = BIT(w, 23), l = BIT(w, 22), o1 = BIT(w, 21);
    unsigned rs = BITS(w, 20, 16), o0 = BIT(w, 15), rt2 = BITS(w, 14, 10), rn = BITS(w, 9, 5),
             rt = BITS(w, 4, 0);
    int x = size == 3;
    const char *base = gpr(rn, 1, SP);

    if (!o2 && !o1) {
        if (rt2 != 31 || (l && rs != 31))
            return 0;
        snprintf(o->mnemonic, sizeof o->mnemonic, "%s%s", l ? (o0 ? "ldaxr" : "ldxr") : (o0 ? "stlxr" : "stxr"),
                 sfx[size]);
        if (!l)
            op(o, "%s, ", gpr(rs, 0, ZR));
        op(o, "%s, [%s]", gpr(rt, x, ZR), base);
        return 1;
    }
    if (!o2 && o1) {
        if (size >= 2) {
            if (l && rs != 31)
                return 0;
            mn(o, l ? (o0 ? "ldaxp" : "ldxp") : (o0 ? "stlxp" : "stxp"));
            if (!l)
                op(o, "%s, ", gpr(rs, 0, ZR));
            op(o, "%s, %s, [%s]", gpr(rt, x, ZR), gpr(rt2, x, ZR), base);
            return 1;
        }
        if (rt2 != 31 || (rs & 1) || (rt & 1))
            return 0;
        int px = size == 1;
        snprintf(o->mnemonic, sizeof o->mnemonic, "casp%s%s", l ? "a" : "", o0 ? "l" : "");
        op(o, "%s, %s, %s, %s, [%s]", gpr(rs, px, ZR), gpr((rs + 1) & 31, px, ZR), gpr(rt, px, ZR),
           gpr((rt + 1) & 31, px, ZR), base);
        return 1;
    }
    if (rt2 != 31)
        return 0;
    if (!o1) {
        if (rs != 31)
            return 0;
        snprintf(o->mnemonic, sizeof o->mnemonic, "%s%s", l ? (o0 ? "ldar" : "ldlar") : (o0 ? "stlr" : "stllr"),
                 sfx[size]);
        op(o, "%s, [%s]", gpr(rt, x, ZR), base);
        return 1;
    }
    snprintf(o->mnemonic, sizeof o->mnemonic, "cas%s%s%s", l ? "a" : "", o0 ? "l" : "", sfx[size]);
    op(o, "%s, %s, [%s]", gpr(rs, x, ZR), gpr(rt, x, ZR), base);
    return 1;
}

static int dec_ldst(uint32_t w, uint64_t pc, arm64_insn *o)
{
    switch (BITS(w, 29, 27)) {
    case 1:
        if (BITS(w, 26, 24) == 0)
            return dec_ldst_excl(w, o);
        return 0;
    case 3: { /* pc-relative literal load */
        static const char *names[2][4] = {{"ldr", "ldr", "ldrsw", "prfm"}, {"ldr", "ldr", "ldr", NULL}};
        unsigned opc = BITS(w, 31, 30), v = BIT(w, 26), rt = BITS(w, 4, 0);
        if (BIT(w, 24) || !names[v][opc])
            return 0;
        mn(o, names[v][opc]);
        if (v)
            op(o, "%c%u", "sdq"[opc], rt);
        else if (opc == 3)
            prfop(o, rt);
        else
            op(o, "%s", gpr(rt, opc != 0, ZR));
        op(o, ", ");
        target(o, pc + (uint64_t)(sext(BITS(w, 23, 5), 19) * 4));
        return 1;
    }
    case 5:
        return dec_ldst_pair(w, o);
    case 7:
        return dec_ldst_reg(w, o);
    }
    return 0;
}

int arm64_decode(uint32_t w, uint64_t pc, arm64_insn *o)
{
    memset(o, 0, sizeof *o);
    int ok = 0;

    /* Bits 28:25 pick the top-level encoding group (Arm ARM C4.1). */
    switch (BITS(w, 28, 25)) {
    case 0x0:
        if (BITS(w, 31, 29) == 0 && BITS(w, 24, 16) == 0) {
            mn(o, "udf");
            imm(o, BITS(w, 15, 0));
            ok = 1;
        }
        break;
    case 0x8:
    case 0x9:
        ok = dec_dp_imm(w, pc, o);
        break;
    case 0xa:
    case 0xb:
        ok = dec_branch_sys(w, pc, o);
        break;
    case 0x5:
    case 0xd:
        ok = dec_dp_reg(w, o);
        break;
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe:
        ok = dec_ldst(w, pc, o);
        break;
    }
    if (ok)
        return 0;

    memset(o, 0, sizeof *o);
    mn(o, ".word");
    op(o, "0x%08x", w);
    return -1;
}
