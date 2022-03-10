
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

// Defines FD_TABLE_OFFSET_32 and FD_TABLE_OFFSET_64, if available
#define FD_DECODE_TABLE_DEFINES
#include <fadec-table.inc>
#undef FD_DECODE_TABLE_DEFINES

enum DecodeMode {
    DECODE_64 = 0,
    DECODE_32 = 1,
};

typedef enum DecodeMode DecodeMode;

#define ENTRY_NONE 0
#define ENTRY_INSTR 1
#define ENTRY_TABLE256 2
#define ENTRY_TABLE16 3
#define ENTRY_TABLE8E 4
#define ENTRY_TABLE_PREFIX 5
#define ENTRY_TABLE_VEX 6
#define ENTRY_TABLE_ROOT 8
#define ENTRY_MASK 7

static unsigned
table_walk(unsigned cur_idx, unsigned entry_idx, unsigned* out_kind) {
    static __attribute__((aligned(16))) const uint16_t _decode_table[] = {
#define FD_DECODE_TABLE_DATA
#include <fadec-table.inc>
#undef FD_DECODE_TABLE_DATA
    };
    unsigned entry = _decode_table[cur_idx + entry_idx];
    *out_kind = entry & ENTRY_MASK;
    return (entry & ~ENTRY_MASK) >> 1;
}

#define LOAD_LE_1(buf) ((uint64_t) *(uint8_t*) (buf))
#define LOAD_LE_2(buf) (LOAD_LE_1(buf) | LOAD_LE_1((uint8_t*) (buf) + 1)<<8)
#define LOAD_LE_3(buf) (LOAD_LE_2(buf) | LOAD_LE_1((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_4(buf) (LOAD_LE_2(buf) | LOAD_LE_2((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_8(buf) (LOAD_LE_4(buf) | LOAD_LE_4((uint8_t*) (buf) + 4)<<32)

enum
{
    PREFIX_REXB = 0x01,
    PREFIX_REXX = 0x02,
    PREFIX_REXR = 0x04,
    PREFIX_REXW = 0x08,
    PREFIX_REX = 0x40,
    PREFIX_VEXL = 0x10,
};

struct InstrDesc
{
    uint16_t type;
    uint16_t operand_indices;
    uint16_t operand_sizes;
    uint16_t reg_types;
} __attribute__((packed));

#define DESC_HAS_MODRM(desc) (((desc)->operand_indices & (3 << 0)) != 0)
#define DESC_MODRM_IDX(desc) ((((desc)->operand_indices >> 0) & 3) ^ 3)
#define DESC_HAS_MODREG(desc) (((desc)->operand_indices & (3 << 2)) != 0)
#define DESC_MODREG_IDX(desc) ((((desc)->operand_indices >> 2) & 3) ^ 3)
#define DESC_HAS_VEXREG(desc) (((desc)->operand_indices & (3 << 4)) != 0)
#define DESC_VEXREG_IDX(desc) ((((desc)->operand_indices >> 4) & 3) ^ 3)
#define DESC_HAS_IMPLICIT(desc) (((desc)->operand_indices & (3 << 6)) != 0)
#define DESC_IMPLICIT_IDX(desc) ((((desc)->operand_indices >> 6) & 3) ^ 3)
#define DESC_IMM_CONTROL(desc) (((desc)->operand_indices >> 12) & 0x7)
#define DESC_IMM_IDX(desc) ((((desc)->operand_indices >> 8) & 3) ^ 3)
#define DESC_IMPLICIT_VAL(desc) (((desc)->operand_indices >> 10) & 1)
#define DESC_LOCK(desc) (((desc)->operand_indices >> 11) & 1)
#define DESC_VSIB(desc) (((desc)->operand_indices >> 15) & 1)
#define DESC_OPSIZE(desc) (((desc)->operand_sizes >> 8) & 3)
#define DESC_SIZE_FIX1(desc) (((desc)->operand_sizes >> 10) & 7)
#define DESC_SIZE_FIX2(desc) (((desc)->operand_sizes >> 13) & 3)
#define DESC_INSTR_WIDTH(desc) (((desc)->operand_sizes >> 15) & 1)
#define DESC_MODRM(desc) (((desc)->reg_types >> 14) & 1)
#define DESC_IGN66(desc) (((desc)->reg_types >> 15) & 1)
#define DESC_REGTY_MODRM(desc) (((desc)->reg_types >> 0) & 7)
#define DESC_REGTY_MODREG(desc) (((desc)->reg_types >> 3) & 7)
#define DESC_REGTY_VEXREG(desc) (((desc)->reg_types >> 6) & 3)
#define DESC_REGTY_ZEROREG(desc) (((desc)->reg_types >> 8) & 3)

int
fd_decode(const uint8_t* buffer, size_t len_sz, int mode_int, uintptr_t address,
          FdInstr* instr)
{
    int len = len_sz > 15 ? 15 : len_sz;

    // Ensure that we can actually handle the decode request
    DecodeMode mode;
    unsigned table_idx;
    unsigned kind = ENTRY_TABLE_ROOT;
    switch (mode_int)
    {
#if defined(FD_TABLE_OFFSET_32)
    case 32: table_idx = FD_TABLE_OFFSET_32; mode = DECODE_32; break;
#endif
#if defined(FD_TABLE_OFFSET_64)
    case 64: table_idx = FD_TABLE_OFFSET_64; mode = DECODE_64; break;
#endif
    default: return FD_ERR_INTERNAL;
    }

    int off = 0;
    uint8_t vex_operand = 0;

    unsigned prefix_rep = 0;
    bool prefix_lock = false;
    bool prefix_66 = false;
    uint8_t addr_size = mode == DECODE_64 ? 8 : 4;
    unsigned prefix_rex = 0;
    int rex_off = -1;
    instr->segment = FD_REG_NONE;

    if (mode == DECODE_32) {
        while (LIKELY(off < len))
        {
            uint8_t prefix = buffer[off];
            switch (UNLIKELY(prefix))
            {
            default: goto prefix_end;
            // From segment overrides, the last one wins.
            case 0x26: instr->segment = FD_REG_ES; break;
            case 0x2e: instr->segment = FD_REG_CS; break;
            case 0x36: instr->segment = FD_REG_SS; break;
            case 0x3e: instr->segment = FD_REG_DS; break;
            case 0x64: instr->segment = FD_REG_FS; break;
            case 0x65: instr->segment = FD_REG_GS; break;
            case 0x66: prefix_66 = true; break;
            case 0x67: addr_size = 2; break;
            case 0xf0: prefix_lock = true; break;
            case 0xf3: prefix_rep = 2; break;
            case 0xf2: prefix_rep = 3; break;
            }
            off++;
        }
    }
    if (mode == DECODE_64) {
        while (LIKELY(off < len))
        {
            uint8_t prefix = buffer[off];
            switch (UNLIKELY(prefix))
            {
            default: goto prefix_end;
            // ES/CS/SS/DS overrides are ignored.
            case 0x26: case 0x2e: case 0x36: case 0x3e: break;
            // From segment overrides, the last one wins.
            case 0x64: instr->segment = FD_REG_FS; break;
            case 0x65: instr->segment = FD_REG_GS; break;
            case 0x66: prefix_66 = true; break;
            case 0x67: addr_size = 4; break;
            case 0xf0: prefix_lock = true; break;
            case 0xf3: prefix_rep = 2; break;
            case 0xf2: prefix_rep = 3; break;
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
            case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b:
            case 0x4c: case 0x4d: case 0x4e: case 0x4f:
                prefix_rex = prefix;
                rex_off = off;
                break;
            }
            off++;
        }
    }

prefix_end:
    // REX prefix is only considered if it is the last prefix.
    if (rex_off != off - 1)
        prefix_rex = 0;

    if (UNLIKELY(off >= len))
        return FD_ERR_PARTIAL;

    unsigned opcode_escape = 0;
    if (buffer[off] == 0x0f)
    {
        if (UNLIKELY(off + 1 >= len))
            return FD_ERR_PARTIAL;
        if (buffer[off + 1] == 0x38)
            opcode_escape = 2;
        else if (buffer[off + 1] == 0x3a)
            opcode_escape = 3;
        else
            opcode_escape = 1;
        off += opcode_escape >= 2 ? 2 : 1;
    }
    else if (UNLIKELY((buffer[off] & 0xfe) == 0xc4)) // VEX c4/c5
    {
        if (UNLIKELY(off + 1 >= len))
            return FD_ERR_PARTIAL;
        if (mode == DECODE_32 && (buffer[off + 1] & 0xc0) != 0xc0)
            goto skipvex;

        // VEX + 66/F3/F2/REX will #UD.
        // Note: REX is also here only respected if it immediately precedes the
        // opcode, in this case the VEX "prefix".
        if (prefix_66 || prefix_rep || prefix_rex)
            return FD_ERR_UD;

        uint8_t byte = buffer[off + 1];
        prefix_rex |= byte & 0x80 ? 0 : PREFIX_REXR;
        if (buffer[off] == 0xc4) // 3-byte VEX
        {
            prefix_rex |= byte & 0x40 ? 0 : PREFIX_REXX;
            // SDM Vol 2A 2-15 (Dec. 2016): Ignored in 32-bit mode
            prefix_rex |= mode != DECODE_64 || (byte & 0x20) ? 0 : PREFIX_REXB;
            if (byte & 0x1c) // Bits 4:2 of opcode_escape must be clear.
                return FD_ERR_UD;
            opcode_escape = (byte & 0x03) | 4; // 4 is table index with VEX

            // Load third byte of VEX prefix
            if (UNLIKELY(off + 2 >= len))
                return FD_ERR_PARTIAL;
            byte = buffer[off + 2];
            prefix_rex |= byte & 0x80 ? PREFIX_REXW : 0;
        }
        else // 2-byte VEX
            opcode_escape = 1 | 4; // 4 is table index with VEX, 0f escape

        prefix_rex |= byte & 0x04 ? PREFIX_VEXL : 0;
        prefix_rep = (byte & 2) ? (byte & 3) : 0;
        prefix_66 = (byte & 3) == 1;
        vex_operand = ((byte & 0x78) >> 3) ^ 0xf;

        off += buffer[off] == 0xc4 ? 3 : 2;
    skipvex:;
    }

    table_idx = table_walk(table_idx, opcode_escape, &kind);
    if (kind == ENTRY_TABLE256 && LIKELY(off < len))
        table_idx = table_walk(table_idx, buffer[off++], &kind);

    // Handle mandatory prefixes (which behave like an opcode ext.).
    if (kind == ENTRY_TABLE_PREFIX)
    {
        // If there is no REP/REPNZ prefix offer 66h as mandatory prefix. If
        // there is a REP prefix, then the 66h prefix is ignored here.
        uint8_t mandatory_prefix = prefix_rep ? prefix_rep : !!prefix_66;
        table_idx = table_walk(table_idx, mandatory_prefix, &kind);
    }

    // Then, walk through ModR/M-encoded opcode extensions.
    if (kind == ENTRY_TABLE16 && LIKELY(off < len)) {
        unsigned isreg = (buffer[off] & 0xc0) == 0xc0 ? 8 : 0;
        table_idx = table_walk(table_idx, ((buffer[off] >> 3) & 7) | isreg, &kind);
        if (kind == ENTRY_TABLE8E)
            table_idx = table_walk(table_idx, buffer[off] & 7, &kind);
    }

    // For VEX prefix, we have to distinguish between VEX.W and VEX.L which may
    // be part of the opcode.
    if (UNLIKELY(kind == ENTRY_TABLE_VEX))
    {
        uint8_t index = 0;
        index |= prefix_rex & PREFIX_REXW ? (1 << 0) : 0;
        index |= prefix_rex & PREFIX_VEXL ? (1 << 1) : 0;
        table_idx = table_walk(table_idx, index, &kind);
    }

    if (UNLIKELY(kind != ENTRY_INSTR))
        return kind == 0 ? FD_ERR_UD : FD_ERR_PARTIAL;

    static __attribute__((aligned(16))) const struct InstrDesc descs[] = {
#define FD_DECODE_TABLE_DESCS
#include <fadec-table.inc>
#undef FD_DECODE_TABLE_DESCS
    };
    const struct InstrDesc* desc = &descs[table_idx >> 2];

    instr->type = desc->type;
    instr->addrsz = addr_size;
    instr->flags = prefix_rep == 2 ? FD_FLAG_REP :
                   prefix_rep == 3 ? FD_FLAG_REPNZ : 0;
    if (mode == DECODE_64)
        instr->flags |= FD_FLAG_64;
    instr->address = address;

    unsigned op_size;
    if (DESC_OPSIZE(desc) == 1)
        op_size = 1;
    else if (mode == DECODE_64)
        op_size = ((prefix_rex & PREFIX_REXW) || DESC_OPSIZE(desc) == 3) ? 8 :
                                UNLIKELY(prefix_66 && !DESC_IGN66(desc)) ? 2 :
                                                       DESC_OPSIZE(desc) ? 8 :
                                                                           4;
    else
        op_size = UNLIKELY(prefix_66 && !DESC_IGN66(desc)) ? 2 : 4;

    uint8_t vec_size = 16;
    if (prefix_rex & PREFIX_VEXL)
        vec_size = 32;

    __builtin_memset(instr->operands, 0, sizeof(instr->operands));

    if (DESC_MODRM(desc) && UNLIKELY(off++ >= len))
        return FD_ERR_PARTIAL;
    unsigned op_byte = buffer[off - 1] | (!DESC_MODRM(desc) ? 0xc0 : 0);

    if (UNLIKELY(instr->type == FDI_MOV_CR || instr->type == FDI_MOV_DR)) {
        unsigned modreg = (op_byte >> 3) & 0x7;
        unsigned modrm = op_byte & 0x7;

        FdOp* op_modreg = &instr->operands[DESC_MODREG_IDX(desc)];
        op_modreg->type = FD_OT_REG;
        op_modreg->reg = modreg | (prefix_rex & PREFIX_REXR ? 8 : 0);
        op_modreg->misc = instr->type == FDI_MOV_CR ? FD_RT_CR : FD_RT_DR;
        if (instr->type == FDI_MOV_CR && (~0x011d >> op_modreg->reg) & 1)
            return FD_ERR_UD;
        else if (instr->type == FDI_MOV_DR && prefix_rex & PREFIX_REXR)
            return FD_ERR_UD;

        FdOp* op_modrm = &instr->operands[DESC_MODRM_IDX(desc)];
        op_modrm->type = FD_OT_REG;
        op_modrm->reg = modrm | (prefix_rex & PREFIX_REXB ? 8 : 0);
        op_modrm->misc = FD_RT_GPL;
        goto skip_modrm;
    }

    if (UNLIKELY(DESC_HAS_IMPLICIT(desc)))
    {
        FdOp* operand = &instr->operands[DESC_IMPLICIT_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->reg = DESC_IMPLICIT_VAL(desc);
        unsigned reg_ty = DESC_REGTY_ZEROREG(desc); // GPL VEC FPU
        operand->misc = (0461 >> (3 * reg_ty)) & 0x7;
    }

    if (DESC_HAS_MODREG(desc))
    {
        FdOp* op_modreg = &instr->operands[DESC_MODREG_IDX(desc)];
        unsigned reg_idx = (op_byte & 0x38) >> 3;
        unsigned reg_ty = DESC_REGTY_MODREG(desc); // GPL VEC MSK - MMX SEG
        op_modreg->misc = (0350761 >> (3 * reg_ty)) & 0x7;
        if (LIKELY(!(reg_ty & 4)))
            reg_idx += prefix_rex & PREFIX_REXR ? 8 : 0;
        op_modreg->type = FD_OT_REG;
        op_modreg->reg = reg_idx;
    }

    if (DESC_HAS_MODRM(desc))
    {
        FdOp* op_modrm = &instr->operands[DESC_MODRM_IDX(desc)];

        unsigned mod = (op_byte & 0xc0) >> 6;
        unsigned rm = op_byte & 0x07;
        if (mod == 3)
        {
            uint8_t reg_idx = rm;
            unsigned reg_ty = DESC_REGTY_MODRM(desc); // GPL VEC - - MMX FPU MSK
            op_modrm->misc = (07450061 >> (3 * reg_ty)) & 0x7;
            if (LIKELY(!(reg_ty & 4)))
                reg_idx += prefix_rex & PREFIX_REXB ? 8 : 0;
            op_modrm->type = FD_OT_REG;
            op_modrm->reg = reg_idx;
        }
        else
        {
            bool vsib = UNLIKELY(DESC_VSIB(desc));

            // SIB byte
            uint8_t base = rm;
            if (rm == 4)
            {
                if (UNLIKELY(off >= len))
                    return FD_ERR_PARTIAL;
                uint8_t sib = buffer[off++];
                unsigned scale = (sib & 0xc0) >> 6;
                unsigned idx = (sib & 0x38) >> 3;
                idx += prefix_rex & PREFIX_REXX ? 8 : 0;
                base = sib & 0x07;
                if (!vsib && idx == 4)
                    idx = FD_REG_NONE;
                op_modrm->misc = (scale << 6) | idx;
            }
            else
            {
                // VSIB must have a memory operand with SIB byte.
                if (vsib)
                    return FD_ERR_UD;
                op_modrm->misc = FD_REG_NONE;
            }

            op_modrm->type = FD_OT_MEM;

            // RIP-relative addressing only if SIB-byte is absent
            if (mod == 0 && rm == 5 && mode == DECODE_64)
                op_modrm->reg = FD_REG_IP;
            else if (mod == 0 && base == 5)
                op_modrm->reg = FD_REG_NONE;
            else
                op_modrm->reg = base + (prefix_rex & PREFIX_REXB ? 8 : 0);

            if (mod == 1)
            {
                if (UNLIKELY(off + 1 > len))
                    return FD_ERR_PARTIAL;
                instr->disp = (int8_t) LOAD_LE_1(&buffer[off]);
                off += 1;
            }
            else if (mod == 2 || (mod == 0 && base == 5))
            {
                if (UNLIKELY(off + 4 > len))
                    return FD_ERR_PARTIAL;
                instr->disp = (int32_t) LOAD_LE_4(&buffer[off]);
                off += 4;
            }
            else
            {
                instr->disp = 0;
            }
        }
    }
skip_modrm:

    if (UNLIKELY(DESC_HAS_VEXREG(desc)))
    {
        FdOp* operand = &instr->operands[DESC_VEXREG_IDX(desc)];
        operand->type = FD_OT_REG;
        if (mode == DECODE_32)
            vex_operand &= 0x7;
        operand->reg = vex_operand;

        unsigned reg_ty = DESC_REGTY_VEXREG(desc); // GPL VEC MSK
        operand->misc = (0761 >> (3 * reg_ty)) & 0x7;
    }
    else if (vex_operand != 0)
    {
        return FD_ERR_UD;
    }

    uint32_t imm_control = DESC_IMM_CONTROL(desc);
    if (UNLIKELY(imm_control == 1))
    {
        // 1 = immediate constant 1, used for shifts
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;
        instr->imm = 1;
    }
    else if (UNLIKELY(imm_control == 2))
    {
        // 2 = memory, address-sized, used for mov with moffs operand
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_MEM;
        operand->reg = FD_REG_NONE;
        operand->misc = FD_REG_NONE;

        if (UNLIKELY(off + addr_size > len))
            return FD_ERR_PARTIAL;
        if (addr_size == 2)
            instr->disp = LOAD_LE_2(&buffer[off]);
        if (addr_size == 4)
            instr->disp = LOAD_LE_4(&buffer[off]);
        if (LIKELY(addr_size == 8))
            instr->disp = LOAD_LE_8(&buffer[off]);
        off += addr_size;
    }
    else if (UNLIKELY(imm_control == 3))
    {
        // 3 = register in imm8[7:4], used for RVMR encoding with VBLENDVP[SD]
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->misc = FD_RT_VEC;

        if (UNLIKELY(off + 1 > len))
            return FD_ERR_PARTIAL;
        uint8_t reg = (uint8_t) LOAD_LE_1(&buffer[off]);
        off += 1;

        if (mode == DECODE_32)
            reg &= 0x7f;
        operand->reg = reg >> 4;
        instr->imm = reg & 0x0f;
    }
    else if (imm_control != 0)
    {
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;

        // 4/5 = immediate, operand-sized/8 bit
        // 6/7 = offset, operand-sized/8 bit (used for jumps/calls)
        int imm_byte = imm_control & 1;
        int imm_offset = imm_control & 2;

        uint8_t imm_size;
        if (imm_byte)
            imm_size = 1;
        else if (UNLIKELY(instr->type == FDI_RET || instr->type == FDI_RETF ||
                          instr->type == FDI_SSE_EXTRQ ||
                          instr->type == FDI_SSE_INSERTQ))
            imm_size = 2;
        else if (UNLIKELY(instr->type == FDI_JMPF || instr->type == FDI_CALLF))
            imm_size = op_size + 2;
        else if (UNLIKELY(instr->type == FDI_ENTER))
            imm_size = 3;
        else if (instr->type == FDI_MOVABS)
            imm_size = op_size;
        else
            imm_size = op_size == 2 ? 2 : 4;

        if (UNLIKELY(off + imm_size > len))
            return FD_ERR_PARTIAL;

        if (imm_size == 1)
            instr->imm = (int8_t) LOAD_LE_1(&buffer[off]);
        else if (imm_size == 2)
            instr->imm = (int16_t) LOAD_LE_2(&buffer[off]);
        else if (imm_size == 3)
            instr->imm = LOAD_LE_3(&buffer[off]);
        else if (imm_size == 4)
            instr->imm = (int32_t) LOAD_LE_4(&buffer[off]);
        else if (imm_size == 6)
            instr->imm = LOAD_LE_4(&buffer[off]) | LOAD_LE_2(&buffer[off+4]) << 32;
        else if (imm_size == 8)
            instr->imm = (int64_t) LOAD_LE_8(&buffer[off]);
        off += imm_size;

        if (imm_offset)
        {
            if (instr->address != 0)
                instr->imm += instr->address + off;
            else
                operand->type = FD_OT_OFF;
        }
    }

    if (instr->type == FDI_XCHG_NOP)
    {
        // Only 4890, 90, and 6690 are true NOPs.
        if (instr->operands[0].reg == 0 && instr->operands[1].reg == 0)
        {
            instr->operands[0].type = FD_OT_NONE;
            instr->operands[1].type = FD_OT_NONE;
            instr->type = FDI_NOP;
        }
        else
        {
            instr->type = FDI_XCHG;
        }
    }

    if (UNLIKELY(instr->type == FDI_3DNOW))
    {
        unsigned opc3dn = instr->imm;
        if (opc3dn & 0x40)
            return FD_ERR_UD;
        uint64_t msk = opc3dn & 0x80 ? 0x88d144d144d14400 : 0x30003000;
        if (!(msk >> (opc3dn & 0x3f) & 1))
            return FD_ERR_UD;
    }

    if (UNLIKELY(prefix_lock)) {
        if (!DESC_LOCK(desc) || instr->operands[0].type != FD_OT_MEM)
            return FD_ERR_UD;
        instr->flags |= FD_FLAG_LOCK;
    }

    uint8_t operand_sizes[4] = {
        1 << DESC_SIZE_FIX1(desc) >> 1, 1 << DESC_SIZE_FIX2(desc), op_size, vec_size
    };

    for (int i = 0; i < 4; i++)
    {
        FdOp* operand = &instr->operands[i];
        if (operand->type == FD_OT_NONE)
            break;

        operand->size = operand_sizes[(desc->operand_sizes >> 2 * i) & 3];
    }

    if (UNLIKELY(op_size == 1 || instr->type == FDI_MOVSX || instr->type == FDI_MOVZX)) {
        if (!(prefix_rex & PREFIX_REX)) {
            for (int i = 0; i < 2; i++) {
                FdOp* operand = &instr->operands[i];
                if (operand->type == FD_OT_NONE)
                    break;
                if (operand->type == FD_OT_REG && operand->misc == FD_RT_GPL &&
                    operand->size == 1 && operand->reg >= 4)
                    operand->misc = FD_RT_GPH;
            }
        }
    }

    instr->size = off;
    instr->operandsz = DESC_INSTR_WIDTH(desc) ? op_size : 0;

    return off;
}
