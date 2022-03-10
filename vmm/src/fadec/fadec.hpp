
#ifndef FD_FADEC_H_
#define FD_FADEC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FD_REG_R0 = 0, FD_REG_R1, FD_REG_R2, FD_REG_R3,
    FD_REG_R4, FD_REG_R5, FD_REG_R6, FD_REG_R7,
    FD_REG_R8, FD_REG_R9, FD_REG_R10, FD_REG_R11,
    FD_REG_R12, FD_REG_R13, FD_REG_R14, FD_REG_R15,
    // Alternative names for byte registers
    FD_REG_AL = 0, FD_REG_CL, FD_REG_DL, FD_REG_BL,
    FD_REG_AH, FD_REG_CH, FD_REG_DH, FD_REG_BH,
    // Alternative names for general purpose registers
    FD_REG_AX = 0, FD_REG_CX, FD_REG_DX, FD_REG_BX,
    FD_REG_SP, FD_REG_BP, FD_REG_SI, FD_REG_DI,
    // FD_REG_IP can only be accessed in long mode (64-bit)
    FD_REG_IP = 0x10,
    // Segment register values
    FD_REG_ES = 0, FD_REG_CS, FD_REG_SS, FD_REG_DS, FD_REG_FS, FD_REG_GS,
    // No register specified
    FD_REG_NONE = 0x3f
} FdReg;

typedef enum {
#define FD_MNEMONIC(name,value) FDI_ ## name = value,
#include <fadec-mnems.inc>
#undef FD_MNEMONIC
} FdInstrType;

/** Internal use only. **/
enum {
    FD_FLAG_LOCK = 1 << 0,
    FD_FLAG_REP = 1 << 1,
    FD_FLAG_REPNZ = 1 << 2,
    FD_FLAG_64 = 1 << 7,
};

/** Operand types. **/
typedef enum {
    FD_OT_NONE = 0,
    FD_OT_REG = 1,
    FD_OT_IMM = 2,
    FD_OT_MEM = 3,
    FD_OT_OFF = 4,
} FdOpType;

typedef enum {
    /** Register type is encoded in mnemonic **/
    FD_RT_IMP = 0,
    /** Low general purpose register **/
    FD_RT_GPL = 1,
    /** High-byte general purpose register **/
    FD_RT_GPH = 2,
    /** Segment register **/
    FD_RT_SEG = 3,
    /** FPU register ST(n) **/
    FD_RT_FPU = 4,
    /** MMX register MMn **/
    FD_RT_MMX = 5,
    /** Vector (SSE/AVX) register XMMn/YMMn/ZMMn **/
    FD_RT_VEC = 6,
    /** Vector mask (AVX-512) register Kn **/
    FD_RT_MASK = 7,
    /** Bound register BNDn **/
    FD_RT_BND = 8,
    /** Control Register CRn **/
    FD_RT_CR = 9,
    /** Debug Register DRn **/
    FD_RT_DR = 10,
    /** Must be a memory operand **/
    FD_RT_MEM = 15,
} FdRegType;

/** Internal use only. **/
typedef struct {
    uint8_t type;
    uint8_t size;
    uint8_t reg;
    uint8_t misc;
} FdOp;

/** Never(!) access struct fields directly. Use the macros defined below. **/
typedef struct {
    uint16_t type;
    uint8_t flags;
    uint8_t segment;
    uint8_t addrsz;
    uint8_t operandsz;
    uint8_t size;
    uint8_t _pad0;

    FdOp operands[4];

    int64_t disp;
    int64_t imm;

    uint64_t address;
} FdInstr;

typedef enum {
    FD_ERR_UD = -1,
    FD_ERR_INTERNAL = -2,
    FD_ERR_PARTIAL = -3,
} FdErr;


/** Decode an instruction.
 * \param buf Buffer for instruction bytes.
 * \param len Length of the buffer (in bytes). An instruction is not longer than
 *        15 bytes on all x86 architectures.
 * \param mode Decoding mode, either 32 for protected/compatibility mode or 64
 *        for long mode. 16-bit mode is not supported.
 * \param address Virtual address where the decoded instruction. This is used
 *        for computing jump targets. If "0" is passed, operands which require
 *        adding EIP/RIP will be stored as FD_OT_OFF operands.
 *        DEPRECATED: Strongly prefer passing 0 and using FD_OT_OFF operands.
 * \param out_instr Pointer to the instruction buffer. Note that this may get
 *        partially written even if an error is returned.
 * \return The number of bytes consumed by the instruction, or a negative number
 *         indicating an error.
 **/
int fd_decode(const uint8_t* buf, size_t len, int mode, uintptr_t address,
              FdInstr* out_instr);

/** Format an instruction to a string.
 * \param instr The instruction.
 * \param buf The buffer to hold the formatted string.
 * \param len The length of the buffer.
 **/
void fd_format(const FdInstr* instr, char* buf, size_t len);

/** Format an instruction to a string.
 * NOTE: API stability is currently not guaranteed for this function; its name
 * and/or signature may change in future.
 *
 * \param instr The instruction.
 * \param addr The base address to use for printing FD_OT_OFF operands.
 * \param buf The buffer to hold the formatted string.
 * \param len The length of the buffer.
 **/
void fd_format_abs(const FdInstr* instr, uint64_t addr, char* buf, size_t len);

/** Get the stringified name of an instruction type.
 * NOTE: API stability is currently not guaranteed for this function; changes
 * to the signature and/or the returned string can be expected. E.g., a future
 * version may take an extra parameter for the instruction operand size; or may
 * take a complete decoded instruction as first parameter and return the
 * mnemonic returned by fd_format.
 *
 * \param ty An instruction type
 * \return The instruction type as string, or "(invalid)".
 **/
const char* fdi_name(FdInstrType ty);


/** Gets the type/mnemonic of the instruction.
 * ABI STABILITY NOTE: different versions or builds of the library may use
 * different values. When linking as shared library, any interpretation of this
 * value is meaningless; in such cases use  fdi_name.
 *
 * API STABILITY NOTE: a future version of this library may decode string
 * instructions prefixed with REP/REPNZ and instructions prefixed with LOCK as
 * separate instruction types. **/
#define FD_TYPE(instr) ((FdInstrType) (instr)->type)
/** DEPRECATED: This functionality is obsolete in favor of FD_OT_OFF.
 * Gets the address of the instruction. Invalid if decoded  address == 0. **/
#define FD_ADDRESS(instr) ((instr)->address)
/** Gets the size of the instruction in bytes. **/
#define FD_SIZE(instr) ((instr)->size)
/** Gets the specified segment override, or FD_REG_NONE for default segment. **/
#define FD_SEGMENT(instr) ((FdReg) (instr)->segment)
/** Gets the address size attribute of the instruction in bytes. **/
#define FD_ADDRSIZE(instr) ((instr)->addrsz)
/** Gets the operation width in bytes of the instruction if this is not encoded
 * in the operands, for example for the string instruction (e.g. MOVS). **/
#define FD_OPSIZE(instr) ((instr)->operandsz)
/** Indicates whether the instruction was encoded with a REP prefix. Needed for:
 * (1) Handling the instructions MOVS, STOS, LODS, INS and OUTS properly.
 * (2) Handling the instructions SCAS and CMPS, for which this means REPZ. **/
#define FD_HAS_REP(instr) ((instr)->flags & FD_FLAG_REP)
/** Indicates whether the instruction was encoded with a REPNZ prefix. **/
#define FD_HAS_REPNZ(instr) ((instr)->flags & FD_FLAG_REPNZ)
/** Indicates whether the instruction was encoded with a LOCK prefix. **/
#define FD_HAS_LOCK(instr) ((instr)->flags & FD_FLAG_LOCK)
/** Do not use. **/
#define FD_IS64(instr) ((instr)->flags & FD_FLAG_64)

/** Gets the type of an operand at the given index. **/
#define FD_OP_TYPE(instr,idx) ((FdOpType) (instr)->operands[idx].type)
/** Gets the size in bytes of an operand. However, there are a few exceptions:
 * (1) For some register types, e.g., segment registers, or x87 registers, the
 *     size is zero. (This allows some simplifications internally.)
 * (2) On some vector instructions this may be only an approximation of the
 *     actually needed operand size (that is, an instruction may/must only use
 *     a smaller part than specified here). The real operand size is always
 *     fully recoverable in combination with the instruction type. **/
#define FD_OP_SIZE(instr,idx) ((instr)->operands[idx].size)
/** Gets the accessed register index of a register operand. Note that /only/ the
 * index is returned, no further interpretation of the index (which depends on
 * the instruction type) is done. The register type can be fetched using
 * FD_OP_REG_TYPE, e.g. for distinguishing high-byte registers.
 * Only valid if  FD_OP_TYPE == FD_OT_REG  **/
#define FD_OP_REG(instr,idx) ((FdReg) (instr)->operands[idx].reg)
/** Gets the type of the accessed register.
 * Only valid if  FD_OP_TYPE == FD_OT_REG  **/
#define FD_OP_REG_TYPE(instr,idx) ((FdRegType) (instr)->operands[idx].misc)
/** DEPRECATED: use FD_OP_REG_TYPE() == FD_RT_GPH instead.
 * Returns whether the accessed register is a high-byte register. In that case,
 * the register index has to be decreased by 4.
 * Only valid if  FD_OP_TYPE == FD_OT_REG  **/
#define FD_OP_REG_HIGH(instr,idx) (FD_OP_REG_TYPE(instr,idx) == FD_RT_GPH)
/** Gets the index of the base register from a memory operand, or FD_REG_NONE,
 * if the memory operand has no base register. This is the only case where the
 * 64-bit register RIP can be returned, in which case the operand also has no
 * scaled index register.
 * Only valid if  FD_OP_TYPE == FD_OT_MEM  **/
#define FD_OP_BASE(instr,idx) ((FdReg) (instr)->operands[idx].reg)
/** Gets the index of the index register from a memory operand, or FD_REG_NONE,
 * if the memory operand has no scaled index register.
 * Only valid if  FD_OP_TYPE == FD_OT_MEM  **/
#define FD_OP_INDEX(instr,idx) ((FdReg) (instr)->operands[idx].misc & 0x3f)
/** Gets the scale of the index register from a memory operand when existent.
 * This does /not/ return the scale in an absolute value but returns the amount
 * of bits the index register is shifted to the left (i.e. the value in in the
 * range 0-3). The actual scale can be computed easily using  1<<FD_OP_SCALE.
 * Only valid if  FD_OP_TYPE == FD_OT_MEM  and  FD_OP_INDEX != FD_REG_NONE **/
#define FD_OP_SCALE(instr,idx) ((instr)->operands[idx].misc >> 6)
/** Gets the sign-extended displacement of a memory operand.
 * Only valid if  FD_OP_TYPE == FD_OT_MEM  **/
#define FD_OP_DISP(instr,idx) ((int64_t) (instr)->disp)
/** Gets the (sign-extended) encoded constant for an immediate operand.
 * Only valid if  FD_OP_TYPE == FD_OT_IMM  or  FD_OP_TYPE == FD_OT_OFF  **/
#define FD_OP_IMM(instr,idx) ((instr)->imm)

#ifdef __cplusplus
}
#endif

#endif
