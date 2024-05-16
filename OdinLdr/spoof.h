#pragma once
#include <Windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5

typedef PRUNTIME_FUNCTION(WINAPI* RTLLOOKUPFUNCTIONENTRY)       (DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);

typedef struct
{
    PVOID       Fixup;             // 0
    PVOID       OG_retaddr;        // 8
    PVOID       rbx;               // 16
    PVOID       rdi;               // 24
    PVOID       BTIT_ss;           // 32
    PVOID       BTIT_retaddr;      // 40
    PVOID       Gadget_ss;         // 48
    PVOID       RUTS_ss;           // 56
    PVOID       RUTS_retaddr;      // 64
    PVOID       ssn;               // 72  
    PVOID       trampoline;        // 80
    PVOID       rsi;               // 88
    PVOID       r12;               // 96
    PVOID       r13;               // 104
    PVOID       r14;               // 112
    PVOID       r15;               // 120
} PRM, * PPRM;

/* God Bless Vulcan Raven*/
typedef struct
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

#define SPOOF_0(func) Spoofer(func, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
#define SPOOF_1(func, arg1) Spoofer(func, arg1, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
#define SPOOF_2(func, arg1, arg2) Spoofer(func, arg1, arg2, NULL, NULL, NULL, NULL, NULL, NULL)
#define SPOOF_3(func, arg1, arg2, arg3) Spoofer(func, arg1, arg2, arg3, NULL, NULL, NULL, NULL, NULL)
#define SPOOF_4(func, arg1, arg2, arg3, arg4) Spoofer(func, arg1, arg2, arg3, arg4, NULL, NULL, NULL, NULL)
#define SPOOF_5(func, arg1, arg2, arg3, arg4, arg5) Spoofer(func, arg1, arg2, arg3, arg4, arg5, NULL, NULL, NULL)
#define SPOOF_6(func, arg1, arg2, arg3, arg4, arg5, arg6) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, NULL, NULL)
#define SPOOF_7(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, NULL)
#define SPOOF_8(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#define GET_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define SPOOF(...) GET_MACRO(__VA_ARGS__, SPOOF_8, SPOOF_7, SPOOF_6, SPOOF_5, SPOOF_4, SPOOF_3, SPOOF_2, SPOOF_1, SPOOF_0)(__VA_ARGS__)


ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress);
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase, StackFrame* stackFrame);
PVOID FindGadget(LPBYTE Module, ULONG Size);
void* Spoofer(void* pFunctionAddr, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8);


extern "C" PVOID Spoof(...);

