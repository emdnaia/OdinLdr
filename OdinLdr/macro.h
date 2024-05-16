#pragma section(".text", execute, readwrite)
#pragma section(".rdata", read, reads)
#pragma code_seg(".text$d")
#define DECLARE_BYTE_ARRAY_IN_TEXT_D(name, data) \
    __declspec(allocate(".text$d")) static BYTE name[] = data

#define DECLARE_BYTE_ARRAY_IN_TEXT_D_W(name, data) \
    __declspec(allocate(".text$d")) static WCHAR name[] = data

#define MACRO_STR(bufferName, data) DECLARE_BYTE_ARRAY_IN_TEXT_D(bufferName, data)
#define MACRO_STR_W(bufferNameW, dataW) DECLARE_BYTE_ARRAY_IN_TEXT_D_W(bufferNameW, dataW)

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

