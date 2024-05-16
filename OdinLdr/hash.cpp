#include <Windows.h>

#pragma code_seg(".text$c")
DWORD HashMeDjb2W(wchar_t* str)
{
	DWORD hash = 5381;
	int c = 0;

	while ((c = *str++)) {
		if (c >= 'A' && c <= 'Z') {
			c += ('a' - 'A');
		}
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

#pragma code_seg(".text$c")
DWORD HashMeDjb2A(char* str)
{
	DWORD hash = 5381;
	int c = 0;

	while ((c = *str++)) {
		if (c >= 'A' && c <= 'Z') {
			c += ('a' - 'A');
		}
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

