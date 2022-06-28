#include "Helper.h"

VOID DisableFunctionWithReturnZero(PVOID Address, int retType)
{
	KIRQL irql;
	CHAR* patchCode = (char *)ExAllocatePool(NonPagedPool, 5);
	int length;

	if (retType == 0) //ret
	{
		char* temp = "\x33\xC0\xC3";
		length = 3;
		memmove(patchCode, temp, length);
	}
	else if (retType == 1) //ret c
	{
		char* temp = "\x33\xC0\xc2\x0c\x00";
		length = 5;
		memmove(patchCode, temp, length);
	}
	else if (retType == 2) //ret 0x10
	{
		char* temp = "\x33\xC0\xc2\x10\x00";
		length = 5;
		memmove(patchCode, temp, length);
	}

	if (MmIsAddressValid(Address))
	{
		irql = WPOFF();
		memmove(Address, patchCode, length);
		WPON(irql);
	}
}

VOID DisableFunctionWithReturnOne(PVOID Address, int retType)
{
	KIRQL irql;
	CHAR* patchCode = (char *)ExAllocatePool(NonPagedPool, 8);
	int length;

	if (retType == 0) //ret
	{
		char* temp = "\xb8\x01\x00\x00\x00\xc3";
		length = 6;
		memmove(patchCode, temp, length);
	}
	else if (retType == 1) //ret c
	{
		char* temp = "\xb8\x01\x00\x00\x00\xc2\x0c\x00";
		length = 8;
		memmove(patchCode, temp, length);
	}
	else if (retType == 2) //ret 0x10
	{
		char* temp = "\xb8\x01\x00\x00\x00\xc2\x10\x00";
		length = 8;
		memmove(patchCode, temp, length);
	}

	if (MmIsAddressValid(Address))
	{
		irql = WPOFF();
		memmove(Address, patchCode, length);
		WPON(irql);
	}
}

KIRQL WPOFF()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
#ifdef _WIN64
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
# else
	UINT32 cr0 = __readcr0();
	cr0 &= 0xFFFEFFFF;
# endif
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPON(KIRQL irql)
{
#ifdef _WIN64
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
# else
	UINT32 cr0 = __readcr0();
	cr0 |= (!0xFFFEFFFF);
# endif
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
