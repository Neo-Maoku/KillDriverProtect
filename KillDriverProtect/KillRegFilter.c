#include "KillRegFilter.h"
#include "Helper.h"

PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize);
PVOID SearchCallbackListHead(PUCHAR pSpecialData, ULONG ulSpecialDataSize, LONG lSpecialOffset);
PVOID GetCallbackListHead();

typedef struct _CM_NOTIFY_ENTRY
{
	LIST_ENTRY ListEntryHead;
	ULONG UnKnown1;
	ULONG UnKnown2;
	LARGE_INTEGER Cookie;
	ULONG64 Context;
	ULONG64 Function;
}CM_NOTIFY_ENTRY, *PCM_NOTIFY_ENTRY;

ULONG KillRegFilter()
{
	LARGE_INTEGER cookie;
	NTSTATUS Status;
	ULONG sum = 0;
	ULONG64 dwNotifyItemAddr;
	PLIST_ENTRY notifyList;
	PCM_NOTIFY_ENTRY notify;
	ULONG64* pPspLINotifyRoutine = GetCallbackListHead();
	dwNotifyItemAddr = *pPspLINotifyRoutine;
	notifyList = (LIST_ENTRY*)dwNotifyItemAddr;

	while (!IsListEmpty(notifyList))
	{
		notify = (CM_NOTIFY_ENTRY*)notifyList;
		if (MmIsAddressValid(notify))
		{
			if (MmIsAddressValid((PVOID)(notify->Function)) && notify->Function > 0x8000000000000000)
			{
				cookie = notify->Cookie;

				sum++;
			}
		}
		notifyList = notifyList->Flink;
		Status = CmUnRegisterCallback(cookie);
		if (NT_SUCCESS(Status))
		{
			LogInfo("删除[CmCallback]Function=%p\t回调", (PVOID)(notify->Function));
		}
	}
	return sum;
}

// 获取 CallbackListHead 链表地址
PVOID GetCallbackListHead()
{
	PVOID pCallbackListHeadAddress = NULL;
	RTL_OSVERSIONINFOW osInfo = { 0 };
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;
	LONG lSpecialOffset = 0;

	// 获取系统版本信息, 判断系统版本
	RtlGetVersion(&osInfo);
	if (6 == osInfo.dwMajorVersion)
	{
		if (1 == osInfo.dwMinorVersion)
		{
			// Win7
# ifdef _WIN64
			// 64 位
			// 488D54
			pSpecialData[0] = 0x48;
			pSpecialData[1] = 0x8D;
			pSpecialData[2] = 0x54;
			ulSpecialDataSize = 3;
			lSpecialOffset = 5;
# else
			// 32 位
			// BF
			pSpecialData[0] = 0xBF;
			ulSpecialDataSize = 1;
# endif	
		}
		else if (2 == osInfo.dwMinorVersion)
		{
			// Win8
# ifdef _WIN64
			// 64 位

# else
			// 32 位

# endif
		}
		else if (3 == osInfo.dwMinorVersion)
		{
			// Win8.1
# ifdef _WIN64
			// 64 位
			// 488D0D
			pSpecialData[0] = 0x48;
			pSpecialData[1] = 0x8D;
			pSpecialData[2] = 0x0D;
			ulSpecialDataSize = 3;
# else
			// 32 位
			// BE
			pSpecialData[0] = 0xBE;
			ulSpecialDataSize = 1;
# endif			
		}
	}
	else if (10 == osInfo.dwMajorVersion)
	{
		// Win10
# ifdef _WIN64
		// 64 位
		// 488D0D
		pSpecialData[0] = 0x48;
		pSpecialData[1] = 0x8D;
		pSpecialData[2] = 0x0D;
		ulSpecialDataSize = 3;
# else
		// 32 位
		// B9
		pSpecialData[0] = 0xB9;
		ulSpecialDataSize = 1;
# endif
	}

	// 根据特征码获取地址
	pCallbackListHeadAddress = SearchCallbackListHead(pSpecialData, ulSpecialDataSize, lSpecialOffset);
	return pCallbackListHeadAddress;
}

// 根据特征码获取 CallbackListHead 链表地址
PVOID SearchCallbackListHead(PUCHAR pSpecialData, ULONG ulSpecialDataSize, LONG lSpecialOffset)
{
	UNICODE_STRING ustrFuncName;
	PVOID pAddress = NULL;
	LONG lOffset = 0;
	PVOID pCmUnRegisterCallback = NULL;
	PVOID pCallbackListHead = NULL;

	// 先获取 CmUnRegisterCallback 函数地址
	RtlInitUnicodeString(&ustrFuncName, L"CmUnRegisterCallback");
	pCmUnRegisterCallback = MmGetSystemRoutineAddress(&ustrFuncName);
	if (NULL == pCmUnRegisterCallback)
	{
		LogError("MmGetSystemRoutineAddress get fail");
		return pCallbackListHead;
	}

	// 然后, 查找 PspSetCreateProcessNotifyRoutine 函数地址
	pAddress = SearchMemory(pCmUnRegisterCallback,
		(PVOID)((PUCHAR)pCmUnRegisterCallback + 0xFF),
		pSpecialData, ulSpecialDataSize);
	if (NULL == pAddress)
	{
		LogError("SearchMemory fail");
		return pCallbackListHead;
	}

	// 获取地址
# ifdef _WIN64
	// 64 位先获取偏移, 再计算地址
	lOffset = *(PLONG)((PUCHAR)pAddress + lSpecialOffset);
	pCallbackListHead = (PVOID)((PUCHAR)pAddress + lSpecialOffset + sizeof(LONG) + lOffset);
# else
	// 32 位直接获取地址
	pCallbackListHead = *(PVOID *)((PUCHAR)pAddress + lSpecialOffset);
# endif

	return pCallbackListHead;
}

// 指定内存区域的特征码扫描
PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{
	PVOID pAddress = NULL;
	PUCHAR i = NULL;
	ULONG m = 0;

	// 扫描内存
	for (i = (PUCHAR)pStartAddress; i < (PUCHAR)pEndAddress; i++)
	{
		// 判断特征码
		for (m = 0; m < ulMemoryDataSize; m++)
		{
			if (*(PUCHAR)(i + m) != pMemoryData[m])
			{
				break;
			}
		}
		// 判断是否找到符合特征码的地址
		if (m >= ulMemoryDataSize)
		{
			// 找到特征码位置, 获取紧接着特征码的下一地址
			pAddress = (PVOID)(i + ulMemoryDataSize);
			break;
		}
	}

	return pAddress;
}