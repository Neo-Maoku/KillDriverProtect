#include "KillFsFilter.h"
#include "Helper.h"

int mj_create_pre, mj_dir_pre, mj_dir_post, mj_shutdown_pre;
ULONG FltFilterOperationsOffset;

typedef struct _FLT_FILTER
{
	UCHAR buffer[1024];
} FLT_FILTER, *PFLT_FILTER;

NTSTATUS RemoveCallback(PFLT_FILTER pFilter);
LONG GetOperationsOffset();
VOID getFuncRetType();

ULONG KillFsFilter()
{
	long	ntStatus;
	ULONG	uNumber;
	PVOID	pBuffer = NULL;
	ULONG	uIndex = 0, DrvCount = 0;
	PVOID	pCallBacks = NULL, pFilter = NULL;
	PFLT_OPERATION_REGISTRATION pNode;
	FltFilterOperationsOffset = GetOperationsOffset();
	getFuncRetType();
	LogInfo("logoinfo");
	LogError("error");
	do
	{
		if (pBuffer != NULL)
		{
			ExFreePool(pBuffer);
			pBuffer = NULL;
		}
		ntStatus = FltEnumerateFilters(NULL, 0, &uNumber);

		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			break;

		pBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(PFLT_FILTER) * uNumber, 'mnft');

		if (pBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		ntStatus = FltEnumerateFilters(pBuffer, uNumber, &uNumber);
	} while (ntStatus == STATUS_BUFFER_TOO_SMALL);

	if (!NT_SUCCESS(ntStatus))
	{
		if (pBuffer != NULL)
			ExFreePool(pBuffer);

		return 0;
	}

	LogInfo("MiniFilter Count: %ld", uNumber);
	LogInfo("------");

	__try
	{
		while (DrvCount < uNumber)
		{
#ifdef _WIN64
			pFilter = (PVOID)(*(PULONG64)((PUCHAR)pBuffer + DrvCount * 8));
#else
			pFilter = (PVOID)(*(PULONG64)((PUCHAR)pBuffer + DrvCount * 4));
#endif
			pCallBacks = (PVOID)((PUCHAR)pFilter + FltFilterOperationsOffset);
			pNode = (PFLT_OPERATION_REGISTRATION)(*(PULONG64)pCallBacks);

			BOOLEAN create_flag = FALSE, directory_flag = FALSE;
			int count = 0;
			__try
			{
				while (pNode->MajorFunction != 0x80)
				{
					if (pNode->MajorFunction < 28)
					{
						if (pNode->MajorFunction == 0x0) create_flag = TRUE;
						if (pNode->MajorFunction == 0xc) directory_flag = TRUE;
						count++;
					}
					pNode++;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				FltObjectDereference(pFilter);
				LogError("[EnumMiniFilter]EXCEPTION_EXECUTE_HANDLER: pNode->MajorFunction");
				ntStatus = GetExceptionCode();
				ExFreePool(pBuffer);
				return uIndex;
			}

			if (create_flag && directory_flag && count <= 3) { RemoveCallback(pFilter); }
			else
			{
				pNode = (PFLT_OPERATION_REGISTRATION)(*(PULONG64)pCallBacks);
				while (pNode->MajorFunction != 0x80)
				{
					if (pNode->MajorFunction < 28)
					{
						LogInfo("Object=%p\tPreFunc=%p\tPostFunc=%p\tIRP=%d\n", pFilter, pNode->PreOperation, pNode->PostOperation, pNode->MajorFunction);
					}
					pNode++;
				}
			}

			DrvCount++;
			FltObjectDereference(pFilter);
			LogInfo("----------------");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		FltObjectDereference(pFilter);
		LogError("[EnumMiniFilter]EXCEPTION_EXECUTE_HANDLER");
		ntStatus = GetExceptionCode();
		ExFreePool(pBuffer);
		return uIndex;
	}

	if (pBuffer != NULL)
	{
		ExFreePool(pBuffer);
		ntStatus = STATUS_SUCCESS;
	}

	return uIndex;
}

VOID getFuncRetType()
{
#ifdef _WIN64
	mj_create_pre = 0;
	mj_dir_pre = 0;
	mj_dir_post = 0;
	mj_shutdown_pre = 0;
#else
	mj_create_pre = 1;
	mj_dir_pre = 1;
	mj_dir_post = 2;
	mj_shutdown_pre = 1;
#endif
}

LONG GetOperationsOffset()
{
	RTL_OSVERSIONINFOW osInfo = { 0 };
	LONG lOperationsOffset = 0;

	// 获取系统版本信息, 判断系统版本
	RtlGetVersion(&osInfo);
	if (6 == osInfo.dwMajorVersion)
	{
		if (1 == osInfo.dwMinorVersion)
		{
			// Win7
# ifdef _WIN64
			// 64 位
			// 0x188
			lOperationsOffset = 0x188;
# else
			// 32 位
			// 0xCC
			lOperationsOffset = 0xCC;
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
			// 0x198
			lOperationsOffset = 0x198;
# else
			// 32 位
			// 0xD4
			lOperationsOffset = 0xD4;
# endif			
		}
	}
	else if (10 == osInfo.dwMajorVersion)
	{
		// Win10
# ifdef _WIN64
		// 64 位
		// 0x1A8
		lOperationsOffset = 0x1A8;
# else
		// 32 位
		// 0xE4
		lOperationsOffset = 0xE4;
# endif
	}

	return lOperationsOffset;
}

NTSTATUS RemoveCallback(PFLT_FILTER pFilter)
{
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;

	// 开始遍历 过滤器Filter 的信息
	// 获取 PFLT_FILTER 中 Operations 成员地址
	LogInfo("offset = %x", FltFilterOperationsOffset);
	pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID *)((PUCHAR)pFilter + FltFilterOperationsOffset));

	__try
	{
		// 同一过滤器下的回调信息
		while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
		{
			if (IRP_MJ_MAXIMUM_FUNCTION > pFltOperationRegistration->MajorFunction)
			{
				if (pFltOperationRegistration->MajorFunction == IRP_MJ_CREATE)
				{
					DisableFunctionWithReturnOne(pFltOperationRegistration->PreOperation, mj_create_pre);
				}
				else if (pFltOperationRegistration->MajorFunction == IRP_MJ_DIRECTORY_CONTROL)
				{
					DisableFunctionWithReturnZero(pFltOperationRegistration->PreOperation, mj_dir_pre);
					DisableFunctionWithReturnZero(pFltOperationRegistration->PostOperation, mj_dir_post);
				}
				else if (pFltOperationRegistration->MajorFunction == IRP_MJ_SHUTDOWN)
				{
					DisableFunctionWithReturnOne(pFltOperationRegistration->PreOperation, mj_shutdown_pre);
				}

				LogInfo("[Filter=%p]IRP=%d, PreFunc=0x%p, PostFunc=0x%p\n", pFilter, pFltOperationRegistration->MajorFunction,
					pFltOperationRegistration->PreOperation, pFltOperationRegistration->PostOperation);
			}
			// 获取下一个消息回调信息
			pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LogError("[EXCEPTION_EXECUTE_HANDLER]\n");
	}

	return STATUS_SUCCESS;
}