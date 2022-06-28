#pragma once
#include <Ntddk.h>

#define _LogMsg(lvl, lvlname, frmt, ...) \
	DbgPrintEx(\
		DPFLTR_IHVDRIVER_ID, \
		lvl, \
		"[" lvlname "] [irql:%Iu,pid:%Iu,tid:%Iu]\tKillDriverProtect!" __FUNCTION__ ": " frmt "\n", \
		KeGetCurrentIrql(), \
		PsGetCurrentProcessId(), \
		PsGetCurrentThreadId(), \
		__VA_ARGS__ \
	)

#define LogError(frmt,   ...) _LogMsg(DPFLTR_ERROR_LEVEL,   "error",   frmt, __VA_ARGS__)
#define LogWarning(frmt, ...) _LogMsg(DPFLTR_WARNING_LEVEL, "warning", frmt, __VA_ARGS__)
#define LogTrace(frmt,   ...) _LogMsg(DPFLTR_TRACE_LEVEL,   "trace",   frmt, __VA_ARGS__)
#define LogInfo(frmt,    ...) _LogMsg(DPFLTR_INFO_LEVEL,    "info",    frmt, __VA_ARGS__)

VOID DisableFunctionWithReturnZero(PVOID Address, int retType);
VOID DisableFunctionWithReturnOne(PVOID Address, int retType);

KIRQL WPOFF();
void WPON(KIRQL irql);

