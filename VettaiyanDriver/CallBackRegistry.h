#ifndef CALLBACK_REGISTRY_H
#define CALLBACK_REGISTRY_H

#include "DriverHeader.h"

NTSTATUS EdrRegistryNotifyCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID Arg1,
	_In_ PVOID Arg2
);

NTSTATUS RegisterRegistryCallbacks(
	_In_ PVOID DriverObject
);

NTSTATUS UnregisterRegistryCallbacks();

#endif