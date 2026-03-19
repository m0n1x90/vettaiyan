#ifndef CALLBACK_REGISTRY_H
#define CALLBACK_REGISTRY_H

/*
 * CallBackRegistry.h -- registry mutation monitoring.
 *
 * Watches create, delete, rename, and set-value operations across
 * the entire registry. The agent uses these events to detect
 * persistence installs, defense evasion, and policy tampering.
 */

#include "DriverHeader.h"

/* The CmRegisterCallbackEx callback -- fires on every registry operation,
   we filter down to mutations only */
NTSTATUS EdrRegistryNotifyCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID Arg1,
	_In_ PVOID Arg2
);

/* Wire up / tear down the registry callback */
NTSTATUS RegisterRegistryCallbacks(
	_In_ PVOID DriverObject
);
NTSTATUS UnregisterRegistryCallbacks();

#endif