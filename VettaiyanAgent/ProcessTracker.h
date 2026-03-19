/*
 * ProcessTracker.h - Process tree and lifecycle management
 * 
 * Maintains a real-time process tree from kernel telemetry.
 * Used for behavioral detection (parent-child analysis, lineage tracking)
 * and UI process explorer visualization.
 */

#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <windows.h>
#include "../EdrCommon/EdrEvents.h"

struct ProcessNode {
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    ULONG               SessionId;
    std::wstring        ImagePath;
    std::wstring        ImageName;      /* Just the filename */
    std::wstring        CommandLine;
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       ExitTime;
    bool                IsAlive;
    ULONG               ThreadCount;
    std::vector<ULONG>  ChildPids;      /* Direct children */
    std::vector<std::wstring> LoadedImages; /* DLLs loaded by this process */
    int                 SuspicionScore; /* Behavioral scoring */
    std::vector<std::wstring> Alerts;   /* Behavioral alerts */
};

/* Initialize the process tracker */
void InitializeProcessTracker();

/* Shutdown and cleanup */
void ShutdownProcessTracker();

/* Process creation event */
void OnProcessCreate(const EDR_PROCESS_EVENT* event);

/* Process termination event */
void OnProcessTerminate(const EDR_PROCESS_EVENT* event);

/* Image load event */
void OnImageLoad(const EDR_IMAGE_EVENT* event);

/* Thread events for counting */
void OnThreadEvent(const EDR_THREAD_EVENT* event);

/* Lookup a process node by PID */
const ProcessNode* GetProcessNode(ULONG processId);

/* Get all children of a process */
std::vector<ULONG> GetProcessChildren(ULONG processId);

/* Get the full lineage (ancestry) from a PID to root */
std::vector<ULONG> GetProcessLineage(ULONG processId);

/* Get parent image name for a PID */
std::wstring GetParentImageName(ULONG processId);

/* Get all active processes */
std::vector<ProcessNode> GetAllActiveProcesses();

/* Get all processes (including terminated, for timeline) */
std::vector<ProcessNode> GetAllProcesses();

/* Get process count */
size_t GetActiveProcessCount();

/* Add an alert to a process */
void AddProcessAlert(ULONG processId, const std::wstring& alert);

/* Increase suspicion score */
void IncrementSuspicionScore(ULONG processId, int amount);

#endif /* PROCESS_TRACKER_H */
