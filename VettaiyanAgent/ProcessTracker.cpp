/*
 * ProcessTracker.cpp - Real-time process tree management
 */

#include "ProcessTracker.h"
#include "Log.h"

#include <algorithm>

static std::unordered_map<ULONG, ProcessNode> g_ProcessMap;
static std::mutex g_ProcessMapMutex;
static const size_t MAX_TRACKED_PROCESSES = 50000;
static const size_t MAX_LOADED_IMAGES_PER_PROCESS = 200;


static std::wstring ExtractFileName(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}


void InitializeProcessTracker()
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    g_ProcessMap.clear();
    LogMessage(L"[ ProcessTracker ] Initialized");
}


void ShutdownProcessTracker()
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    g_ProcessMap.clear();
    LogMessage(L"[ ProcessTracker ] Shutdown");
}


void OnProcessCreate(const EDR_PROCESS_EVENT* event)
{
    if (!event) return;

    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);

    /* Evict old terminated processes if map is too large */
    if (g_ProcessMap.size() >= MAX_TRACKED_PROCESSES) {
        for (auto it = g_ProcessMap.begin(); it != g_ProcessMap.end();) {
            if (!it->second.IsAlive) {
                it = g_ProcessMap.erase(it);
            } else {
                ++it;
            }
        }
    }

    ProcessNode node = {};
    node.ProcessId = event->Header.ProcessId;
    node.ParentProcessId = event->ParentProcessId;
    node.SessionId = event->SessionId;
    node.ImagePath = event->ImagePath;
    node.ImageName = ExtractFileName(node.ImagePath);
    node.CommandLine = event->CommandLine;
    node.CreateTime = event->Header.Timestamp;
    node.IsAlive = true;
    node.ThreadCount = 1;
    node.SuspicionScore = 0;

    g_ProcessMap[node.ProcessId] = node;

    /* Register as child of parent */
    auto parentIt = g_ProcessMap.find(event->ParentProcessId);
    if (parentIt != g_ProcessMap.end()) {
        parentIt->second.ChildPids.push_back(node.ProcessId);
    }
}


void OnProcessTerminate(const EDR_PROCESS_EVENT* event)
{
    if (!event) return;

    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);

    auto it = g_ProcessMap.find(event->Header.ProcessId);
    if (it != g_ProcessMap.end()) {
        it->second.IsAlive = false;
        it->second.ExitTime = event->Header.Timestamp;
    }
}


void OnImageLoad(const EDR_IMAGE_EVENT* event)
{
    if (!event) return;

    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);

    auto it = g_ProcessMap.find(event->Header.ProcessId);
    if (it != g_ProcessMap.end()) {
        if (it->second.LoadedImages.size() < MAX_LOADED_IMAGES_PER_PROCESS) {
            std::wstring imageName = ExtractFileName(event->ImagePath);
            it->second.LoadedImages.push_back(imageName);
        }
    }
}


void OnThreadEvent(const EDR_THREAD_EVENT* event)
{
    if (!event) return;

    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);

    auto it = g_ProcessMap.find(event->TargetProcessId);
    if (it != g_ProcessMap.end()) {
        if (event->Header.EventType == EdrEventThreadCreate) {
            it->second.ThreadCount++;
        } else if (event->Header.EventType == EdrEventThreadTerminate && it->second.ThreadCount > 0) {
            it->second.ThreadCount--;
        }
    }
}


const ProcessNode* GetProcessNode(ULONG processId)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    auto it = g_ProcessMap.find(processId);
    return (it != g_ProcessMap.end()) ? &it->second : nullptr;
}


std::vector<ULONG> GetProcessChildren(ULONG processId)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    auto it = g_ProcessMap.find(processId);
    if (it != g_ProcessMap.end()) {
        return it->second.ChildPids;
    }
    return {};
}


std::vector<ULONG> GetProcessLineage(ULONG processId)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    std::vector<ULONG> lineage;
    ULONG current = processId;
    int maxDepth = 32; /* Prevent infinite loops */

    while (current != 0 && maxDepth-- > 0) {
        lineage.push_back(current);
        auto it = g_ProcessMap.find(current);
        if (it == g_ProcessMap.end()) break;
        current = it->second.ParentProcessId;
    }

    return lineage;
}


std::wstring GetParentImageName(ULONG processId)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    auto it = g_ProcessMap.find(processId);
    if (it == g_ProcessMap.end()) return L"";

    auto parentIt = g_ProcessMap.find(it->second.ParentProcessId);
    if (parentIt == g_ProcessMap.end()) return L"";

    return parentIt->second.ImageName;
}


std::vector<ProcessNode> GetAllActiveProcesses()
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    std::vector<ProcessNode> result;
    for (const auto& [pid, node] : g_ProcessMap) {
        if (node.IsAlive) {
            result.push_back(node);
        }
    }
    return result;
}


std::vector<ProcessNode> GetAllProcesses()
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    std::vector<ProcessNode> result;
    for (const auto& [pid, node] : g_ProcessMap) {
        result.push_back(node);
    }
    return result;
}


size_t GetActiveProcessCount()
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    size_t count = 0;
    for (const auto& [pid, node] : g_ProcessMap) {
        if (node.IsAlive) count++;
    }
    return count;
}


void AddProcessAlert(ULONG processId, const std::wstring& alert)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    auto it = g_ProcessMap.find(processId);
    if (it != g_ProcessMap.end()) {
        it->second.Alerts.push_back(alert);
    }
}


void IncrementSuspicionScore(ULONG processId, int amount)
{
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    auto it = g_ProcessMap.find(processId);
    if (it != g_ProcessMap.end()) {
        it->second.SuspicionScore += amount;
    }
}
