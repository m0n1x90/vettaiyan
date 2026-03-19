/*
 * BehaviorEngine.h - Behavioral detection engine
 *
 * Implements MITRE ATT&CK-aligned behavioral detection rules:
 * - Suspicious parent-child process relationships
 * - LOLBAS (Living Off the Land Binaries and Scripts) abuse
 * - Remote thread injection detection
 * - Credential access patterns
 * - Persistence mechanism monitoring
 * - Defense evasion techniques
 */

#ifndef BEHAVIOR_ENGINE_H
#define BEHAVIOR_ENGINE_H

#include <string>
#include <vector>
#include <functional>
#include "../EdrCommon/EdrEvents.h"

/* Detection severity levels */
enum class DetectionSeverity {
    Info        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4,
};

/* A behavioral detection result */
struct BehaviorDetection {
    std::wstring        RuleName;
    std::wstring        Description;
    std::wstring        MitreTactic;
    std::wstring        MitreTechnique;
    DetectionSeverity   Severity;
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    std::wstring        ProcessImage;
    std::wstring        ParentImage;
    LARGE_INTEGER       Timestamp;
};

/* Callback for detections */
typedef std::function<void(const BehaviorDetection& detection)> DetectionCallback;

/* Initialize the behavioral detection engine */
void InitializeBehaviorEngine();

/* Shutdown */
void ShutdownBehaviorEngine();

/* Register detection callback */
void RegisterDetectionCallback(DetectionCallback callback);

/* Process a kernel event through behavioral rules */
void AnalyzeProcessEvent(const EDR_PROCESS_EVENT* event);
void AnalyzeImageEvent(const EDR_IMAGE_EVENT* event);
void AnalyzeThreadEvent(const EDR_THREAD_EVENT* event);
void AnalyzeRegistryEvent(const EDR_REGISTRY_EVENT* event);
void AnalyzeFileEvent(const EDR_FILE_EVENT* event);
void AnalyzeHandleEvent(const EDR_HANDLE_EVENT* event);

/* Get all detections */
std::vector<BehaviorDetection> GetRecentDetections(int limit = 50);

/* Get detection count */
size_t GetDetectionCount();

#endif /* BEHAVIOR_ENGINE_H */
