#include "YaraScanner.h"
#include "Support.h"
#include "Utils.h"

static YR_RULES* YARA_RULES = nullptr;

int YaraScanCallback(
    YR_SCAN_CONTEXT* context, 
    int message, 
    void* message_data, 
    void* user_data
) {
	
    if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* rule = reinterpret_cast<YR_RULE*>(message_data);
		YaraScanResult* result = reinterpret_cast<YaraScanResult*>(user_data);
		result->matched = true;

		std::wstring ruleName;
		if (rule->identifier) {
			std::string ruleNameStr(rule->identifier);
			ruleName.assign(ruleNameStr.begin(), ruleNameStr.end());
		}

		std::wstring fileName = PathFindFileNameW(result->filePath.c_str());
		result->reason = L"Detected in " + fileName + L"\nRule: " + ruleName ;
	}

	return CALLBACK_CONTINUE;

}

bool InitializeYara() {
    if (yr_initialize() != ERROR_SUCCESS) {
        LogMessage(L"[-] Failed to initialize YARA");
        return false;
    }

    std::wstring compiledRulesPath = GetAssetPath(YARA_RULES_PATH);
    std::string narrowPath(compiledRulesPath.begin(), compiledRulesPath.end());
    LogMessage(L"[+] Attempting to load YARA rules from: " + compiledRulesPath);

    int result = yr_rules_load(narrowPath.c_str(), &YARA_RULES);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        LogMessage(L"[-] yr_rules_load failed with error code: " + std::to_wstring(result));
        return false;
    }

    return true;
}

void FinalizeYara() {
    if (YARA_RULES) {
        LogMessage(L"[+] YARA rules destroyed!");
        yr_rules_destroy(YARA_RULES);
        YARA_RULES = nullptr;
    }

    LogMessage(L"[+] yr_finalize completed");
    yr_finalize();
}

YaraScanResult ScanFileWithYara(const std::wstring& filePath) {
    YaraScanResult result{ false, L"" };
    result.filePath = filePath;

    if (!YARA_RULES) return result;

    std::string narrowFile(filePath.begin(), filePath.end());
    LogMessage(L"Scan started for !" + filePath);
    yr_rules_scan_file(YARA_RULES, narrowFile.c_str(), 0, YaraScanCallback, &result, 0);
    LogMessage(L"Scan finished for !" + filePath);

    return result;
}
