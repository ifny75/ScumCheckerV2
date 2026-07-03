#pragma once

#include <Windows.h>

extern "C" {

enum NsStatus : int {
    NS_STATUS_OK = 0,
    NS_STATUS_INVALID_ARGUMENT = 1,
    NS_STATUS_INTERNAL_ERROR = 2
};

enum NsSeverity : int {
    NS_SEVERITY_INFO = 0,
    NS_SEVERITY_LOW = 1,
    NS_SEVERITY_MEDIUM = 2,
    NS_SEVERITY_HIGH = 3
};

struct NsFinding {
    wchar_t category[64];
    wchar_t title[128];
    wchar_t reason[256];
    wchar_t details[512];
    wchar_t evidence_path[520];
    int severity;
    int score;
};

struct NsReport {
    int status;
    int findings_returned;
    int files_checked;
    int drivers_checked;
    int services_checked;
    int processes_checked;
    int registry_values_checked;
    int steam_accounts_checked;
    int errors;
    int ran_as_admin;
    int elapsed_ms;
};

__declspec(dllexport) BOOL __stdcall Ns_IsAdministrator();
__declspec(dllexport) void __stdcall Ns_SetRulesPath(const wchar_t* rules_path);
__declspec(dllexport) int __stdcall Ns_RunDriverMemoryScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);
__declspec(dllexport) int __stdcall Ns_RunSteamScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);
__declspec(dllexport) int __stdcall Ns_RunHistoryScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);

// Backs the "DMA & Network" UI tab: lists every PCIe device (severity = DMA
// degree, category "PCIeDevice") and active TCP connections (category
// "NetConn") plus a radar-limit note (category "NetInfo").
__declspec(dllexport) int __stdcall Ns_RunDmaNetworkInspect(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);

// Backs the "Security configuration" UI tab: reports the system protection
// posture (Secure Boot, DSE/test-signing, Defender, VBS/HVCI) under the
// "SecurityConfig" category.
__declspec(dllexport) int __stdcall Ns_RunSecurityConfigScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);

// Extended read-only mode. It attempts to load/connect to KSystemInformer and
// then runs kernel-aware checks such as live external handles to the game.
__declspec(dllexport) int __stdcall Ns_RunKernelSysScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report);

}
