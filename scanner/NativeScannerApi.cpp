#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "NativeScannerApi.h"

#include "DmaNetworkInspector.h"
#include "SystemHistoryInspector.h"
#include "DriverScanner.h"
#include "FileScanner.h"
#include "HypervisorScanner.h"
#include "KernelSysScanner.h"
#include "PcieScanner.h"
#include "ProcessScanner.h"
#include "RegistryScanner.h"
#include "RiskAnalyzer.h"
#include "ScanReporting.h"
#include "ScannerShared.h"
#include "SecurityConfigScanner.h"
#include "SteamScanner.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <mutex>
#include <vector>

namespace {

std::mutex g_rulesPathMutex;
std::wstring g_rulesPath;

bool IsAdmin() {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (!AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        return false;
    }

    BOOL isMember = FALSE;
    CheckTokenMembership(nullptr, adminGroup, &isMember);
    FreeSid(adminGroup);
    return isMember == TRUE;
}

void MergeOutput(const wchar_t* name, const ns::ModuleOutput& mo, NsReport* report, std::vector<NsFinding>* findings) {
    ns::MergeModuleOutput(name, mo, *report, *findings);
}

std::wstring ResolveRulesPath() {
    std::lock_guard<std::mutex> lock(g_rulesPathMutex);
    if (!g_rulesPath.empty()) {
        return g_rulesPath;
    }
    return (std::filesystem::path(ns::GetModuleDirectory()) / L"profiles" / L"scum.json").wstring();
}

int FinishScanResult(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report,
    const std::chrono::steady_clock::time_point& started,
    std::vector<NsFinding>& findings) {
    ns::ApplyRiskAnalysis(findings);
    std::stable_sort(findings.begin(), findings.end(),
        [](const NsFinding& a, const NsFinding& b) {
            if (a.severity != b.severity) return a.severity > b.severity;
            return a.score > b.score;
        });

    if (findings_buffer && findings_capacity > 0 && !findings.empty()) {
        const int copyCount = std::min<int>(findings_capacity, static_cast<int>(findings.size()));
        for (int i = 0; i < copyCount; ++i) {
            findings_buffer[i] = findings[static_cast<size_t>(i)];
        }
        out_report->findings_returned = copyCount;
    } else {
        out_report->findings_returned = 0;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    out_report->elapsed_ms = static_cast<int>(elapsed.count());
    return out_report->status;
}

template <typename Fn>
int RunSingleModuleScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report,
    const wchar_t* moduleName,
    Fn&& module) {
    if (!out_report || findings_capacity < 0) {
        return NS_STATUS_INVALID_ARGUMENT;
    }

    *out_report = {};
    out_report->status = NS_STATUS_OK;
    out_report->ran_as_admin = IsAdmin() ? 1 : 0;

    const auto started = std::chrono::steady_clock::now();
    std::vector<NsFinding> findings;

    try {
        const auto rulesPath = ResolveRulesPath();
        const auto rules = ns::LoadRulesFromJson(rulesPath);
        auto mo = module(rules);
        MergeOutput(moduleName, mo, out_report, &findings);
    } catch (...) {
        MergeOutput(moduleName, ns::FailedModule(), out_report, &findings);
        out_report->status = NS_STATUS_INTERNAL_ERROR;
    }

    return FinishScanResult(findings_buffer, findings_capacity, out_report, started, findings);
}

} // namespace

extern "C" __declspec(dllexport) BOOL __stdcall Ns_IsAdministrator() {
    return IsAdmin() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) void __stdcall Ns_SetRulesPath(const wchar_t* rules_path) {
    std::lock_guard<std::mutex> lock(g_rulesPathMutex);
    g_rulesPath = rules_path ? rules_path : L"";
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunDriverMemoryScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    if (!out_report || findings_capacity < 0) {
        return NS_STATUS_INVALID_ARGUMENT;
    }

    *out_report = {};
    out_report->status = NS_STATUS_OK;
    out_report->ran_as_admin = IsAdmin() ? 1 : 0;

    const auto started = std::chrono::steady_clock::now();
    std::vector<NsFinding> findings;
    findings.reserve(static_cast<size_t>(findings_capacity > 0 ? findings_capacity : 512));

    try {
        const auto rulesPath = ResolveRulesPath();
        const auto rules = ns::LoadRulesFromJson(rulesPath);

        std::vector<std::future<ns::ModuleOutput>> jobs;
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunFileScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunProcessScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules, out_report]() { return ns::RunDriverScanner(rules, out_report->ran_as_admin == 1); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunRegistryScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunSteamScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunPcieScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunHypervisorScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunSystemHistoryInspector(rules); }));

        const wchar_t* names[] = {L"Files", L"Processes", L"Drivers", L"Registry", L"Steam", L"PCIe", L"Hypervisor", L"History"};
        size_t index = 0;
        for (auto& job : jobs) {
            const auto name = names[index++];
            try {
                auto mo = job.get();
                MergeOutput(name, mo, out_report, &findings);
            } catch (...) {
                MergeOutput(name, ns::FailedModule(), out_report, &findings);
            }
        }

    } catch (...) {
        out_report->errors++;
        out_report->status = NS_STATUS_INTERNAL_ERROR;
    }

    return FinishScanResult(findings_buffer, findings_capacity, out_report, started, findings);
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunSteamScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    return RunSingleModuleScan(findings_buffer, findings_capacity, out_report, L"Steam",
        [](const ns::RuleSet& rules) { return ns::RunSteamScanner(rules); });
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunHistoryScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    return RunSingleModuleScan(findings_buffer, findings_capacity, out_report, L"History",
        [](const ns::RuleSet& rules) { return ns::RunSystemHistoryInspector(rules); });
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunSecurityConfigScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    const bool isAdmin = IsAdmin();
    return RunSingleModuleScan(findings_buffer, findings_capacity, out_report, L"Security configuration",
        [isAdmin](const ns::RuleSet& rules) { return ns::RunSecurityConfigScanner(rules, isAdmin); });
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunDmaNetworkInspect(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    if (!out_report || findings_capacity < 0) {
        return NS_STATUS_INVALID_ARGUMENT;
    }

    *out_report = {};
    out_report->status = NS_STATUS_OK;
    out_report->ran_as_admin = IsAdmin() ? 1 : 0;

    const auto started = std::chrono::steady_clock::now();
    std::vector<NsFinding> findings;

    try {
        const auto rulesPath = ResolveRulesPath();
        const auto rules = ns::LoadRulesFromJson(rulesPath);

        auto mo = ns::RunDmaNetworkInspector(rules);
        MergeOutput(L"DMA / Network", mo, out_report, &findings);

        auto hist = ns::RunSystemHistoryInspector(rules);
        MergeOutput(L"History", hist, out_report, &findings);

    } catch (...) {
        out_report->errors++;
        out_report->status = NS_STATUS_INTERNAL_ERROR;
    }

    return FinishScanResult(findings_buffer, findings_capacity, out_report, started, findings);
}

extern "C" __declspec(dllexport) int __stdcall Ns_RunKernelSysScan(
    NsFinding* findings_buffer,
    int findings_capacity,
    NsReport* out_report) {
    if (!out_report || findings_capacity < 0) {
        return NS_STATUS_INVALID_ARGUMENT;
    }

    *out_report = {};
    out_report->status = NS_STATUS_OK;
    out_report->ran_as_admin = IsAdmin() ? 1 : 0;

    const auto started = std::chrono::steady_clock::now();
    std::vector<NsFinding> findings;
    findings.reserve(static_cast<size_t>(findings_capacity > 0 ? findings_capacity : 512));

    try {
        const auto rulesPath = ResolveRulesPath();
        const auto rules = ns::LoadRulesFromJson(rulesPath);

        const bool isAdmin = out_report->ran_as_admin == 1;
        auto kernel = ns::RunKernelSysScanner(rules, isAdmin);
        MergeOutput(L"Kernel provider", kernel, out_report, &findings);

        std::vector<std::future<ns::ModuleOutput>> jobs;
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunProcessScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules, isAdmin]() { return ns::RunDriverScanner(rules, isAdmin); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunPcieScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules]() { return ns::RunHypervisorScanner(rules); }));
        jobs.emplace_back(std::async(std::launch::async, [&rules, isAdmin]() { return ns::RunSecurityConfigScanner(rules, isAdmin); }));

        const wchar_t* names[] = {L"Processes", L"Drivers", L"PCIe", L"Hypervisor", L"Security configuration"};
        size_t index = 0;
        for (auto& job : jobs) {
            const auto name = names[index++];
            try {
                auto mo = job.get();
                MergeOutput(name, mo, out_report, &findings);
            } catch (...) {
                MergeOutput(name, ns::FailedModule(), out_report, &findings);
            }
        }
    } catch (...) {
        out_report->errors++;
        out_report->status = NS_STATUS_INTERNAL_ERROR;
    }

    return FinishScanResult(findings_buffer, findings_capacity, out_report, started, findings);
}
