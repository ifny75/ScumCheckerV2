#include "FileScanner.h"
#include "RiskAnalyzer.h"
#include "ProcessModuleEnumerator.h"
#include <Psapi.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Fixture {
    std::filesystem::path root = std::filesystem::temp_directory_path() /
        (L"ScumCheckerRegression-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    Fixture() { std::filesystem::create_directories(root / L"nested"); }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(root, ec); }
};

void TestRepeatedFileScans() {
    Fixture fixture;
    const auto file = fixture.root / L"nested" / L"regression-marker.json";
    std::ofstream(file) << "{}";
    ns::RuleSet rules;
    rules.strings = {L"regression-marker"};
    const std::vector<std::wstring> roots = {fixture.root.wstring(), file.parent_path().wstring()};
    for (int i = 0; i < 2; ++i) {
        const auto result = ns::RunFileScanner(rules, roots);
        Require(result.errors == 0, "File scan failed");
        Require(result.files_checked == 1, "Overlapping roots counted a file twice");
        Require(result.findings.size() == 1, "Repeated scan lost or duplicated an unchanged finding");
    }
    rules.strings.clear();
    Require(ns::RunFileScanner(rules, roots).findings.empty(), "Old rule finding survived rule change");
    rules.strings = {L"regression-marker"};
    Require(ns::RunFileScanner(rules, roots).findings.size() == 1, "Changed rules did not re-evaluate unchanged file");
}

void TestRiskDoesNotDependOnDisplayText() {
    const wchar_t* titles[] = {
        L"File hash matched rule",
        L"Injected thread(s) from non-module memory",
        L"Executable pagefile-backed section (manual-mapped code)",
        L"Known vulnerable kernel driver",
        L"Совпадение индикатора"
    };
    for (const auto* title : titles) {
        std::vector<NsFinding> findings;
        ns::PushFinding(findings, L"Process", title, L"unsigned mapper dse", L"",
            L"C:\\Temp\\sample.exe", NS_SEVERITY_HIGH, 95);
        ns::ApplyRiskAnalysis(findings);
        Require(findings[0].severity == NS_SEVERITY_HIGH, "Strong detection was downgraded");
        Require(findings[0].score == 95, "Display text changed detection score");
    }
    std::vector<NsFinding> context;
    ns::PushFinding(context, L"Info", L"unsigned kernel driver mapper", L"unsigned", L"",
        L"C:\\Temp\\context.sys", NS_SEVERITY_INFO, 30);
    ns::ApplyRiskAnalysis(context);
    Require(context[0].severity == NS_SEVERITY_INFO && context[0].score == 30,
        "Kernel-related display text elevated an informational finding");
}

void TestRiskCorrelationAndDeduplication() {
    std::vector<NsFinding> findings;
    for (const auto* title : {L"Signal A", L"Signal B", L"Signal C"}) {
        ns::PushFinding(findings, L"File", title, L"", L"", L"C:\\sample.exe", NS_SEVERITY_LOW, 40);
    }
    findings.push_back(findings.front());
    ns::ApplyRiskAnalysis(findings);
    Require(findings.size() == 3, "Duplicate finding was retained");
    for (const auto& finding : findings) {
        Require(finding.severity == NS_SEVERITY_MEDIUM && finding.score == 48,
            "Independent findings no longer correlate");
    }
}

void TestGrowingModuleSnapshot() {
    int calls = 0;
    const auto modules = ns::ReadProcessModuleSnapshot([&](HMODULE* buffer, DWORD bytes, DWORD* needed) {
        ++calls;
        // Grow again after the first size query, exceeding both old arrays.
        const size_t count = calls == 1 ? 2048 : 4096;
        *needed = static_cast<DWORD>(count * sizeof(HMODULE));
        const size_t written = (std::min)(count, bytes / sizeof(HMODULE));
        for (size_t i = 0; i < written; ++i) buffer[i] = reinterpret_cast<HMODULE>(i + 1);
        return TRUE;
    });
    Require(calls == 3, "Module enumeration did not retry after growth");
    Require(modules && modules->size() == 4096, "Module snapshot was truncated");
    for (size_t i = 0; i < modules->size(); ++i) {
        Require((*modules)[i] == reinterpret_cast<HMODULE>(i + 1), "Invalid module in snapshot");
    }
}

void TestIncompleteModuleSnapshots() {
    int calls = 0;
    const auto failed = ns::ReadProcessModuleSnapshot([&](HMODULE*, DWORD bytes, DWORD* needed) {
        *needed = bytes + static_cast<DWORD>(sizeof(HMODULE));
        return ++calls == 1 ? TRUE : FALSE;
    });
    Require(!failed && calls == 2, "Enumeration failure exposed an incomplete snapshot");
    calls = 0;
    const auto unstable = ns::ReadProcessModuleSnapshot([&](HMODULE*, DWORD bytes, DWORD* needed) {
        ++calls;
        *needed = bytes + static_cast<DWORD>(sizeof(HMODULE));
        return TRUE;
    });
    Require(!unstable && calls == 8, "Unstable enumeration was not bounded");
    const auto empty = ns::ReadProcessModuleSnapshot([](HMODULE*, DWORD, DWORD* needed) {
        *needed = 0;
        return TRUE;
    });
    Require(empty && empty->empty(), "Empty snapshot was treated as an error");
}

void TestLiveModuleSnapshot() {
    const auto modules = ns::ReadProcessModuleSnapshot([](HMODULE* buffer, DWORD bytes, DWORD* needed) {
        return EnumProcessModulesEx(GetCurrentProcess(), buffer, bytes, needed, LIST_MODULES_ALL);
    });
    Require(modules && !modules->empty(), "Could not enumerate test process modules");
    Require(std::find(modules->begin(), modules->end(), GetModuleHandleW(nullptr)) != modules->end(),
        "Live module snapshot omitted the executable");
}
}

int main() {
    try {
        TestRepeatedFileScans();
        TestRiskDoesNotDependOnDisplayText();
        TestRiskCorrelationAndDeduplication();
        TestGrowingModuleSnapshot();
        TestIncompleteModuleSnapshots();
        TestLiveModuleSnapshot();
        std::cout << "Scanner regressions passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
