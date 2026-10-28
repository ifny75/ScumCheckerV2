#include "FileScanner.h"
#include "RiskAnalyzer.h"
#include "ProcessModuleEnumerator.h"
#include "ScanReporting.h"
#include "ScanRunner.h"
#include "DriverIndicators.h"
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

void TestFullFileHashes() {
    Fixture fixture;
    const auto file = fixture.root / L"hash-fixture.json";
    std::ofstream(file, std::ios::binary) << "abc";
    Require(ns::ComputeSha256Hex(file.wstring()) ==
        L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 known vector mismatch");
    std::ofstream(file, std::ios::binary | std::ios::trunc).close();
    Require(ns::ComputeSha256Hex(file.wstring()) ==
        L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Empty file SHA-256 mismatch");
    {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out << std::string(2 * 1024 * 1024, 'a') << "tail";
    }
    const std::wstring expected = L"e04a36603efd1d3d31610f6f8328106c07e817025de43a8d99ecffc98a040eb5";
    Require(ns::ComputeSha256Hex(file.wstring()) == expected, "Hash omitted bytes after 2 MiB");
    ns::RuleSet rules;
    rules.hashes = {expected};
    const auto result = ns::RunFileScanner(rules, {fixture.root.wstring()});
    Require(result.errors == 0 && result.findings.size() == 1 && result.findings[0].score == 98,
        "File scanner failed to match a full hash above 2 MiB");
    Require(ns::ComputeSha256Hex((fixture.root / L"missing").wstring()).empty(),
        "Missing file returned a hash");
    HANDLE locked = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    Require(locked != INVALID_HANDLE_VALUE, "Could not lock hash fixture");
    const auto hash = ns::ComputeSha256Hex(file.wstring());
    CloseHandle(locked);
    Require(hash.empty(), "Unreadable file returned a hash");
}

void TestModuleReporting() {
    NsReport report{};
    std::vector<NsFinding> findings;
    ns::ModuleOutput output;
    ns::MergeModuleOutput(L"Completed", output, report, findings);
    Require(report.status == NS_STATUS_OK && report.modules_returned == 1,
        "Successful module marked incomplete");
    output.errors = 2;
    ns::MergeModuleOutput(L"Partial", output, report, findings);
    Require(report.status == NS_STATUS_PARTIAL && report.modules[1].status == NS_MODULE_PARTIAL,
        "Module errors did not mark scan incomplete");
    ns::MergeModuleOutput(L"Failed", ns::FailedModule(), report, findings);
    Require(report.modules[2].status == NS_MODULE_FAILED && report.errors == 3,
        "Failed module was not reported");
    output = {};
    output.status = NS_MODULE_ACCESS_DENIED;
    ns::MergeModuleOutput(L"Denied", output, report, findings);
    Require(report.modules[3].status == NS_MODULE_ACCESS_DENIED,
        "Access denied status lost");
    ns::MergeModuleOutput(L"Completed later", ns::ModuleOutput{}, report, findings);
    Require(report.status == NS_STATUS_PARTIAL, "Later success hid an earlier failure");
    report.status = NS_STATUS_INTERNAL_ERROR;
    ns::MergeModuleOutput(L"After fatal error", output, report, findings);
    Require(report.status == NS_STATUS_INTERNAL_ERROR, "Fatal error was overwritten");
}

void TestExplicitFileScanLimits() {
    Fixture fixture;
    std::ofstream(fixture.root / L"first.json") << "{}";
    std::ofstream(fixture.root / L"second.json") << "{}";
    std::ofstream(fixture.root / L"nested" / L"third.json") << "{}";
    const std::vector<std::wstring> roots = {fixture.root.wstring()};
    const auto entries = ns::RunFileScanner({}, roots, {5, 1});
    Require(entries.roots_limited == 1 && entries.status == NS_MODULE_PARTIAL,
        "Entry limit silently reported a complete scan");
    const auto depth = ns::RunFileScanner({}, roots, {0, 35000});
    Require(depth.depth_limited_directories == 1 && depth.status == NS_MODULE_PARTIAL,
        "Depth limit silently reported a complete scan");
    std::filesystem::create_directory(fixture.root / L"cache");
    const auto excluded = ns::RunFileScanner({}, roots);
    Require(excluded.excluded_directories == 1 && excluded.status == NS_MODULE_PARTIAL,
        "Excluded directory was not reported");
    const auto missing = ns::RunFileScanner({}, {(fixture.root / L"missing").wstring()});
    Require(missing.errors > 0 && missing.status == NS_MODULE_PARTIAL,
        "Unavailable root silently reported a complete scan");
    NsReport report{};
    std::vector<NsFinding> findings;
    ns::MergeModuleOutput(L"Files", excluded, report, findings);
    Require(report.modules[0].excluded_directories == 1 && report.status == NS_STATUS_PARTIAL,
        "Coverage limits were lost from the scan report");
}

void TestResultBufferTruncation() {
    std::vector<NsFinding> findings(5001);
    for (size_t i = 0; i < findings.size(); ++i) findings[i].score = static_cast<int>(i);
    std::vector<NsFinding> buffer(4096);
    NsReport report{};
    Require(ns::CopyScanFindings(findings, buffer.data(), 4096, report) == NS_STATUS_PARTIAL,
        "Truncated result silently reported success");
    Require(report.findings_total == 5001 && report.findings_returned == 4096 && report.findings_truncated == 905,
        "Incorrect truncation counts");
    Require(buffer.back().score == 4095, "Result buffer was copied incorrectly");
    buffer.resize(findings.size());
    report = {};
    Require(ns::CopyScanFindings(findings, buffer.data(), 5001, report) == NS_STATUS_OK &&
        report.findings_returned == 5001 && report.findings_truncated == 0 && buffer.back().score == 5000,
        "Results above 4096 could not be retained");
    report = {};
    Require(ns::CopyScanFindings(findings, nullptr, 0, report) == NS_STATUS_PARTIAL && report.findings_truncated == 5001,
        "Zero capacity did not report omitted findings");
    Require(Ns_RunSteamScan(nullptr, 1, &report) == NS_STATUS_INVALID_ARGUMENT,
        "Null result buffer was accepted");
    Require(Ns_RunSteamScan(nullptr, 0, nullptr) == NS_STATUS_INVALID_ARGUMENT,
        "Null report was accepted");
}

void TestSignatureExemptionsAndDriverIndicators() {
    Fixture fixture;
    wchar_t system[MAX_PATH]{};
    GetSystemDirectoryW(system, MAX_PATH);
    const auto source = std::filesystem::path(system) / L"kernel32.dll";
    Require(ns::VerifyFileSignature(source.wstring()), "Windows DLL signature was not trusted");
    const auto copied = fixture.root / L"bypass-mapper-loader.dll";
    std::filesystem::copy_file(source, copied);
    Require(ns::VerifyFileSignature(copied.wstring()), "Copied signed DLL lost signature trust");
    ns::RuleSet rules;
    rules.strings = {L"bypass", L"mapper", L"loader"};
    Require(ns::RunFileScanner(rules, {fixture.root.wstring()}).findings.empty(),
        "Signed DLL was detected by filename keywords");
    std::filesystem::copy_file(source, fixture.root / L"iqvw64e.sys");
    Require(ns::RunFileScanner(rules, {fixture.root.wstring()}).findings.empty(),
        "Signed file with a driver-family name was treated as a confirmed vulnerable version");
    {
        std::fstream corrupt(copied, std::ios::in | std::ios::out | std::ios::binary);
        corrupt.put('Z');
    }
    Require(!ns::VerifyFileSignature(copied.wstring()), "Modified binary retained signature exemption");
    Require(!ns::RunFileScanner(rules, {fixture.root.wstring()}).findings.empty(),
        "Unsigned keyword sample was incorrectly exempted");
    Require(!ns::MatchVulnerableDriverHash(
        L"4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b").empty(),
        "Known vulnerable Intel sample was absent from driver database");
    Require(ns::MatchVulnerableDriverHash(std::wstring(64, L'0')).empty(), "Unknown hash matched driver database");
    Require(ns::IsKnownVulnerableDriverName(L"C:\\drivers\\IQVW64E.SYS"), "Driver family lookup failed");
    Require(!ns::IsKnownVulnerableDriverName(L"normal.sys"), "Unknown driver name matched database");
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
        TestFullFileHashes();
        TestModuleReporting();
        TestExplicitFileScanLimits();
        TestResultBufferTruncation();
        TestSignatureExemptionsAndDriverIndicators();
        std::cout << "Scanner regressions passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
