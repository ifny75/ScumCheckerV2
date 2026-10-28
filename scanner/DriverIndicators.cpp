#include "DriverIndicators.h"
#include "VulnerableDriverData.h"
#include <unordered_map>
#include <unordered_set>

namespace ns {
std::wstring MatchVulnerableDriverHash(const std::wstring& sha256) {
    static const auto samples = [] {
        std::unordered_map<std::wstring, std::wstring> result;
        for (const auto& sample : driver_data::samples) result.emplace(sample.sha256, sample.name);
        return result;
    }();
    const auto found = samples.find(ToLowerCopy(sha256));
    return found == samples.end() ? L"" : found->second;
}

bool IsKnownVulnerableDriverName(const std::wstring& name) {
    static const std::unordered_set<std::wstring> names(std::begin(driver_data::names), std::end(driver_data::names));
    return names.contains(ToLowerCopy(Basename(name)));
}

std::wstring NormalizeDriverPath(std::wstring path) {
    path = ExpandEnvironment(TrimQuotesAndArgs(path));
    if (path.rfind(L"\\??\\", 0) == 0) path.erase(0, 4);
    wchar_t windows[MAX_PATH]{};
    GetWindowsDirectoryW(windows, MAX_PATH);
    auto lower = ToLowerCopy(path);
    if (lower.rfind(L"\\systemroot\\", 0) == 0) return std::wstring(windows) + path.substr(11);
    if (lower.rfind(L"system32\\", 0) == 0) return std::wstring(windows) + L"\\" + path;
    if (lower.rfind(L"\\device\\", 0) == 0) {
        wchar_t drives[512]{};
        GetLogicalDriveStringsW(512, drives);
        for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
            std::wstring letter(drive, 2);
            wchar_t device[1024]{};
            if (!QueryDosDeviceW(letter.c_str(), device, 1024)) continue;
            const auto prefix = ToLowerCopy(device);
            if (lower.rfind(prefix + L"\\", 0) == 0) return letter + path.substr(prefix.size());
        }
    }
    return path;
}

bool ReportVulnerableDriverFile(const std::wstring& path, const wchar_t* category, ModuleOutput& output) {
    const auto hash = ComputeSha256Hex(path);
    if (hash.empty()) { ++output.errors; return false; }
    const auto family = MatchVulnerableDriverHash(hash);
    if (family.empty()) return false;
    PushFinding(output.findings, category, L"Known vulnerable driver (SHA-256 confirmed)",
        L"Full file hash matches a verified vulnerable sample in LOLDrivers; signature does not exempt this version",
        L"Family=" + family + L" | SHA256=" + hash, path, NS_SEVERITY_HIGH, 95);
    return true;
}
}
