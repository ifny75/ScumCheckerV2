#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "DriverScanner.h"
#include "DriverIndicators.h"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <unordered_set>

#pragma comment(lib, "Psapi.lib")

namespace {

void ScanLoadedDrivers(const ns::RuleSet& rules, ns::ModuleOutput& out) {
    std::array<LPVOID, 4096> drivers{};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed)) {
        out.errors++;
        return;
    }

    const DWORD count = std::min<DWORD>(needed / sizeof(LPVOID), static_cast<DWORD>(drivers.size()));
    out.drivers_checked = static_cast<int>(count);

    for (DWORD i = 0; i < count; ++i) {
        wchar_t baseName[MAX_PATH]{};
        if (GetDeviceDriverBaseNameW(drivers[i], baseName, static_cast<DWORD>(std::size(baseName))) == 0) {
            continue;
        }

        const auto lower = ns::ToLowerCopy(baseName);
        wchar_t rawPath[2048]{};
        GetDeviceDriverFileNameW(drivers[i], rawPath, static_cast<DWORD>(std::size(rawPath)));
        const auto path = ns::NormalizeDriverPath(rawPath);
        const bool fileExists = ns::PathExistsFile(path);
        if (fileExists && ns::ReportVulnerableDriverFile(path, L"Driver", out)) continue;
        if (fileExists && ns::VerifyFileSignature(path)) continue;
        const bool suspicious = ns::ContainsAnyNeedle(lower, rules.strings);
        if (!fileExists && ns::IsKnownVulnerableDriverName(lower)) {
            ns::PushFinding(out.findings, L"Driver", L"Driver family requires version verification",
                L"Name matches a vulnerable driver family; file unavailable, vulnerability is not confirmed",
                baseName, path, NS_SEVERITY_LOW, 35);
        } else if (suspicious) {
            ns::PushFinding(
                out.findings,
                L"Driver",
                L"Suspicious loaded driver name",
                L"Loaded driver name matched suspicious keywords",
                baseName,
                path,
                NS_SEVERITY_MEDIUM,
                72);
        }
    }
}

void ScanKernelDriverServices(const ns::RuleSet& rules, ns::ModuleOutput& out) {
    HKEY servicesKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &servicesKey) != ERROR_SUCCESS) {
        out.errors++;
        return;
    }

    DWORD index = 0;
    wchar_t subkeyName[512]{};
    DWORD subkeyLen = static_cast<DWORD>(std::size(subkeyName));

    while (RegEnumKeyExW(servicesKey, index, subkeyName, &subkeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        ++index;
        ++out.services_checked;

        HKEY oneService = nullptr;
        if (RegOpenKeyExW(servicesKey, subkeyName, 0, KEY_READ, &oneService) != ERROR_SUCCESS) {
            subkeyLen = static_cast<DWORD>(std::size(subkeyName));
            continue;
        }

        DWORD type = 0;
        DWORD typeSize = sizeof(type);
        const bool typeOk = RegQueryValueExW(oneService, L"Type", nullptr, nullptr, reinterpret_cast<LPBYTE>(&type), &typeSize) == ERROR_SUCCESS;
        if (!typeOk || type != SERVICE_KERNEL_DRIVER) {
            RegCloseKey(oneService);
            subkeyLen = static_cast<DWORD>(std::size(subkeyName));
            continue;
        }

        auto imagePathRaw = ns::QueryStringValue(oneService, L"ImagePath");
        std::wstring imagePath;
        if (imagePathRaw.has_value()) {
            imagePath = ns::NormalizeDriverPath(*imagePathRaw);
        }

        auto serviceName = std::wstring(subkeyName);
        auto serviceLower = ns::ToLowerCopy(serviceName);
        const bool suspiciousName = ns::ContainsAnyNeedle(serviceLower, rules.strings);

        bool signatureOk = false;
        if (!imagePath.empty() && ns::PathExistsFile(imagePath)) {
            signatureOk = ns::VerifyFileSignature(imagePath);
        }

        if (!imagePath.empty() && ns::PathExistsFile(imagePath)) {
            ns::ReportVulnerableDriverFile(imagePath, L"DriverService", out);
        }
        if (signatureOk) {
            RegCloseKey(oneService);
            subkeyLen = static_cast<DWORD>(std::size(subkeyName));
            continue;
        }

        if (suspiciousName) {
            ns::PushFinding(
                out.findings,
                L"DriverService",
                L"Suspicious kernel driver service",
                L"Kernel service name matched suspicious keyword",
                serviceName,
                imagePath,
                NS_SEVERITY_HIGH,
                90);
        }

        if (!imagePath.empty()) {
            const auto pathLower = ns::ToLowerCopy(imagePath);
            if (!signatureOk && ns::IsUserSpacePath(pathLower)) {
                ns::PushFinding(
                    out.findings,
                    L"DriverService",
                    L"Unsigned kernel driver from user-space path",
                    L"Kernel driver image is unsigned and launched from appdata/temp path",
                    serviceName,
                    imagePath,
                    NS_SEVERITY_HIGH,
                    94);
            } else if (!signatureOk && suspiciousName) {
                ns::PushFinding(
                    out.findings,
                    L"DriverService",
                    L"Unsigned suspicious kernel driver",
                    L"Kernel driver signature invalid and service is suspicious",
                    serviceName,
                    imagePath,
                    NS_SEVERITY_HIGH,
                    89);
            }
        }

        RegCloseKey(oneService);
        subkeyLen = static_cast<DWORD>(std::size(subkeyName));
    }

    RegCloseKey(servicesKey);
}

} // namespace

namespace ns {

ModuleOutput RunDriverScanner(const RuleSet& rules, bool isAdmin) {
    ModuleOutput out;
    if (!isAdmin) {
        out.status = NS_MODULE_PARTIAL;
        PushFinding(
            out.findings,
            L"Driver",
            L"Driver scanner running without admin rights",
            L"Some kernel driver checks are limited without elevation",
            L"Run scanner as Administrator for full driver visibility",
            L"",
            NS_SEVERITY_LOW,
            25);
    }

    try {
        ScanLoadedDrivers(rules, out);
        ScanKernelDriverServices(rules, out);
    } catch (...) {
        out.errors++;
    }

    return out;
}

} // namespace ns
