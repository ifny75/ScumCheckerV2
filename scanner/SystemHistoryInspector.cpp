#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "SystemHistoryInspector.h"

#include <Windows.h>
#include <winternl.h>

#include <string>
#include <vector>

namespace {

// ---- shared helpers -----------------------------------------------------

std::wstring FormatFiletime(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return L"";
    FILETIME local{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&ft, &local)) return L"";
    if (!FileTimeToSystemTime(&local, &st)) return L"";
    wchar_t buf[32]{};
    swprintf(buf, 32, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

bool IsRecentDays(const FILETIME& ft, int days) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return false;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER a{}, b{};
    a.LowPart = ft.dwLowDateTime; a.HighPart = ft.dwHighDateTime;
    b.LowPart = now.dwLowDateTime; b.HighPart = now.dwHighDateTime;
    if (b.QuadPart <= a.QuadPart) return true;
    const auto diff = b.QuadPart - a.QuadPart;
    const unsigned long long perDay = 10ull * 1000 * 1000 * 60 * 60 * 24;
    return diff <= perDay * static_cast<unsigned long long>(days);
}

std::wstring RegStr(HKEY key, const wchar_t* name) {
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS || size == 0)
        return {};
    std::wstring out(size / sizeof(wchar_t) + 1, L'\0');
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(out.data()), &size) != ERROR_SUCCESS)
        return {};
    out.resize(wcslen(out.c_str()));
    return out;
}

// Read the default (unnamed) REG_BINARY value of subkey <parent>\Properties\{guid}\<prop>
// and interpret the first 8 bytes as a FILETIME (USB connect/disconnect stamps).
std::wstring ReadUsbPropTime(HKEY instanceKey, const wchar_t* prop) {
    std::wstring path = L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\";
    path += prop;
    HKEY k = nullptr;
    if (RegOpenKeyExW(instanceKey, path.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) return {};
    BYTE buf[8]{};
    DWORD size = sizeof(buf), type = 0;
    std::wstring result;
    if (RegQueryValueExW(k, nullptr, nullptr, &type, buf, &size) == ERROR_SUCCESS && size >= 8) {
        FILETIME ft{};
        ft.dwLowDateTime = *reinterpret_cast<DWORD*>(buf);
        ft.dwHighDateTime = *reinterpret_cast<DWORD*>(buf + 4);
        result = FormatFiletime(ft);
    }
    RegCloseKey(k);
    return result;
}

// ---- USB / USBSTOR history ---------------------------------------------

void ScanUsbTree(const wchar_t* enumPath, const wchar_t* label, const ns::RuleSet& rules, ns::ModuleOutput& out, int& count) {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, enumPath, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        out.errors++;
        return;
    }

    wchar_t model[512]{};
    DWORD idx = 0, len = static_cast<DWORD>(std::size(model));
    while (RegEnumKeyExW(root, idx, model, &len, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        ++idx; len = static_cast<DWORD>(std::size(model));
        HKEY modelKey = nullptr;
        if (RegOpenKeyExW(root, model, 0, KEY_READ, &modelKey) != ERROR_SUCCESS) continue;

        wchar_t inst[512]{};
        DWORD j = 0, ilen = static_cast<DWORD>(std::size(inst));
        while (RegEnumKeyExW(modelKey, j, inst, &ilen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            ++j; ilen = static_cast<DWORD>(std::size(inst));
            if (count >= 600) break;

            HKEY instKey = nullptr;
            if (RegOpenKeyExW(modelKey, inst, 0, KEY_READ, &instKey) != ERROR_SUCCESS) continue;

            std::wstring friendly = RegStr(instKey, L"FriendlyName");
            if (friendly.empty()) friendly = RegStr(instKey, L"DeviceDesc");
            if (friendly.empty()) friendly = model;

            const std::wstring first = ReadUsbPropTime(instKey, L"0064"); // install / first seen
            const std::wstring last  = ReadUsbPropTime(instKey, L"0066"); // last arrival
            const std::wstring rem   = ReadUsbPropTime(instKey, L"0067"); // last removal

            std::wstring details = std::wstring(label) + L" | serial=" + std::wstring(inst);
            if (!first.empty()) details += L" | first=" + first;
            if (!last.empty())  details += L" | last=" + last;
            if (!rem.empty())   details += L" | removed=" + rem;

            const bool nameSus = ns::ContainsAnyNeedle(ns::ToLowerCopy(friendly), rules.strings);
            const int degree = nameSus ? NS_SEVERITY_MEDIUM : NS_SEVERITY_INFO;
            const int score = nameSus ? 55 : 3;

            ns::PushFinding(out.findings, L"UsbHistory", friendly,
                nameSus ? L"USB device name matched a keyword" : L"USB device seen on this machine",
                details, std::wstring(enumPath) + L"\\" + model + L"\\" + inst, degree, score);
            ++count;
            RegCloseKey(instKey);
        }
        RegCloseKey(modelKey);
        if (count >= 600) break;
    }
    RegCloseKey(root);
}

// ---- BAM / DAM execution history ---------------------------------------

void ScanBamHistory(const ns::RuleSet& rules, ns::ModuleOutput& out) {
    const wchar_t* candidates[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
    };

    int total = 0;
    for (const wchar_t* base : candidates) {
        HKEY baseKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_READ, &baseKey) != ERROR_SUCCESS) continue;

        wchar_t sid[256]{};
        DWORD si = 0, slen = static_cast<DWORD>(std::size(sid));
        while (RegEnumKeyExW(baseKey, si, sid, &slen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            ++si; slen = static_cast<DWORD>(std::size(sid));
            HKEY sidKey = nullptr;
            if (RegOpenKeyExW(baseKey, sid, 0, KEY_READ, &sidKey) != ERROR_SUCCESS) continue;

            DWORD vi = 0;
            wchar_t valName[1024];
            BYTE data[64];
            for (;; ++vi) {
                DWORD nameLen = static_cast<DWORD>(std::size(valName));
                DWORD dataLen = sizeof(data);
                DWORD type = 0;
                LONG r = RegEnumValueW(sidKey, vi, valName, &nameLen, nullptr, &type,
                                       data, &dataLen);
                if (r != ERROR_SUCCESS) break;
                if (type != REG_BINARY || dataLen < 8) continue;
                if (total >= 800) break;

                FILETIME ft{};
                ft.dwLowDateTime = *reinterpret_cast<DWORD*>(data);
                ft.dwHighDateTime = *reinterpret_cast<DWORD*>(data + 4);
                const std::wstring when = FormatFiletime(ft);
                if (when.empty()) continue;

                std::wstring path(valName);
                const std::wstring lower = ns::ToLowerCopy(path);
                const bool keyword = ns::ContainsAnyNeedle(lower, rules.strings);
                const bool userspace = ns::IsUserSpacePath(lower);
                const bool recent = IsRecentDays(ft, 7);

                int degree = NS_SEVERITY_INFO; int score = 5;
                std::wstring reason = L"Program execution recorded by BAM";
                if (keyword) { degree = NS_SEVERITY_HIGH; score = 88; reason = L"Executed binary name matched a cheat keyword"; }
                else if (userspace && recent) { degree = NS_SEVERITY_MEDIUM; score = 60; reason = L"Recently executed binary from appdata/temp"; }
                else if (userspace) { degree = NS_SEVERITY_LOW; score = 30; reason = L"Executed binary from appdata/temp"; }

                ns::PushFinding(out.findings, L"ExecHistory", path, reason,
                    L"lastRun=" + when + (recent ? L" | recent(7d)" : L""),
                    path, degree, score);
                ++total;
            }
            RegCloseKey(sidKey);
            if (total >= 800) break;
        }
        RegCloseKey(baseKey);
    }

    if (total == 0) {
        ns::PushFinding(out.findings, L"ExecHistory",
            L"BAM execution history unavailable",
            L"Could not read BAM/DAM keys (run as Administrator for execution history)",
            L"", L"", NS_SEVERITY_LOW, 20);
    }
}

// ---- PnP device inventory by class -------------------------------------

void ScanDeviceClasses(ns::ModuleOutput& out) {
    HKEY enumRoot = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum", 0, KEY_READ, &enumRoot) != ERROR_SUCCESS)
        return;

    wchar_t bus[128]{};
    DWORD bi = 0, blen = static_cast<DWORD>(std::size(bus));
    while (RegEnumKeyExW(enumRoot, bi, bus, &blen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        ++bi; blen = static_cast<DWORD>(std::size(bus));
        // Count instances under each bus (PCI, USB, USBSTOR, HID, SCSI, ...)
        HKEY busKey = nullptr;
        if (RegOpenKeyExW(enumRoot, bus, 0, KEY_READ, &busKey) != ERROR_SUCCESS) continue;
        DWORD models = 0;
        RegQueryInfoKeyW(busKey, nullptr, nullptr, nullptr, &models, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, nullptr);
        ns::PushFinding(out.findings, L"DeviceHistory",
            std::wstring(L"Bus ") + bus,
            L"Enumerated device bus (current + historical entries)",
            L"models=" + std::to_wstring(models),
            L"", NS_SEVERITY_INFO, 1);
        RegCloseKey(busKey);
    }
    RegCloseKey(enumRoot);
}

} // namespace

namespace ns {

ModuleOutput RunSystemHistoryInspector(const RuleSet& rules) {
    ModuleOutput out;
    int usbCount = 0;
    try {
        ScanUsbTree(L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", L"USB storage", rules, out, usbCount);
        ScanUsbTree(L"SYSTEM\\CurrentControlSet\\Enum\\USB", L"USB device", rules, out, usbCount);
        ScanBamHistory(rules, out);
        ScanDeviceClasses(out);
    } catch (...) {
        out.errors++;
    }
    return out;
}

} // namespace ns
