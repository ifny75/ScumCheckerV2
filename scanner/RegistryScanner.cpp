#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "RegistryScanner.h"

#include <Windows.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::wstring ReadSmallTextFile(const std::filesystem::path& path, size_t maxBytes = 512 * 1024) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return L"";
    std::string bytes;
    bytes.resize(maxBytes);
    in.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<size_t>(in.gcount()));
    if (bytes.empty()) return L"";
    const int needed = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (needed <= 0) return L"";
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), out.data(), needed);
    return out;
}

std::wstring ExtractXmlTag(const std::wstring& text, const std::wstring& tag) {
    const auto open = L"<" + tag + L">";
    const auto close = L"</" + tag + L">";
    const auto start = text.find(open);
    if (start == std::wstring::npos) return L"";
    const auto valueStart = start + open.size();
    const auto end = text.find(close, valueStart);
    if (end == std::wstring::npos) return L"";
    std::wstring value = text.substr(valueStart, end - valueStart);
    const std::pair<const wchar_t*, const wchar_t*> entities[] = {
        {L"&quot;", L"\""}, {L"&amp;", L"&"}, {L"&lt;", L"<"}, {L"&gt;", L">"}
    };
    for (const auto& e : entities) {
        size_t pos = 0;
        while ((pos = value.find(e.first, pos)) != std::wstring::npos) {
            value.replace(pos, wcslen(e.first), e.second);
            pos += wcslen(e.second);
        }
    }
    return value;
}

bool LooksSuspiciousCommand(const std::wstring& lower, const ns::RuleSet& rules) {
    static const std::vector<std::wstring> hot = {
        L"powershell", L"cmd.exe", L"wscript", L"cscript", L"rundll32",
        L"regsvr32", L"mshta", L"bitsadmin", L"certutil", L"curl ",
        L"invoke-webrequest", L"downloadstring", L"frombase64string",
        L"encodedcommand", L"-enc ", L"\\temp\\", L"\\appdata\\"
    };
    return ns::ContainsAnyNeedle(lower, hot) ||
           ns::ContainsAnyNeedle(lower, rules.strings) ||
           ns::ContainsAnyNeedle(lower, rules.paths);
}

void AnalyzeAutorunCommand(const std::wstring& source, const std::wstring& valueName,
                           const std::wstring& command, const ns::RuleSet& rules,
                           ns::ModuleOutput& out) {
    if (command.empty()) return;
    ++out.registry_values_checked;

    auto expanded = ns::ExpandEnvironment(command);
    auto trimmed = ns::TrimQuotesAndArgs(expanded);
    auto lowerFull = ns::ToLowerCopy(expanded);
    auto lowerPath = ns::ToLowerCopy(trimmed);

    const bool userSpace = ns::IsUserSpacePath(lowerPath) || ns::IsUserSpacePath(lowerFull);
    const bool temp = ns::IsTempPath(lowerPath) || ns::IsTempPath(lowerFull);
    const bool suspicious = LooksSuspiciousCommand(lowerFull, rules);

    if (ns::VerifyFileSignature(trimmed)) return;
    if (userSpace || suspicious) {
        int severity = (temp || lowerFull.find(L"encodedcommand") != std::wstring::npos ||
                        lowerFull.find(L"frombase64string") != std::wstring::npos)
            ? NS_SEVERITY_HIGH
            : NS_SEVERITY_MEDIUM;
        int score = severity == NS_SEVERITY_HIGH ? 86 : 72;

        ns::PushFinding(
            out.findings,
            L"Registry",
            userSpace ? L"Autorun entry from user-space" : L"Suspicious autorun command",
            source,
            L"Name=" + valueName + L" | Command=" + expanded,
            trimmed,
            severity,
            score);
    }
}

void ScanRunKey(HKEY root, const wchar_t* subKey, REGSAM sam, const ns::RuleSet& rules, ns::ModuleOutput& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ | sam, &key) != ERROR_SUCCESS) {
        return;
    }

    DWORD idx = 0;
    wchar_t valueName[512]{};
    BYTE valueData[4096]{};

    while (true) {
        DWORD valueNameLen = static_cast<DWORD>(std::size(valueName));
        DWORD valueDataSize = static_cast<DWORD>(std::size(valueData));
        DWORD type = 0;

        const LONG rc = RegEnumValueW(
            key,
            idx++,
            valueName,
            &valueNameLen,
            nullptr,
            &type,
            valueData,
            &valueDataSize);

        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            out.errors++;
            break;
        }

        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        std::wstring cmd(reinterpret_cast<wchar_t*>(valueData), valueDataSize / sizeof(wchar_t));
        if (!cmd.empty() && cmd.back() == L'\0') cmd.pop_back();

        AnalyzeAutorunCommand(std::wstring(L"Startup registry key: ") + subKey,
                              std::wstring(valueName), cmd, rules, out);
    }

    RegCloseKey(key);
}

void ScanServices(HKEY root, REGSAM sam, const ns::RuleSet& rules, ns::ModuleOutput& out) {
    HKEY services = nullptr;
    if (RegOpenKeyExW(root, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ | sam, &services) != ERROR_SUCCESS) {
        return;
    }

    DWORD idx = 0;
    wchar_t name[512]{};
    while (true) {
        DWORD nameLen = static_cast<DWORD>(std::size(name));
        LONG rc = RegEnumKeyExW(services, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            out.errors++;
            break;
        }

        HKEY svc = nullptr;
        if (RegOpenKeyExW(services, name, 0, KEY_READ | sam, &svc) != ERROR_SUCCESS) continue;
        auto image = ns::QueryStringValue(svc, L"ImagePath");
        RegCloseKey(svc);
        if (!image.has_value()) continue;

        AnalyzeAutorunCommand(L"Windows service ImagePath", std::wstring(name), *image, rules, out);
    }

    RegCloseKey(services);
}

void ScanIfeo(HKEY root, REGSAM sam, const ns::RuleSet& rules, ns::ModuleOutput& out) {
    HKEY ifeo = nullptr;
    if (RegOpenKeyExW(root,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_READ | sam, &ifeo) != ERROR_SUCCESS) {
        return;
    }

    DWORD idx = 0;
    wchar_t name[512]{};
    while (true) {
        DWORD nameLen = static_cast<DWORD>(std::size(name));
        LONG rc = RegEnumKeyExW(ifeo, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            out.errors++;
            break;
        }

        HKEY app = nullptr;
        if (RegOpenKeyExW(ifeo, name, 0, KEY_READ | sam, &app) != ERROR_SUCCESS) continue;
        auto debugger = ns::QueryStringValue(app, L"Debugger");
        RegCloseKey(app);
        if (!debugger.has_value()) continue;

        ns::PushFinding(
            out.findings,
            L"Registry",
            L"Image File Execution Options debugger",
            L"IFEO Debugger can hijack or monitor process launch",
            L"Target=" + std::wstring(name) + L" | Debugger=" + *debugger,
            ns::TrimQuotesAndArgs(ns::ExpandEnvironment(*debugger)),
            NS_SEVERITY_MEDIUM,
            78);
        ++out.registry_values_checked;
    }

    RegCloseKey(ifeo);
}

void ScanScheduledTasks(const ns::RuleSet& rules, ns::ModuleOutput& out) {
    wchar_t win[MAX_PATH]{};
    if (GetWindowsDirectoryW(win, static_cast<UINT>(std::size(win))) == 0) return;

    std::filesystem::path root = std::filesystem::path(win) / L"System32" / L"Tasks";
    std::error_code ec;
    if (!std::filesystem::exists(root, ec) || ec) return;

    int visited = 0;
    for (std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            out.errors++;
            ec.clear();
            continue;
        }
        if (++visited > 7000) break;
        if (!it->is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        auto xml = ReadSmallTextFile(it->path());
        if (xml.empty()) continue;
        auto command = ExtractXmlTag(xml, L"Command");
        auto args = ExtractXmlTag(xml, L"Arguments");
        if (command.empty() && args.empty()) continue;

        AnalyzeAutorunCommand(
            L"Scheduled task action",
            it->path().filename().wstring(),
            command + L" " + args,
            rules,
            out);
    }
}

} // namespace

namespace ns {

ModuleOutput RunRegistryScanner(const RuleSet& rules) {
    ModuleOutput out;

    try {
        ScanRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, rules, out);
        ScanRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, rules, out);

        ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY, rules, out);
        ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY, rules, out);
        ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_32KEY, rules, out);
        ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_32KEY, rules, out);

        ScanServices(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, rules, out);
        ScanServices(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, rules, out);
        ScanIfeo(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, rules, out);
        ScanIfeo(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, rules, out);
        ScanScheduledTasks(rules, out);
    } catch (...) {
        out.errors++;
    }

    return out;
}

} // namespace ns
