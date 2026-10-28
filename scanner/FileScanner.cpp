#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "FileScanner.h"

#include <Windows.h>

#include <array>
#include <chrono>
#include <future>
#include <filesystem>
#include <mutex>
#include <algorithm>
#include <unordered_set>

namespace {

struct ScanState {
    std::mutex mutex;
    std::unordered_set<std::wstring> visitedFiles;
};

struct RootSpec {
    std::wstring path;
    int maxDepth = 5;
};

int DaysSinceCreation(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        return 9999;
    }

    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);

    ULARGE_INTEGER created{};
    created.HighPart = fad.ftCreationTime.dwHighDateTime;
    created.LowPart = fad.ftCreationTime.dwLowDateTime;

    ULARGE_INTEGER now{};
    now.HighPart = nowFt.dwHighDateTime;
    now.LowPart = nowFt.dwLowDateTime;

    if (now.QuadPart <= created.QuadPart) return 0;
    const auto diff100ns = now.QuadPart - created.QuadPart;
    const auto days = static_cast<int>(diff100ns / (10ull * 1000ull * 1000ull * 60ull * 60ull * 24ull));
    return days;
}

bool IsInterestingExtension(const std::wstring& extLower) {
    return extLower == L".exe" || extLower == L".dll" || extLower == L".sys" ||
           extLower == L".bat" || extLower == L".cmd" || extLower == L".ps1" ||
           extLower == L".vbs" || extLower == L".js" || extLower == L".lnk" ||
           extLower == L".cfg" || extLower == L".ini" || extLower == L".json";
}

bool IsMasqueradingSystemName(const std::wstring& exeLower) {
    static const std::unordered_set<std::wstring> names = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"winlogon.exe", L"services.exe", L"smss.exe"
    };
    return names.find(exeLower) != names.end();
}

bool ContainsCriticalToken(const std::wstring& value) {
    static const std::vector<std::wstring> critical = {
        L"kdmapper", L"iqvw64e", L"manualmap", L"manual map", L"driver mapper",
        L"ring0", L"kernelmode", L"bypass", L"spoofer", L"hwid",
        L"melonity", L"ambrela", L"ambrella", L"scumhack"
    };
    return ns::ContainsAnyNeedle(value, critical);
}

bool ContainsDevToolToken(const std::wstring& value) {
    static const std::vector<std::wstring> devTools = {
        L"dnspy", L"ilspy", L"x64dbg", L"x32dbg", L"ollydbg", L"ghidra",
        L"ida64", L"ida pro", L"cheat engine", L"cheatengine", L"process hacker",
        L"procexp", L"debugger", L"decompiler", L"api monitor", L"wireshark"
    };
    return ns::ContainsAnyNeedle(value, devTools);
}

bool ContainsConfigHint(const std::wstring& value, const std::wstring& extLower) {
    return extLower == L".cfg" || extLower == L".ini" || extLower == L".json" ||
           value.find(L"config") != std::wstring::npos ||
           value.find(L"settings") != std::wstring::npos;
}

bool IsScriptExtension(const std::wstring& extLower) {
    return extLower == L".bat" || extLower == L".cmd" || extLower == L".ps1" ||
           extLower == L".vbs" || extLower == L".js";
}

bool ContainsSpecificPathNeedle(const std::wstring& value, const std::vector<std::wstring>& needles) {
    static const std::unordered_set<std::wstring> generic = {
        L"\\temp\\", L"\\appdata\\", L"\\local\\temp\\", L"\\programdata\\"
    };
    for (const auto& needle : needles) {
        if (needle.empty() || generic.find(needle) != generic.end()) continue;
        if (value.find(needle) != std::wstring::npos) return true;
    }
    return false;
}

bool ShouldSkipDirectory(const std::filesystem::path& path) {
    const auto name = ns::ToLowerCopy(path.filename().wstring());
    static const std::unordered_set<std::wstring> skipNames = {
        L".git", L".vs", L"node_modules", L"packages", L"cache", L"caches",
        L"code cache", L"gpu cache", L"shadercache", L"logs", L"temp",
        L"temporary internet files", L"windowsapps", L"steamapps"
    };
    if (skipNames.find(name) != skipNames.end()) return true;

    const auto lower = ns::ToLowerCopy(path.wstring());
    return lower.find(L"\\google\\chrome\\user data\\") != std::wstring::npos ||
           lower.find(L"\\microsoft\\edge\\user data\\") != std::wstring::npos ||
           lower.find(L"\\discord\\cache\\") != std::wstring::npos;
}

void AddRoot(std::vector<RootSpec>& roots, const std::wstring& path, int maxDepth) {
    if (path.empty()) return;
    roots.push_back({path, maxDepth});
}

std::vector<RootSpec> BuildRoots() {
    std::vector<RootSpec> roots;
    std::array<wchar_t, 4096> buf{};

    if (GetEnvironmentVariableW(L"APPDATA", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 5);
    }
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 5);
        AddRoot(roots, std::wstring(buf.data()) + L"\\Programs", 3);
        AddRoot(roots, std::wstring(buf.data()) + L"\\Temp", 2);
    }
    if (GetEnvironmentVariableW(L"TEMP", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 2);
    }
    if (GetEnvironmentVariableW(L"USERPROFILE", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        const std::wstring profile = buf.data();
        AddRoot(roots, profile + L"\\Desktop", 5);
        AddRoot(roots, profile + L"\\Downloads", 5);
        AddRoot(roots, profile + L"\\Documents", 5);
        AddRoot(roots, profile + L"\\Saved Games", 5);
        AddRoot(roots, profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", 5);
        AddRoot(roots, profile, 2);
    }
    if (GetEnvironmentVariableW(L"ProgramData", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 2);
        AddRoot(roots, std::wstring(buf.data()) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", 5);
    }
    if (GetEnvironmentVariableW(L"ProgramFiles", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 2);
    }
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", buf.data(), static_cast<DWORD>(buf.size())) > 0) {
        AddRoot(roots, buf.data(), 2);
    }

    std::vector<RootSpec> unique;
    std::unordered_set<std::wstring> seen;
    for (auto& r : roots) {
        if (r.path.empty()) continue;
        auto low = ns::ToLowerCopy(r.path);
        if (seen.insert(low).second && std::filesystem::exists(std::filesystem::path(r.path))) {
            unique.push_back(r);
        }
    }

    return unique;
}

void ScanRoot(const RootSpec& root, const ns::RuleSet& rules, ns::ModuleOutput& out, ScanState& state) {
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(
        std::filesystem::path(root.path),
        std::filesystem::directory_options::skip_permission_denied,
        ec);
    std::filesystem::recursive_directory_iterator end;

    int visited = 0;
    constexpr int kMaxVisitedPerRoot = 35000;

    for (; it != end; it.increment(ec)) {
        if (ec) {
            out.errors++;
            ec.clear();
            continue;
        }

        if (++visited > kMaxVisitedPerRoot) {
            break;
        }

        if (it->is_directory(ec)) {
            if (!ec && ShouldSkipDirectory(it->path())) {
                it.disable_recursion_pending();
                ec.clear();
                continue;
            }
            if (!ec && it.depth() >= root.maxDepth) {
                it.disable_recursion_pending();
            }

            const auto dirLower = ns::ToLowerCopy(it->path().wstring());
            const auto dirName = ns::ToLowerCopy(it->path().filename().wstring());
            if (ContainsCriticalToken(dirLower) ||
                ns::ContainsAnyNeedle(dirLower, rules.strings) ||
                ns::ContainsAnyNeedle(dirLower, rules.paths)) {
                const bool criticalDir = ContainsCriticalToken(dirName);
                ns::PushFinding(out.findings, L"File",
                    criticalDir ? L"High-risk suspicious folder" : L"Suspicious folder",
                    L"Directory name/path matched checker indicators",
                    it->path().filename().wstring(),
                    it->path().wstring(),
                    criticalDir ? NS_SEVERITY_MEDIUM : NS_SEVERITY_LOW,
                    criticalDir ? 66 : 34);
            } else if (ContainsDevToolToken(dirName)) {
                ns::PushFinding(out.findings, L"File",
                    L"Dev / reverse tool folder",
                    L"Reverse engineering/debug tooling folder detected (context only)",
                    it->path().filename().wstring(),
                    it->path().wstring(),
                    NS_SEVERITY_LOW,
                    34);
            }
            ec.clear();
            continue;
        }

        if (!it->is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        const auto path = it->path().wstring();
        const auto pathLower = ns::ToLowerCopy(path);
        const auto extLower = ns::ToLowerCopy(it->path().extension().wstring());

        if (!IsInterestingExtension(extLower)) continue;

        // Only deduplicate overlapping roots within this scan. Every new scan
        // must evaluate unchanged files again, including against changed rules.
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (!state.visitedFiles.insert(pathLower).second) continue;
        }
        out.files_checked++;

        // ---------------------------------------------------------------
        // Combination model. The scanner only walks APPDATA/LOCALAPPDATA/TEMP,
        // so "lives in a user-space path" is true for EVERYTHING here and means
        // nothing on its own (it used to flag ~94% of files). A file becomes a
        // finding only when signals *combine* into something actually suspicious.
        // ---------------------------------------------------------------
        const auto baseName = ns::Basename(path);
        const auto baseLower = ns::ToLowerCopy(baseName);
        const int daysOld = DaysSinceCreation(path);
        const bool recentlyCreated = daysOld <= 3;
        const bool isSys = extLower == L".sys";
        const bool isExeDll = extLower == L".exe" || extLower == L".dll";
        const bool isSignable = isSys || isExeDll;
        const bool signedOk = isSignable ? ns::VerifyFileSignature(path) : false;

        // Keyword match is taken on the FILE NAME only (not the full path), so
        // the appdata/temp roots themselves can no longer trigger it.
        const bool nameKeywordHit = ns::ContainsAnyNeedle(baseLower, rules.strings);
        const bool pathKeywordHit = ContainsSpecificPathNeedle(pathLower, rules.paths);
        const bool criticalHit = ContainsCriticalToken(baseLower);
        const bool devToolHit = ContainsDevToolToken(baseLower);
        const bool configHint = ContainsConfigHint(pathLower, extLower);
        const bool script = IsScriptExtension(extLower);
        const bool masquerading = IsMasqueradingSystemName(baseLower) &&
            pathLower.find(L"\\windows\\system32\\") == std::wstring::npos;

        // 1) Known-bad hash — strongest, always wins.
        bool hashMatched = false;
        if (!rules.hashes.empty()) {
            auto hash = ns::ComputeSha256Hex(path, 2 * 1024 * 1024);
            if (!hash.empty()) {
                auto hashLower = ns::ToLowerCopy(hash);
                if (std::find(rules.hashes.begin(), rules.hashes.end(), hashLower) != rules.hashes.end()) {
                    hashMatched = true;
                    ns::PushFinding(out.findings, L"File",
                        L"File hash matched rule",
                        L"SHA256 hash is present in rules.json",
                        hashLower, path, NS_SEVERITY_HIGH, 98);
                }
            }
        }
        if (hashMatched) continue;

        // 2) System-process name outside System32 — masquerading binary.
        if (masquerading) {
            ns::PushFinding(out.findings, L"File",
                L"System-process name outside trusted directory",
                L"Masquerading executable name not located in System32",
                baseName, path, NS_SEVERITY_HIGH, 92);
            continue;
        }

        // 3) Unsigned kernel driver staged in a user dir — classic mapper/BYOVD.
        if (isSys && !signedOk) {
            const bool userStaged = ns::IsUserSpacePath(pathLower);
            ns::PushFinding(out.findings, L"File",
                userStaged ? L"Unsigned kernel driver staged in user path"
                           : L"Unsigned kernel driver image",
                L"Unsigned .sys is a common cheat-mapper / BYOVD artifact",
                L"Name=" + baseName + L" | Signature=Invalid",
                path,
                NS_SEVERITY_HIGH, userStaged ? 94 : 88);
            continue;
        }

        // 3.5) Signed .sys with a known leaked / abused signer. These are common
        // BYOVD loader materials because Windows accepts the signature.
        if (isSys && signedOk) {
            const auto signer = ns::GetFileSignerInfo(path);
            const auto leaked = ns::MatchKnownLeakedSigner(signer);
            if (!leaked.empty()) {
                ns::PushFinding(out.findings, L"File",
                    L"Kernel driver signed with known leaked certificate",
                    L"Signed .sys uses a leaked/abused code-signing certificate",
                    L"Name=" + baseName + L" | Signature=Valid | Signer=" + signer.subject +
                        L" | Serial=" + signer.serial + L" | Match=" + leaked,
                    path,
                    NS_SEVERITY_HIGH,
                    97);
                continue;
            }
        }

        // 4) Cheat-keyword in the file name.
        if (criticalHit || nameKeywordHit || pathKeywordHit) {
            const bool strong = criticalHit && (isSys || !signedOk || script);
            const int sev = strong ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM;
            const int score = strong ? 88 : ((!signedOk || script) ? 66 : 52);
            ns::PushFinding(out.findings, L"File",
                criticalHit ? L"File matched high-risk checker indicator" :
                (!signedOk ? L"Unsigned file with cheat-related indicator"
                           : L"File path/name matched checker indicator"),
                criticalHit ? L"Critical keyword/brand detected in file path"
                            : L"File path/name matched rules.json indicators",
                L"Name=" + baseName + L" | Signature=" + (signedOk ? L"Valid" : L"Invalid") +
                    L" | ConfigHint=" + (configHint ? L"1" : L"0"),
                path, sev, score);
            continue;
        }

        if (devToolHit) {
            ns::PushFinding(out.findings, L"File",
                L"Dev / reverse tool file",
                L"Reverse engineering/debug tooling detected (context only)",
                baseName, path, NS_SEVERITY_LOW, 35);
            continue;
        }

        // 4.5) Unsigned exe/dll sitting in a download landing zone (Desktop /
        // Downloads). These folders hold few binaries, so flagging unsigned ones
        // regardless of age does not flood — and this is exactly where injected
        // cheats / loaders (e.g. melonity's kernel.dll) live.
        const bool downloadZone =
            pathLower.find(L"\\desktop\\") != std::wstring::npos ||
            pathLower.find(L"\\downloads\\") != std::wstring::npos;
        const bool startupZone = pathLower.find(L"\\start menu\\programs\\startup\\") != std::wstring::npos;
        if ((isExeDll || script || extLower == L".lnk") && (!signedOk || script || startupZone) && (downloadZone || startupZone)) {
            ns::PushFinding(out.findings, L"File",
                startupZone ? L"Startup folder executable/script" : L"Unsigned binary in Desktop/Downloads",
                startupZone ? L"User/common Startup folder contains an executable/script shortcut"
                            : L"Unsigned executable/DLL in a download landing zone — common loader location",
                L"DaysOld=" + std::to_wstring(daysOld) + L" | Signature=" + (signedOk ? L"Valid" : L"Invalid") +
                    L" | Startup=" + (startupZone ? L"1" : L"0"),
                path, startupZone ? NS_SEVERITY_MEDIUM : NS_SEVERITY_MEDIUM,
                startupZone ? 78 : 66);
            continue;
        }

        // 5) Fresh + unsigned exe/dll in a user dir. NOT every unsigned appdata
        // binary (that floods); only ones created in the last 3 days — i.e.
        // something that arrived right before/around the check.
        if (isExeDll && !signedOk && recentlyCreated && ns::IsUserSpacePath(pathLower)) {
            ns::PushFinding(out.findings, L"File",
                L"Recently created unsigned binary in user path",
                L"Unsigned executable created in the last 3 days inside appdata/temp",
                L"DaysOld=" + std::to_wstring(daysOld) + L" | Signature=Invalid",
                path, ns::IsTempPath(pathLower) ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM,
                ns::IsTempPath(pathLower) ? 76 : 60);
            continue;
        }

        // Everything else (signed apps, old unsigned apps) -> no finding.
    }
}

} // namespace

namespace ns {

ModuleOutput RunFileScanner(const RuleSet& rules) {
    return RunFileScanner(rules, {});
}

ModuleOutput RunFileScanner(const RuleSet& rules, const std::vector<std::wstring>& selectedRoots) {
    ModuleOutput merged;
    auto roots = selectedRoots.empty() ? BuildRoots() : std::vector<RootSpec>{};
    for (const auto& path : selectedRoots) AddRoot(roots, path, 5);
    ScanState state;
    if (roots.empty()) {
        return merged;
    }

    std::vector<std::future<ModuleOutput>> tasks;
    tasks.reserve(roots.size());

    for (const auto& r : roots) {
        tasks.push_back(std::async(std::launch::async, [r, &rules, &state]() {
            ModuleOutput mo;
            try {
                ScanRoot(r, rules, mo, state);
            } catch (...) {
                mo.errors++;
            }
            return mo;
        }));
    }

    for (auto& t : tasks) {
        auto mo = t.get();
        merged.files_checked += mo.files_checked;
        merged.errors += mo.errors;
        merged.findings.insert(merged.findings.end(), mo.findings.begin(), mo.findings.end());
    }

    return merged;
}

} // namespace ns
