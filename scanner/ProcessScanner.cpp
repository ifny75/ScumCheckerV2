#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ProcessScanner.h"
#include "ProcessModuleEnumerator.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace {

struct OverlayWindowCollector {
    std::unordered_set<DWORD> pids;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    const LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    const bool topMost = (exStyle & WS_EX_TOPMOST) != 0;
    const bool layered = (exStyle & WS_EX_LAYERED) != 0;
    const bool transparent = (exStyle & WS_EX_TRANSPARENT) != 0;

    if (!(topMost && (layered || transparent))) {
        return TRUE;
    }

    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) return TRUE;
    if ((rc.right - rc.left) < 250 || (rc.bottom - rc.top) < 150) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return TRUE;

    auto* collector = reinterpret_cast<OverlayWindowCollector*>(lParam);
    collector->pids.insert(pid);
    return TRUE;
}

std::unordered_set<DWORD> CollectOverlayProcessIds() {
    OverlayWindowCollector collector;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&collector));
    return collector.pids;
}

bool IsTrustedProcessName(const std::wstring& exeLower) {
    static const std::unordered_set<std::wstring> trusted = {
        L"system", L"csrss.exe", L"wininit.exe", L"winlogon.exe", L"services.exe", L"svchost.exe",
        L"lsass.exe", L"explorer.exe", L"dwm.exe", L"taskmgr.exe", L"steam.exe", L"discord.exe"
    };
    return trusted.find(exeLower) != trusted.end();
}

bool IsMasqueradingName(const std::wstring& exeLower) {
    static const std::unordered_set<std::wstring> names = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"winlogon.exe", L"services.exe", L"smss.exe"
    };
    return names.find(exeLower) != names.end();
}

bool IsGameProcessName(const std::wstring& exeLower) {
    return exeLower == L"scum.exe" || exeLower == L"dota2.exe";
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

bool ContainsDangerousCommandToken(const std::wstring& value) {
    static const std::vector<std::wstring> tokens = {
        L"encodedcommand", L"-enc ", L"frombase64string", L"downloadstring",
        L"invoke-webrequest", L"regsvr32", L"rundll32", L"mshta",
        L"wscript", L"cscript", L"bitsadmin", L"certutil"
    };
    return ns::ContainsAnyNeedle(value, tokens);
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

int DaysSinceFileCreation(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 9999;
    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER created{}, now{};
    created.HighPart = fad.ftCreationTime.dwHighDateTime;
    created.LowPart = fad.ftCreationTime.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    now.LowPart = nowFt.dwLowDateTime;
    if (now.QuadPart <= created.QuadPart) return 0;
    return static_cast<int>((now.QuadPart - created.QuadPart) / (10ull * 1000ull * 1000ull * 60ull * 60ull * 24ull));
}

std::wstring ReadRemoteCommandLine(HANDLE hProc) {
    using PFN_NtQIP = LONG(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<PFN_NtQIP>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return L"";

    struct Pbi {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } pbi{};
    if (NtQIP(hProc, 0, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress) return L"";

#ifdef _WIN64
    constexpr SIZE_T kProcessParametersOffset = 0x20;
    constexpr SIZE_T kCommandLineOffset = 0x70;
#else
    constexpr SIZE_T kProcessParametersOffset = 0x10;
    constexpr SIZE_T kCommandLineOffset = 0x40;
#endif

    PVOID params = nullptr;
    SIZE_T read = 0;
    auto* peb = static_cast<const BYTE*>(pbi.PebBaseAddress);
    if (!ReadProcessMemory(hProc, peb + kProcessParametersOffset, &params, sizeof(params), &read) ||
        read != sizeof(params) || !params) {
        return L"";
    }

    struct RemoteUnicodeString {
        USHORT Length;
        USHORT MaximumLength;
        PVOID Buffer;
    } cmd{};
    auto* pp = static_cast<const BYTE*>(params);
    if (!ReadProcessMemory(hProc, pp + kCommandLineOffset, &cmd, sizeof(cmd), &read) ||
        read != sizeof(cmd) || !cmd.Buffer || cmd.Length == 0 || cmd.Length > 32766) {
        return L"";
    }

    std::wstring out;
    out.resize(cmd.Length / sizeof(wchar_t));
    if (!ReadProcessMemory(hProc, cmd.Buffer, out.data(), cmd.Length, &read) || read != cmd.Length) {
        return L"";
    }
    return out;
}

bool ProcessHasGraphicsModules(HANDLE hProc, const std::vector<HMODULE>& modules) {
    for (const auto module : modules) {
        wchar_t modName[MAX_PATH]{};
        if (!GetModuleBaseNameW(hProc, module, modName, static_cast<DWORD>(std::size(modName)))) {
            continue;
        }

        auto lower = ns::ToLowerCopy(modName);
        if (lower == L"d3d9.dll" || lower == L"d3d11.dll" || lower == L"dxgi.dll" || lower == L"opengl32.dll") {
            return true;
        }
    }

    return false;
}

std::wstring DirOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

// Flag DLLs loaded into a process from outside its own install directory and
// outside Windows — i.e. a foreign module injected via LoadLibrary. Skips the
// host's own modules and system DLLs to stay quiet; flags foreign modules that
// are unsigned or keyword-matched (legit signed overlays like Steam/Discord are
// left alone). Does NOT catch manual-mapped code — see DetectManualMappedRegions.
void DetectSuspiciousModules(HANDLE hProc, DWORD pid, const std::wstring& hostDirLower,
                             const ns::RuleSet& rules, std::vector<NsFinding>& findings,
                             const std::vector<HMODULE>& modules) {
    for (const auto module : modules) {
        wchar_t modPath[2048]{};
        if (!GetModuleFileNameExW(hProc, module, modPath, static_cast<DWORD>(std::size(modPath)))) {
            continue;
        }

        std::wstring path = modPath;
        auto lower = ns::ToLowerCopy(path);

        // System DLLs — ignore.
        if (lower.find(L"\\windows\\") != std::wstring::npos) continue;
        // The process's own modules (its install dir) — ignore.
        const std::wstring modDir = ns::ToLowerCopy(DirOf(path));
        if (!hostDirLower.empty() && !modDir.empty() && modDir.rfind(hostDirLower, 0) == 0) continue;

        const bool keyword = ns::ContainsAnyNeedle(lower, rules.strings) || ns::ContainsAnyNeedle(lower, rules.paths);
        const bool signedOk = ns::VerifyFileSignature(path);

        // Foreign module: flag unsigned modules, but keep generic unsigned
        // third-party modules below High. Many legit apps ship unsigned native
        // addons outside the host dir (Discord/ASUS/Node/Electron stacks).
        if (!signedOk || keyword) {
            ns::PushFinding(
                findings,
                L"Process",
                L"Foreign module injected into process",
                signedOk ? L"Process loaded a foreign module matching cheat keywords"
                         : L"Process loaded an UNSIGNED module from outside its install directory",
                L"PID " + std::to_wstring(pid) + L" | " + ns::Basename(path) + L" <- " + path,
                path,
                keyword ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM,
                keyword ? 84 : 58);
        }
    }
}

struct ModRange { uintptr_t lo; uintptr_t hi; };

std::vector<ModRange> BuildModuleRanges(HANDLE hProc, const std::vector<HMODULE>& modules) {
    std::vector<ModRange> ranges;
    ranges.reserve(modules.size());
    for (const auto module : modules) {
        MODULEINFO mi{};
        if (GetModuleInformation(hProc, module, &mi, sizeof(mi))) {
            const auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            ranges.push_back({base, base + mi.SizeOfImage});
        }
    }
    return ranges;
}

bool InAnyModule(const std::vector<ModRange>& ranges, uintptr_t a) {
    for (const auto& r : ranges) if (a >= r.lo && a < r.hi) return true;
    return false;
}

bool IsExecProtect(DWORD protect) {
    const DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

// PRIMARY manual-map / injection signal (validated live against melonity in
// dota2): a thread whose Win32 start address lies in committed executable memory
// that is NOT backed by any loaded module. Legit code starts threads inside
// images; manual-mapped / shellcode threads start in mapped/private memory.
void DetectInjectedThreads(HANDLE hProc, DWORD pid, const std::vector<ModRange>& mods,
                           std::vector<NsFinding>& findings) {
    using PFN_NtQIT = LONG(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
    static auto NtQIT = reinterpret_cast<PFN_NtQIT>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (!NtQIT) return;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    int injected = 0;
    uintptr_t firstAddr = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hT = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!hT) continue;

            PVOID start = nullptr;
            // 9 == ThreadQuerySetWin32StartAddress
            if (NtQIT(hT, 9, &start, sizeof(start), nullptr) == 0 && start) {
                const auto a = reinterpret_cast<uintptr_t>(start);
                if (!InAnyModule(mods, a)) {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQueryEx(hProc, start, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                        mbi.State == MEM_COMMIT && IsExecProtect(mbi.Protect)) {
                        if (injected == 0) firstAddr = a;
                        ++injected;
                    }
                }
            }
            CloseHandle(hT);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (injected > 0) {
        wchar_t info[160]{};
        swprintf(info, 160, L"threads=%d firstStart=0x%llx",
                 injected, static_cast<unsigned long long>(firstAddr));
        ns::PushFinding(findings, L"Process",
            L"Injected thread(s) from non-module memory",
            L"Thread(s) start in executable memory not backed by any loaded module (manual-mapped / injected code)",
            L"PID " + std::to_wstring(pid) + L" | " + info,
            L"", NS_SEVERITY_HIGH, 95);
    }
}

// CORROBORATING signal: a large executable region with NO file backing and not
// inside any module. melonity maps its DLL as an executable pagefile-backed
// SECTION (MEM_MAPPED, RWX, ~10MB) — invisible to module enumeration and to
// private-memory scans. An executable MEM_MAPPED region with no mapped file
// name is the section-mapping signature.
void DetectUnbackedExecRegions(HANDLE hProc, DWORD pid, const std::vector<ModRange>& mods,
                               std::vector<NsFinding>& findings) {
    auto* addr = reinterpret_cast<const BYTE*>(0);
    const auto* maxAddr = reinterpret_cast<const BYTE*>(0x7FFFFFFEFFFFull);
    MEMORY_BASIC_INFORMATION mbi{};

    SIZE_T bestSize = 0;
    const void* bestBase = nullptr;
    bool bestMapped = false;

    while (addr < maxAddr && VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && IsExecProtect(mbi.Protect) &&
            (mbi.Type == MEM_MAPPED || mbi.Type == MEM_PRIVATE) &&
            !InAnyModule(mods, reinterpret_cast<uintptr_t>(mbi.BaseAddress))) {

            wchar_t fileName[MAX_PATH]{};
            const DWORD got = GetMappedFileNameW(hProc, mbi.BaseAddress, fileName, MAX_PATH);
            const bool fileBacked = got > 0; // real on-disk file backing

            // Pagefile-backed executable section (no file name) is the strong tell.
            if (!fileBacked && mbi.RegionSize > bestSize) {
                bestSize = mbi.RegionSize;
                bestBase = mbi.BaseAddress;
                bestMapped = (mbi.Type == MEM_MAPPED);
            }
        }
        auto* next = reinterpret_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    // MEM_MAPPED executable with no backing is rare in legit apps -> flag from
    // 64KB. Private (JIT-like) needs a much larger size to avoid JIT false hits.
    const SIZE_T threshold = bestMapped ? (64u * 1024u) : (4u * 1024u * 1024u);
    if (bestSize >= threshold) {
        wchar_t info[160]{};
        swprintf(info, 160, L"base=0x%llx size=%lluKB type=%s prot=exec",
                 reinterpret_cast<unsigned long long>(bestBase),
                 static_cast<unsigned long long>(bestSize / 1024),
                 bestMapped ? L"MAPPED(section)" : L"PRIVATE");
        ns::PushFinding(findings, L"Process",
            bestMapped ? L"Executable pagefile-backed section (manual-mapped code)"
                       : L"Large unbacked private executable region",
            L"Executable memory not backed by a module or file — manual-map / section-mapping signature",
            L"PID " + std::to_wstring(pid) + L" | " + info,
            L"", bestMapped ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM,
            bestMapped ? 92 : 74);
    }
}

} // namespace

namespace ns {

ModuleOutput RunProcessScanner(const RuleSet& rules) {
    ModuleOutput out;

    std::array<DWORD, 8192> pids{};
    DWORD needed = 0;
    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &needed)) {
        out.errors++;
        return out;
    }

    auto overlayPids = CollectOverlayProcessIds();

    const DWORD count = std::min<DWORD>(needed / sizeof(DWORD), static_cast<DWORD>(pids.size()));
    out.processes_checked = static_cast<int>(count);

    bool gameRunning = false;

    for (DWORD i = 0; i < count; ++i) {
        const DWORD pid = pids[i];
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;

        HANDLE qh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!qh) continue;

        wchar_t pathBuf[2048]{};
        DWORD pathLen = static_cast<DWORD>(std::size(pathBuf));
        const bool gotPath = QueryFullProcessImageNameW(qh, 0, pathBuf, &pathLen) == TRUE;
        CloseHandle(qh);
        if (!gotPath || pathLen == 0) continue;

        std::wstring fullPath(pathBuf, pathLen);
        auto fullLower = ToLowerCopy(fullPath);
        auto exeLower = ToLowerCopy(Basename(fullPath));

        if (IsGameProcessName(exeLower)) {
            gameRunning = true;
        }

        const bool signedOk = VerifyFileSignature(fullPath);
        const bool userSpace = IsUserSpacePath(fullLower);
        const bool tempPath = IsTempPath(fullLower);
        const bool trusted = IsTrustedProcessName(exeLower);
        const int daysOld = DaysSinceFileCreation(fullPath);

        std::wstring commandLine;
        {
            HANDLE ch = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (ch) {
                commandLine = ReadRemoteCommandLine(ch);
                CloseHandle(ch);
            }
        }
        const auto cmdLower = ToLowerCopy(commandLine);
        const std::wstring haystack = exeLower + L" " + fullLower + L" " + cmdLower;

        if (!signedOk && userSpace) {
            PushFinding(
                out.findings,
                L"Process",
                L"Unsigned process from user-space",
                tempPath ? L"Unsigned process executable is running from Temp"
                         : L"Process executable is unsigned and launched from user-space",
                L"PID " + std::to_wstring(pid) + L" | DaysOld=" + std::to_wstring(daysOld),
                fullPath,
                NS_SEVERITY_MEDIUM,
                tempPath ? 68 : (daysOld <= 3 ? 62 : 48));
        }

        if (IsMasqueradingName(exeLower) && fullLower.find(L"\\windows\\system32\\") == std::wstring::npos) {
            PushFinding(
                out.findings,
                L"Process",
                L"System process name masquerading",
                L"Process name mimics system binary but path is not System32",
                L"PID " + std::to_wstring(pid),
                fullPath,
                NS_SEVERITY_HIGH,
                93);
        }

        if (ContainsCriticalToken(haystack)) {
            PushFinding(
                out.findings,
                L"Process",
                L"Process matched high-risk checker indicator",
                L"Critical loader/mapper/spoofer/brand keyword found in name/path/command line",
                L"PID " + std::to_wstring(pid) + (commandLine.empty() ? L"" : L" | Cmd=" + commandLine),
                fullPath,
                userSpace || !signedOk ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM,
                userSpace || !signedOk ? 88 : 70);
        } else if (ContainsAnyNeedle(haystack, rules.strings) || ContainsSpecificPathNeedle(haystack, rules.paths)) {
            PushFinding(
                out.findings,
                L"Process",
                L"Process name/path matched signature rules",
                L"Matched process indicator from rules.json in name/path/command line",
                L"PID " + std::to_wstring(pid) + (commandLine.empty() ? L"" : L" | Cmd=" + commandLine),
                fullPath,
                !signedOk || userSpace ? NS_SEVERITY_MEDIUM : NS_SEVERITY_LOW,
                !signedOk || userSpace ? 78 : 48);
        }

        if (ContainsDevToolToken(haystack)) {
            PushFinding(
                out.findings,
                L"Process",
                L"Dev / reverse engineering tool running",
                L"Debugging/reverse tooling detected (context only)",
                L"PID " + std::to_wstring(pid) + (commandLine.empty() ? L"" : L" | Cmd=" + commandLine),
                fullPath,
                NS_SEVERITY_LOW,
                36);
        }

        if (ContainsDangerousCommandToken(cmdLower) && (userSpace || !signedOk || tempPath)) {
            PushFinding(
                out.findings,
                L"Process",
                L"Suspicious command-line execution pattern",
                L"Process command line uses script/proxy execution from risky context",
                L"PID " + std::to_wstring(pid) + L" | Cmd=" + commandLine,
                fullPath,
                NS_SEVERITY_MEDIUM,
                tempPath ? 70 : 62);
        }

        HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!ph) {
            ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }

        bool hasGraphics = false;
        if (ph) {
            const auto modules = ReadProcessModuleSnapshot([ph](HMODULE* buffer, DWORD bytes, DWORD* needed) {
                return EnumProcessModulesEx(ph, buffer, bytes, needed, LIST_MODULES_ALL);
            });
            if (!modules) {
                out.errors++;
                CloseHandle(ph);
                continue;
            }
            hasGraphics = ProcessHasGraphicsModules(ph, *modules);
            const size_t slash = fullLower.find_last_of(L"\\/");
            const std::wstring hostDirLower = (slash == std::wstring::npos) ? std::wstring() : fullLower.substr(0, slash);
            DetectSuspiciousModules(ph, pid, hostDirLower, rules, out.findings, *modules);
            // Injection/manual-map scans are heavier and noisier on JIT apps; run
            // them only on game-like processes (graphics modules present) — exactly
            // where game cheats like melonity live.
            if (hasGraphics) {
                const auto modRanges = BuildModuleRanges(ph, *modules);
                DetectInjectedThreads(ph, pid, modRanges, out.findings);
                DetectUnbackedExecRegions(ph, pid, modRanges, out.findings);
            }
            CloseHandle(ph);
        }

        if (overlayPids.find(pid) != overlayPids.end() && hasGraphics && !trusted) {
            PushFinding(
                out.findings,
                L"Process",
                L"Unknown overlay-like process",
                L"Top-most layered window + DirectX/OpenGL modules",
                L"PID " + std::to_wstring(pid),
                fullPath,
                NS_SEVERITY_MEDIUM,
                79);
        }
    }

    if (gameRunning) {
        PushFinding(
            out.findings,
            L"Process",
            L"Game process detected",
            L"SCUM process is running during scan",
            L"Process context for access/overlay checks is active",
            L"",
            NS_SEVERITY_INFO,
            5);
    }

    return out;
}

} // namespace ns
