#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "KernelSysScanner.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

namespace {

constexpr wchar_t kServiceName[] = L"KSystemInformer";
constexpr wchar_t kPortName[] = L"\\KSystemInformer";

constexpr ULONG kSystemExtendedHandleInformation = 64;

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
};

using NtQuerySystemInformationFn = NTSTATUS (NTAPI*)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

using FilterConnectCommunicationPortFn = HRESULT (WINAPI*)(
    LPCWSTR lpPortName,
    DWORD dwOptions,
    LPCVOID lpContext,
    WORD wSizeOfContext,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HANDLE* hPort);

std::wstring Win32ErrorText(DWORD error) {
    if (error == ERROR_SUCCESS) return L"success";

    wchar_t* raw = nullptr;
    const DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&raw),
        0,
        nullptr);

    std::wstring text = len && raw ? std::wstring(raw, len) : L"Win32=" + std::to_wstring(error);
    if (raw) LocalFree(raw);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
        text.pop_back();
    }
    return text;
}

std::wstring GetEnvString(const wchar_t* name) {
    wchar_t buffer[4096]{};
    const DWORD n = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(std::size(buffer)));
    if (n == 0 || n >= std::size(buffer)) return L"";
    return std::wstring(buffer, n);
}

std::wstring DriverArchFolder() {
#if defined(_M_ARM64)
    return L"arm64";
#else
    return L"amd64";
#endif
}

// Driver resource IDs - must match app/resource.h (IDR_DRIVER_AMD64 / IDR_DRIVER_ARM64).
constexpr int kDriverResAmd64 = 201;
constexpr int kDriverResArm64 = 202;

// Writes the embedded (RCDATA) driver for the current architecture into
// %TEMP%\ScumCheckerV2\<arch>\systeminformer.sys and returns its path.
// Returns empty if the resource is missing or cannot be written.
std::wstring ExtractEmbeddedDriverToTemp() {
    const HMODULE mod = GetModuleHandleW(nullptr);
#if defined(_M_ARM64)
    const int resId = kDriverResArm64;
#else
    const int resId = kDriverResAmd64;
#endif

    const HRSRC hRes = FindResourceW(mod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) return L"";
    const HGLOBAL hData = LoadResource(mod, hRes);
    const DWORD size = SizeofResource(mod, hRes);
    const void* bytes = LockResource(hData);
    if (!bytes || size == 0) return L"";

    wchar_t tempDir[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tempDir) == 0) return L"";

    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::path(tempDir) / L"ScumCheckerV2" / DriverArchFolder();
    std::filesystem::create_directories(dir, ec);
    const std::filesystem::path out = dir / L"systeminformer.sys";

    // Reuse an already-extracted copy of the same size (the service may have it open).
    if (std::filesystem::exists(out, ec) && std::filesystem::file_size(out, ec) == size) {
        return out.wstring();
    }

    HANDLE file = CreateFileW(
        out.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        // Locked because a previous instance loaded it; reuse what's on disk.
        if (std::filesystem::exists(out, ec)) return out.wstring();
        return L"";
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(file, bytes, size, &written, nullptr);
    CloseHandle(file);
    if (!ok || written != size) return L"";
    return out.wstring();
}

std::wstring ResolveSystemInformerDriverPath() {
    const auto envPath = GetEnvString(L"SCUMCHECKER_SYSTEMINFORMER_SYS");
    if (!envPath.empty() && std::filesystem::exists(envPath)) {
        return envPath;
    }

    // Prefer the driver embedded in the .exe, extracted to %TEMP% on demand.
    const auto extracted = ExtractEmbeddedDriverToTemp();
    if (!extracted.empty()) {
        return extracted;
    }

    const std::filesystem::path moduleDir = ns::GetModuleDirectory();
    const std::wstring arch = DriverArchFolder();
    const std::vector<std::filesystem::path> candidates = {
        moduleDir / L"drivers" / arch / L"systeminformer.sys",
        moduleDir / L"drivers" / L"systeminformer.sys",
        moduleDir / L"systeminformer.sys",
        std::filesystem::path(L"C:\\Users\\Nezeryxs\\Downloads\\ProcessHacker-master\\ProcessHacker-master\\KSystemInformer\\bin-signed") / arch / L"systeminformer.sys"
    };

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate.wstring();
        }
    }

    return candidates.front().wstring();
}

bool WaitForServiceState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;

    do {
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &needed)) {
            return false;
        }

        if (status.dwCurrentState == desiredState) {
            return true;
        }

        Sleep(std::clamp<DWORD>(status.dwWaitHint / 10, 120, 900));
    } while (GetTickCount64() < deadline);

    return false;
}

DWORD EnsureDriverServiceRunning(const std::wstring& driverPath, bool* createdService) {
    if (createdService) *createdService = false;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) return GetLastError();

    SC_HANDLE service = OpenServiceW(
        scm,
        kServiceName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);

    if (!service) {
        service = CreateServiceW(
            scm,
            kServiceName,
            kServiceName,
            SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            driverPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (!service) {
            const DWORD error = GetLastError();
            CloseServiceHandle(scm);
            return error;
        }

        if (createdService) *createdService = true;
    }

    DWORD result = ERROR_SUCCESS;
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) &&
        status.dwCurrentState == SERVICE_RUNNING) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return ERROR_SUCCESS;
    }

    if (!StartServiceW(service, 0, nullptr)) {
        result = GetLastError();
        if (result == ERROR_SERVICE_ALREADY_RUNNING) {
            result = ERROR_SUCCESS;
        }
    }

    if (result == ERROR_SUCCESS && !WaitForServiceState(service, SERVICE_RUNNING, 5000)) {
        result = ERROR_SERVICE_REQUEST_TIMEOUT;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return result;
}

void StopAndDeleteCreatedService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!service) {
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) &&
        status.dwCurrentState == SERVICE_RUNNING) {
        SERVICE_STATUS ignored{};
        ControlService(service, SERVICE_CONTROL_STOP, &ignored);
        WaitForServiceState(service, SERVICE_STOPPED, 3000);
    }

    DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

bool TryConnectKphPort(std::wstring* errorText) {
    HMODULE fltLib = LoadLibraryW(L"fltlib.dll");
    if (!fltLib) {
        if (errorText) *errorText = L"fltlib.dll is not available: " + Win32ErrorText(GetLastError());
        return false;
    }

    auto connect = reinterpret_cast<FilterConnectCommunicationPortFn>(
        GetProcAddress(fltLib, "FilterConnectCommunicationPort"));
    if (!connect) {
        if (errorText) *errorText = L"FilterConnectCommunicationPort export was not found.";
        FreeLibrary(fltLib);
        return false;
    }

    HANDLE port = nullptr;
    const HRESULT hr = connect(kPortName, 0, nullptr, 0, nullptr, &port);
    if (FAILED(hr)) {
        if (errorText) {
            wchar_t buf[64]{};
            swprintf_s(buf, L"HRESULT=0x%08X", static_cast<unsigned>(hr));
            *errorText = buf;
        }
        FreeLibrary(fltLib);
        return false;
    }

    if (port) CloseHandle(port);
    FreeLibrary(fltLib);
    return true;
}

bool IsSystemInformerLoaded(std::wstring* loadedName) {
    std::array<LPVOID, 4096> drivers{};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed)) {
        return false;
    }

    const DWORD count = std::min<DWORD>(needed / sizeof(LPVOID), static_cast<DWORD>(drivers.size()));
    for (DWORD i = 0; i < count; ++i) {
        wchar_t baseName[MAX_PATH]{};
        if (!GetDeviceDriverBaseNameW(drivers[i], baseName, static_cast<DWORD>(std::size(baseName)))) {
            continue;
        }
        const auto lower = ns::ToLowerCopy(baseName);
        if (lower == L"systeminformer.sys") {
            if (loadedName) *loadedName = baseName;
            return true;
        }
    }
    return false;
}

std::wstring ProcessImagePath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return L"";

    wchar_t path[2048]{};
    DWORD len = static_cast<DWORD>(std::size(path));
    std::wstring out;
    if (QueryFullProcessImageNameW(process, 0, path, &len) && len > 0) {
        out.assign(path, len);
    }
    CloseHandle(process);
    return out;
}

std::unordered_map<DWORD, std::wstring> CollectProcessImageMap() {
    std::unordered_map<DWORD, std::wstring> result;
    std::array<DWORD, 8192> pids{};
    DWORD needed = 0;
    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &needed)) {
        return result;
    }

    const DWORD count = std::min<DWORD>(needed / sizeof(DWORD), static_cast<DWORD>(pids.size()));
    for (DWORD i = 0; i < count; ++i) {
        const DWORD pid = pids[i];
        if (!pid) continue;
        auto path = ProcessImagePath(pid);
        if (!path.empty()) result.emplace(pid, std::move(path));
    }
    return result;
}

std::unordered_set<DWORD> FindGameProcessIds(const std::unordered_map<DWORD, std::wstring>& processes) {
    std::unordered_set<DWORD> targets;
    for (const auto& [pid, path] : processes) {
        const auto exe = ns::ToLowerCopy(ns::Basename(path));
        if (exe == L"scum.exe" || exe == L"dota2.exe" || exe == L"minecraft.exe" || exe == L"javaw.exe") {
            targets.insert(pid);
        }
    }
    return targets;
}

bool IsDangerousProcessAccess(ULONG access) {
    constexpr ULONG dangerous =
        PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_SUSPEND_RESUME |
        PROCESS_SET_INFORMATION;

    return (access & dangerous) != 0;
}

std::wstring AccessSummary(ULONG access) {
    std::vector<std::wstring> parts;
    if (access & PROCESS_CREATE_THREAD) parts.push_back(L"CREATE_THREAD");
    if (access & PROCESS_VM_OPERATION) parts.push_back(L"VM_OPERATION");
    if (access & PROCESS_VM_READ) parts.push_back(L"VM_READ");
    if (access & PROCESS_VM_WRITE) parts.push_back(L"VM_WRITE");
    if (access & PROCESS_DUP_HANDLE) parts.push_back(L"DUP_HANDLE");
    if (access & PROCESS_SUSPEND_RESUME) parts.push_back(L"SUSPEND_RESUME");
    if (access & PROCESS_SET_INFORMATION) parts.push_back(L"SET_INFORMATION");
    if (parts.empty()) return L"0x" + std::to_wstring(access);

    std::wstring out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += L"|";
        out += parts[i];
    }
    return out;
}

void ScanGameProcessHandles(ns::ModuleOutput& out) {
    const auto processMap = CollectProcessImageMap();
    const auto targetPids = FindGameProcessIds(processMap);
    out.processes_checked += static_cast<int>(processMap.size());

    if (targetPids.empty()) {
        ns::PushFinding(
            out.findings,
            L"KernelProvider",
            L"No active game process for handle audit",
            L"Sys-mode handle audit is ready, but target game process is not running",
            L"Start the game before sys scan to catch live external handles",
            L"",
            NS_SEVERITY_INFO,
            6);
        return;
    }

    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQuerySystemInformation = ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!ntQuerySystemInformation) {
        out.errors++;
        return;
    }

    ULONG size = 1 << 20;
    std::unique_ptr<BYTE[]> buffer;
    NTSTATUS status = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer = std::make_unique<BYTE[]>(size);
        ULONG needed = 0;
        status = ntQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>(kSystemExtendedHandleInformation),
            buffer.get(),
            size,
            &needed);
        if (status >= 0) break;
        size = needed > size ? needed + (1 << 16) : size * 2;
    }

    if (status < 0 || !buffer) {
        out.errors++;
        return;
    }

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX_LOCAL*>(buffer.get());
    std::unordered_map<DWORD, HANDLE> sourceHandles;
    std::unordered_set<std::wstring> emitted;
    int auditedHandles = 0;

    const DWORD currentPid = GetCurrentProcessId();
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& h = info->Handles[i];
        const DWORD ownerPid = static_cast<DWORD>(h.UniqueProcessId);
        if (ownerPid == 0 || ownerPid == 4 || ownerPid == currentPid || targetPids.contains(ownerPid)) {
            continue;
        }
        if (!IsDangerousProcessAccess(h.GrantedAccess)) {
            continue;
        }

        HANDLE ownerProcess = nullptr;
        auto cached = sourceHandles.find(ownerPid);
        if (cached == sourceHandles.end()) {
            ownerProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid);
            sourceHandles.emplace(ownerPid, ownerProcess);
        } else {
            ownerProcess = cached->second;
        }

        if (!ownerProcess) continue;

        HANDLE dup = nullptr;
        if (!DuplicateHandle(
                ownerProcess,
                reinterpret_cast<HANDLE>(h.HandleValue),
                GetCurrentProcess(),
                &dup,
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                0)) {
            continue;
        }

        ++auditedHandles;
        const DWORD targetPid = GetProcessId(dup);
        CloseHandle(dup);

        if (!targetPid || !targetPids.contains(targetPid)) {
            continue;
        }

        const std::wstring key = std::to_wstring(ownerPid) + L":" + std::to_wstring(targetPid) + L":" + std::to_wstring(h.GrantedAccess);
        if (emitted.contains(key)) {
            continue;
        }
        emitted.insert(key);

        const auto ownerIt = processMap.find(ownerPid);
        const auto targetIt = processMap.find(targetPid);
        const std::wstring ownerPath = ownerIt == processMap.end() ? L"" : ownerIt->second;
        const std::wstring targetName = targetIt == processMap.end() ? L"game" : ns::Basename(targetIt->second);
        const bool keyword = ns::ContainsAnyNeedle(ns::ToLowerCopy(ownerPath), std::vector<std::wstring>{
            L"cheat", L"inject", L"overlay", L"aim", L"esp", L"mapper", L"hack"
        });
        const bool signedOk = !ownerPath.empty() && ns::VerifyFileSignature(ownerPath);
        if (signedOk) continue;

        ns::PushFinding(
            out.findings,
            L"KernelHandle",
            L"External process has high-risk handle to game",
            L"Process owns a live handle to " + targetName + L" with memory/injection-capable rights",
            L"OwnerPID=" + std::to_wstring(ownerPid) +
                L" TargetPID=" + std::to_wstring(targetPid) +
                L" Access=" + AccessSummary(h.GrantedAccess) +
                (signedOk ? L" Signature=valid" : L" Signature=missing/invalid"),
            ownerPath,
            (!signedOk || keyword) ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM,
            (!signedOk || keyword) ? 92 : 76);
    }

    for (auto& [pid, handle] : sourceHandles) {
        if (handle) CloseHandle(handle);
    }

    out.registry_values_checked += auditedHandles;
}

} // namespace

namespace ns {

ModuleOutput RunKernelSysScanner(const RuleSet& rules, bool isAdmin) {
    UNREFERENCED_PARAMETER(rules);

    ModuleOutput out;

    if (!isAdmin) {
        out.status = NS_MODULE_ACCESS_DENIED;
        PushFinding(
            out.findings,
            L"KernelProvider",
            L"Sys mode requires Administrator",
            L"KSystemInformer cannot be loaded without elevation",
            L"Restart ScumCheckerV2 as Administrator to enable sys mode",
            L"",
            NS_SEVERITY_MEDIUM,
            55);
        out.errors++;
        return out;
    }

    const auto driverPath = ResolveSystemInformerDriverPath();
    if (!std::filesystem::exists(driverPath)) {
        out.status = NS_MODULE_SKIPPED;
        PushFinding(
            out.findings,
            L"KernelProvider",
            L"System Informer driver not found",
            L"Set SCUMCHECKER_SYSTEMINFORMER_SYS or copy systeminformer.sys into drivers\\" + DriverArchFolder(),
            driverPath,
            driverPath,
            NS_SEVERITY_MEDIUM,
            58);
        out.errors++;
        return out;
    }

    const bool signedOk = VerifyFileSignature(driverPath);
    bool createdService = false;
    const DWORD startError = EnsureDriverServiceRunning(driverPath, &createdService);
    if (startError != ERROR_SUCCESS) {
        out.status = NS_MODULE_FAILED;
        PushFinding(
            out.findings,
            L"KernelProvider",
            L"KSystemInformer failed to start",
            L"Driver service could not be started: " + Win32ErrorText(startError),
            L"Path=" + driverPath + (signedOk ? L" | Signature=valid" : L" | Signature=missing/invalid"),
            driverPath,
            NS_SEVERITY_HIGH,
            82);
        out.errors++;
        return out;
    }

    std::wstring loadedName;
    const bool loaded = IsSystemInformerLoaded(&loadedName);
    std::wstring portError;
    const bool portOk = TryConnectKphPort(&portError);
    if (!portOk || !signedOk) out.status = NS_MODULE_PARTIAL;

    PushFinding(
        out.findings,
        L"KernelProvider",
        portOk ? L"Sys mode is active" : L"Driver loaded but KPH port is not reachable",
        portOk ? L"KSystemInformer service is running and Filter Manager port accepted a connection"
               : L"KSystemInformer started, but user-mode KPH channel could not be opened",
        L"Service=" + std::wstring(kServiceName) +
            L" | Driver=" + (loaded ? loadedName : L"not visible in EnumDeviceDrivers") +
            L" | CreatedService=" + std::wstring(createdService ? L"yes" : L"no") +
            L" | Port=" + (portOk ? L"connected" : portError) +
            (signedOk ? L" | Signature=valid" : L" | Signature=missing/invalid"),
        driverPath,
        portOk ? NS_SEVERITY_INFO : NS_SEVERITY_LOW,
        portOk ? 12 : 34);

    if (!signedOk) {
        PushFinding(
            out.findings,
            L"KernelProvider",
            L"Configured sys driver signature is not trusted",
            L"Do not rely on sys mode until the configured driver file is verified",
            driverPath,
            driverPath,
            NS_SEVERITY_HIGH,
            90);
    }

    out.drivers_checked++;
    ScanGameProcessHandles(out);
    if (createdService) {
        StopAndDeleteCreatedService();
    }
    return out;
}

} // namespace ns
