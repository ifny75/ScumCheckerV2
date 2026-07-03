#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "SecurityConfigScanner.h"

#include <Windows.h>

#include <optional>
#include <string>

namespace {

// Best-effort DWORD read. Returns nullopt when the key/value is missing or the
// caller lacks rights (Defender keys are tamper-protected) — callers treat that
// as "unknown", never as an error spam source.
std::optional<DWORD> ReadDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, REGSAM sam = 0) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ | sam, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LONG rc = RegQueryValueExW(key, valueName, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);

    if (rc != ERROR_SUCCESS || type != REG_DWORD) {
        return std::nullopt;
    }
    return value;
}

// ---- individual checks: each takes (const RuleSet&, ModuleOutput&) ----------

void CheckSecureBoot(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    const auto state = ReadDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled");
    if (!state.has_value()) return; // legacy BIOS / unreadable — stay silent
    ++out.registry_values_checked;

    if (*state == 1) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Secure Boot enabled",
            L"UEFI Secure Boot is active — firmware/bootkit surface reduced",
            L"UEFISecureBootEnabled=1",
            L"",
            NS_SEVERITY_INFO,
            5);
    } else {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Secure Boot disabled",
            L"Secure Boot is off — unsigned bootloaders/drivers can load earlier in boot",
            L"UEFISecureBootEnabled=0",
            L"",
            NS_SEVERITY_MEDIUM,
            70);
    }
}

void CheckCodeSigningEnforcement(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    // SystemStartOptions mirrors active boot flags. TESTSIGNING / nointegritychecks
    // mean Driver Signature Enforcement is relaxed — the classic BYOVD setup.
    HKEY control = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_READ, &control) != ERROR_SUCCESS) {
        return;
    }
    const auto opts = ns::QueryStringValue(control, L"SystemStartOptions");
    RegCloseKey(control);

    if (!opts.has_value()) return;
    ++out.registry_values_checked;

    const auto lower = ns::ToLowerCopy(*opts);
    const bool testSigning = lower.find(L"testsigning") != std::wstring::npos;
    const bool noIntegrity = lower.find(L"nointegritychecks") != std::wstring::npos ||
                             lower.find(L"disable_integrity_checks") != std::wstring::npos;
    // An attached kernel debugger lets DSE be toggled off at runtime — same effect.
    const bool kernelDebug = lower.find(L"debug") != std::wstring::npos;

    if (testSigning) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Windows test-signing mode enabled",
            L"TESTSIGNING is active — custom kernel drivers signed by a test certificate can load",
            L"SystemStartOptions=" + *opts,
            L"",
            NS_SEVERITY_HIGH,
            92);
    }

    if (noIntegrity) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Driver signature enforcement disabled",
            L"Boot options disable DSE — unsigned kernel drivers can load (typical BYOVD precondition)",
            L"SystemStartOptions=" + *opts,
            L"",
            NS_SEVERITY_HIGH,
            94);
    }

    if (kernelDebug) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Kernel debugging enabled",
            L"Boot options enable kernel debugging — DSE can be disabled at runtime via the debugger",
            L"SystemStartOptions=" + *opts,
            L"",
            NS_SEVERITY_HIGH,
            84);
    }
}

void CheckVulnerableDriverBlocklist(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    // Microsoft's vulnerable-driver blocklist (HVCI-backed) blocks known BYOVD
    // drivers. When the value exists and is 0, blocking is off.
    const auto enabled = ReadDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        L"VulnerableDriverBlocklistEnable");
    if (!enabled.has_value()) return;
    ++out.registry_values_checked;

    if (*enabled == 0) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Vulnerable driver blocklist disabled",
            L"Microsoft vulnerable-driver blocklist is off — known BYOVD drivers are not blocked",
            L"VulnerableDriverBlocklistEnable=0",
            L"",
            NS_SEVERITY_MEDIUM,
            66);
    }
}

void CheckDefender(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    // Tamper protection guards these keys; a denied read is itself benign-unknown.
    const auto rtDisabled = ReadDword(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableRealtimeMonitoring");
    if (rtDisabled.has_value()) {
        ++out.registry_values_checked;
        if (*rtDisabled == 1) {
            ns::PushFinding(
                out.findings,
                L"SecurityConfig",
                L"Defender real-time protection disabled",
                L"Real-time monitoring is turned off — on-access detection is not running",
                L"DisableRealtimeMonitoring=1",
                L"",
                NS_SEVERITY_HIGH,
                82);
        }
    }

    const auto tamper = ReadDword(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
        L"TamperProtection");
    if (tamper.has_value()) {
        ++out.registry_values_checked;
        // 5 = enabled, anything else (commonly 0/4) = off/disabled.
        if (*tamper != 5) {
            ns::PushFinding(
                out.findings,
                L"SecurityConfig",
                L"Defender tamper protection off",
                L"Tamper protection is not enabled — security settings can be silently modified",
                L"TamperProtection=" + std::to_wstring(*tamper),
                L"",
                NS_SEVERITY_MEDIUM,
                68);
        }
    }
}

void CheckVbsHvci(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    const auto hvci = ReadDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled");
    if (!hvci.has_value()) return;
    ++out.registry_values_checked;

    if (*hvci == 1) {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"HVCI enabled",
            L"Hypervisor-enforced code integrity is active — kernel memory integrity is protected",
            L"HypervisorEnforcedCodeIntegrity.Enabled=1",
            L"",
            NS_SEVERITY_INFO,
            5);
    } else {
        ns::PushFinding(
            out.findings,
            L"SecurityConfig",
            L"HVCI not enabled",
            L"Memory integrity (HVCI) is off — weakens protection against malicious kernel drivers",
            L"HypervisorEnforcedCodeIntegrity.Enabled=" + std::to_wstring(*hvci),
            L"",
            NS_SEVERITY_LOW,
            40);
    }
}

} // namespace

namespace ns {

ModuleOutput RunSecurityConfigScanner(const RuleSet& rules, bool isAdmin) {
    ModuleOutput out;
    if (!isAdmin) {
        PushFinding(
            out.findings,
            L"SecurityConfig",
            L"Security-config scan limited without admin rights",
            L"Some protection settings (Defender, tamper protection) are unreadable without elevation",
            L"Run scanner as Administrator for full visibility",
            L"",
            NS_SEVERITY_LOW,
            25);
    }

    try {
        CheckSecureBoot(rules, out);
        CheckCodeSigningEnforcement(rules, out);
        CheckVulnerableDriverBlocklist(rules, out);
        CheckDefender(rules, out);
        CheckVbsHvci(rules, out);
    } catch (...) {
        out.errors++;
    }

    return out;
}

} // namespace ns
