#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "PcieScanner.h"

#include <Windows.h>
#include <SetupAPI.h>

#include <array>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")

namespace {

// FPGA / dev-board vendors commonly used to build DMA attack cards. A raw FPGA
// vendor ID sitting on the PCIe bus of a gaming PC is the strongest cheap tell,
// because legitimate consumer hardware almost never exposes a bare FPGA vendor.
struct FpgaVendor {
    const wchar_t* id;   // 4 hex chars, uppercase
    const wchar_t* name;
};

const std::array<FpgaVendor, 5> kFpgaVendors = {{
    {L"10EE", L"Xilinx"},
    {L"1172", L"Altera / Intel FPGA"},
    {L"1204", L"Lattice"},
    {L"1B55", L"NetUP (FPGA boards)"},
    {L"1DA1", L"Teledyne / FPGA dev boards"},
}};

std::wstring ToUpperCopy(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(::towupper(c));
    return s;
}

// Pull a single string device property; returns empty on failure.
std::wstring GetDeviceStringProperty(HDEVINFO devInfo, SP_DEVINFO_DATA& data, DWORD prop) {
    DWORD dataType = 0;
    std::vector<BYTE> buffer(512);
    DWORD required = 0;

    if (!SetupDiGetDeviceRegistryPropertyW(devInfo, &data, prop, &dataType,
                                           buffer.data(), static_cast<DWORD>(buffer.size()), &required)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && required > 0) {
            buffer.resize(required);
            if (!SetupDiGetDeviceRegistryPropertyW(devInfo, &data, prop, &dataType,
                                                   buffer.data(), static_cast<DWORD>(buffer.size()), &required)) {
                return {};
            }
        } else {
            return {};
        }
    }

    // For REG_MULTI_SZ (e.g. hardware IDs) we take the first string.
    return std::wstring(reinterpret_cast<wchar_t*>(buffer.data()));
}

// Extract the 4-char VEN_ token from a hardware ID like "PCI\VEN_10EE&DEV_7024&...".
std::wstring ExtractVendorId(const std::wstring& hardwareId) {
    const std::wstring upper = ToUpperCopy(hardwareId);
    const size_t pos = upper.find(L"VEN_");
    if (pos == std::wstring::npos || pos + 8 > upper.size()) return {};
    return upper.substr(pos + 4, 4);
}

const wchar_t* MatchFpgaVendor(const std::wstring& venId) {
    for (const auto& v : kFpgaVendors) {
        if (venId == v.id) return v.name;
    }
    return nullptr;
}

void EnumeratePciDevices(const ns::RuleSet& rules, ns::ModuleOutput& out) {
    // Enumerator "PCI" restricts the set to the PCI/PCIe bus.
    HDEVINFO devInfo = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (devInfo == INVALID_HANDLE_VALUE) {
        out.errors++;
        return;
    }

    SP_DEVINFO_DATA data{};
    data.cbSize = sizeof(SP_DEVINFO_DATA);

    int devicesChecked = 0;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &data); ++i) {
        ++devicesChecked;

        const std::wstring hardwareId = GetDeviceStringProperty(devInfo, data, SPDRP_HARDWAREID);
        const std::wstring desc = GetDeviceStringProperty(devInfo, data, SPDRP_DEVICEDESC);
        const std::wstring driver = GetDeviceStringProperty(devInfo, data, SPDRP_DRIVER);
        const std::wstring venId = ExtractVendorId(hardwareId);

        const wchar_t* fpgaName = venId.empty() ? nullptr : MatchFpgaVendor(venId);
        const bool noDriver = driver.empty();

        const std::wstring label = desc.empty() ? hardwareId : desc;
        const std::wstring details =
            L"VEN_" + (venId.empty() ? std::wstring(L"????") : venId) +
            L", Driver=" + (noDriver ? std::wstring(L"<none>") : driver) +
            L", HWID=" + hardwareId;

        if (fpgaName) {
            // FPGA on the bus. No driver => almost certainly not legit hardware.
            const int severity = noDriver ? NS_SEVERITY_HIGH : NS_SEVERITY_MEDIUM;
            const int score = noDriver ? 92 : 70;
            ns::PushFinding(
                out.findings,
                L"PCIe",
                noDriver ? L"FPGA PCIe device with no driver (possible DMA card)"
                         : L"FPGA PCIe device present (possible DMA card)",
                std::wstring(L"PCIe device exposes FPGA vendor ") + fpgaName +
                    (noDriver ? L" and has no bound driver" : L""),
                details,
                hardwareId,
                severity,
                score);
        } else if (noDriver) {
            // Non-FPGA but driverless PCIe device — weaker signal, worth noting.
            ns::PushFinding(
                out.findings,
                L"PCIe",
                L"PCIe device with no bound driver",
                L"Present PCIe device has no driver bound (unusual; review)",
                details,
                hardwareId,
                NS_SEVERITY_LOW,
                30);
        } else if (!rules.strings.empty() &&
                   ns::ContainsAnyNeedle(ns::ToLowerCopy(label), rules.strings)) {
            ns::PushFinding(
                out.findings,
                L"PCIe",
                L"PCIe device name matched suspicious keyword",
                L"Device description matched signature rules",
                details,
                hardwareId,
                NS_SEVERITY_MEDIUM,
                55);
        }
    }

    out.drivers_checked += devicesChecked; // reuse existing counter for visibility
    SetupDiDestroyDeviceInfoList(devInfo);
}

// Best-effort read of virtualization-based security state. Authoritative
// IOMMU / Kernel DMA Protection status needs the kernel agent (Layer 3); this
// only reports what the registry exposes so the admin has context.
void CheckDmaProtectionContext(ns::ModuleOutput& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                      0, KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }

    DWORD vbsRunning = 0;
    DWORD size = sizeof(vbsRunning);
    // EnableVirtualizationBasedSecurity reflects policy, not live state, but is
    // the most reliable usermode-readable proxy we have.
    if (RegQueryValueExW(key, L"EnableVirtualizationBasedSecurity", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&vbsRunning), &size) == ERROR_SUCCESS) {
        if (vbsRunning == 0) {
            ns::PushFinding(
                out.findings,
                L"PCIe",
                L"Virtualization-based security disabled",
                L"VBS/Device Guard policy is disabled — DMA protections may be weaker (context only)",
                L"EnableVirtualizationBasedSecurity=0",
                L"",
                NS_SEVERITY_LOW,
                25);
        }
    }

    RegCloseKey(key);
}

} // namespace

namespace ns {

ModuleOutput RunPcieScanner(const RuleSet& rules) {
    ModuleOutput out;
    try {
        EnumeratePciDevices(rules, out);
        CheckDmaProtectionContext(out);
    } catch (...) {
        out.errors++;
    }
    return out;
}

} // namespace ns
