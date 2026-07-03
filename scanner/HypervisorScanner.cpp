#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "HypervisorScanner.h"

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {

// CPUID leaf 0x40000000 returns a 12-byte vendor signature in EBX:ECX:EDX.
// Known *legitimate* signatures — present hypervisor here is expected, low risk.
struct KnownHv {
    const char* signature;
    const wchar_t* friendly;
};

const std::array<KnownHv, 8> kKnownHypervisors = {{
    {"Microsoft Hv", L"Microsoft Hyper-V / VBS"},
    {"VMwareVMware", L"VMware"},
    {"KVMKVMKVM\0\0\0", L"KVM"},
    {"VBoxVBoxVBox", L"VirtualBox"},
    {"XenVMMXenVMM", L"Xen"},
    {"prl hyperv\0\0", L"Parallels"},
    {"TCGTCGTCGTCG", L"QEMU/TCG"},
    {"ACRNACRNACRN", L"ACRN"},
}};

// Read the hypervisor vendor signature (leaf 0x40000000). Returns 12 chars.
std::string ReadHypervisorVendor() {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 0x40000000);

    char buf[13] = {0};
    std::memcpy(buf + 0, &regs[1], 4); // EBX
    std::memcpy(buf + 4, &regs[2], 4); // ECX
    std::memcpy(buf + 8, &regs[3], 4); // EDX
    buf[12] = '\0';
    return std::string(buf, 12);
}

bool HypervisorPresentBit() {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    // CPUID.1:ECX[31] — "hypervisor present" hint.
    return (static_cast<unsigned>(regs[2]) & (1u << 31)) != 0;
}

std::wstring Trimmed(const std::string& raw) {
    std::wstring out;
    for (char c : raw) {
        if (c == '\0') break;
        out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    // strip trailing spaces
    while (!out.empty() && (out.back() == L' ')) out.pop_back();
    return out;
}

bool MatchesKnown(const std::string& vendor, const wchar_t*& friendlyOut) {
    for (const auto& hv : kKnownHypervisors) {
        if (std::memcmp(vendor.data(), hv.signature, 12) == 0) {
            friendlyOut = hv.friendly;
            return true;
        }
    }
    return false;
}

// Measure median cycle cost of a VM-exit-forcing instruction (CPUID).
// On bare metal CPUID costs ~hundreds of cycles; under most hypervisors it
// traps to the VMM and costs noticeably more. Noisy by nature — we report the
// value as context and only escalate when it is extreme.
unsigned long long MeasureCpuidCycles() {
    constexpr int kWarmup = 1000;
    constexpr int kSamples = 200;

    int regs[4];
    for (int i = 0; i < kWarmup; ++i) {
        __cpuid(regs, 0);
    }

    std::vector<unsigned long long> samples;
    samples.reserve(kSamples);

    for (int i = 0; i < kSamples; ++i) {
        unsigned int aux = 0;
        const unsigned long long start = __rdtscp(&aux);
        __cpuid(regs, 0);
        const unsigned long long end = __rdtscp(&aux);
        if (end > start) {
            samples.push_back(end - start);
        }
    }

    if (samples.empty()) return 0;
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2]; // median resists scheduler outliers
}

} // namespace

namespace ns {

ModuleOutput RunHypervisorScanner(const RuleSet& /*rules*/) {
    ModuleOutput out;

    try {
        const bool present = HypervisorPresentBit();
        const unsigned long long cpuidCycles = MeasureCpuidCycles();

        // Rough bare-metal CPUID ceiling. Above this strongly suggests trapping.
        constexpr unsigned long long kSuspiciousCycles = 1000;

        if (present) {
            const std::string vendor = ReadHypervisorVendor();
            const wchar_t* friendly = nullptr;
            const bool known = MatchesKnown(vendor, friendly);
            const std::wstring vendorW = Trimmed(vendor);

            if (known) {
                // Expected virtualization — context, not an accusation.
                PushFinding(
                    out.findings,
                    L"Hypervisor",
                    L"Hypervisor present (known vendor)",
                    L"System is running under a recognized hypervisor/VBS",
                    L"Vendor=" + std::wstring(friendly) + L" (" + vendorW + L"), CPUID=" + std::to_wstring(cpuidCycles) + L" cyc",
                    L"",
                    NS_SEVERITY_LOW,
                    20);
            } else {
                // Present bit set but vendor is blank/unknown/spoofed — exactly
                // what a stealth cheat hypervisor looks like.
                PushFinding(
                    out.findings,
                    L"Hypervisor",
                    L"Hypervisor present with unknown/blank vendor",
                    L"Hypervisor-present bit set but vendor signature is not recognized (possible stealth hypervisor)",
                    L"Vendor='" + (vendorW.empty() ? std::wstring(L"<blank>") : vendorW) + L"', CPUID=" + std::to_wstring(cpuidCycles) + L" cyc",
                    L"",
                    NS_SEVERITY_HIGH,
                    85);
            }
        } else {
            // No present bit. A thin malicious hypervisor may hide it, but
            // CPUID still traps -> abnormally high timing is a tell.
            if (cpuidCycles >= kSuspiciousCycles) {
                PushFinding(
                    out.findings,
                    L"Hypervisor",
                    L"Possible hidden hypervisor (timing anomaly)",
                    L"No hypervisor-present bit, but CPUID timing is abnormally high (possible VM-exit trapping)",
                    L"CPUID=" + std::to_wstring(cpuidCycles) + L" cyc (suspicious >= " + std::to_wstring(kSuspiciousCycles) + L")",
                    L"",
                    NS_SEVERITY_MEDIUM,
                    60);
            } else {
                PushFinding(
                    out.findings,
                    L"Hypervisor",
                    L"No hypervisor detected",
                    L"Hypervisor-present bit clear and CPUID timing within bare-metal range",
                    L"CPUID=" + std::to_wstring(cpuidCycles) + L" cyc",
                    L"",
                    NS_SEVERITY_INFO,
                    5);
            }
        }
    } catch (...) {
        out.errors++;
    }

    return out;
}

} // namespace ns
