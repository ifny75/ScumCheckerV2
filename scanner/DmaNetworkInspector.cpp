#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "DmaNetworkInspector.h"

#include <Windows.h>
#include <SetupAPI.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <Psapi.h>

#include <array>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace {

// ---- PCIe side ----------------------------------------------------------

struct FpgaVendor { const wchar_t* id; const wchar_t* name; };
const std::array<FpgaVendor, 5> kFpgaVendors = {{
    {L"10EE", L"Xilinx"},
    {L"1172", L"Altera / Intel FPGA"},
    {L"1204", L"Lattice"},
    {L"1B55", L"NetUP (FPGA boards)"},
    {L"1DA1", L"Teledyne / FPGA dev boards"},
}};

std::wstring ToUpper(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(::towupper(c));
    return s;
}

std::wstring GetDevStr(HDEVINFO h, SP_DEVINFO_DATA& d, DWORD prop) {
    DWORD type = 0, req = 0;
    std::vector<BYTE> buf(512);
    if (!SetupDiGetDeviceRegistryPropertyW(h, &d, prop, &type, buf.data(),
                                           static_cast<DWORD>(buf.size()), &req)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && req > 0) {
            buf.resize(req);
            if (!SetupDiGetDeviceRegistryPropertyW(h, &d, prop, &type, buf.data(),
                                                   static_cast<DWORD>(buf.size()), &req))
                return {};
        } else {
            return {};
        }
    }
    return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
}

std::wstring ExtractToken(const std::wstring& hwid, const wchar_t* key, size_t len) {
    const std::wstring up = ToUpper(hwid);
    const size_t k = up.find(key);
    if (k == std::wstring::npos) return {};
    const size_t start = k + wcslen(key);
    if (start + len > up.size()) return {};
    return up.substr(start, len);
}

const wchar_t* MatchFpga(const std::wstring& ven) {
    for (const auto& v : kFpgaVendors) if (ven == v.id) return v.name;
    return nullptr;
}

void EnumeratePcie(ns::ModuleOutput& out) {
    HDEVINFO h = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (h == INVALID_HANDLE_VALUE) { out.errors++; return; }

    SP_DEVINFO_DATA d{};
    d.cbSize = sizeof(d);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &d); ++i) {
        const std::wstring hwid = GetDevStr(h, d, SPDRP_HARDWAREID);
        const std::wstring desc = GetDevStr(h, d, SPDRP_DEVICEDESC);
        const std::wstring driver = GetDevStr(h, d, SPDRP_DRIVER);
        const std::wstring ven = ExtractToken(hwid, L"VEN_", 4);
        const std::wstring dev = ExtractToken(hwid, L"DEV_", 4);

        const wchar_t* fpga = ven.empty() ? nullptr : MatchFpga(ven);
        const bool noDriver = driver.empty();

        // DMA-risk degree.
        int degree = NS_SEVERITY_INFO;
        int score = 5;
        std::wstring reason = L"Standard PCIe device";
        if (fpga && noDriver) {
            degree = NS_SEVERITY_HIGH; score = 92;
            reason = std::wstring(L"FPGA vendor (") + fpga + L") with no driver — typical DMA attack card";
        } else if (fpga) {
            degree = NS_SEVERITY_MEDIUM; score = 70;
            reason = std::wstring(L"FPGA vendor (") + fpga + L") present — review purpose";
        } else if (noDriver) {
            degree = NS_SEVERITY_LOW; score = 30;
            reason = L"PCIe device with no bound driver";
        }

        const std::wstring cls = GetDevStr(h, d, SPDRP_CLASS);
        const std::wstring mfg = GetDevStr(h, d, SPDRP_MFG);
        const std::wstring loc = GetDevStr(h, d, SPDRP_LOCATION_INFORMATION);
        const std::wstring svc = GetDevStr(h, d, SPDRP_SERVICE);

        std::wstring details =
            L"VEN_" + (ven.empty() ? std::wstring(L"????") : ven) +
            L" DEV_" + (dev.empty() ? std::wstring(L"????") : dev) +
            L" | Driver=" + (noDriver ? std::wstring(L"<none>") : (svc.empty() ? std::wstring(L"bound") : svc)) +
            (cls.empty() ? std::wstring() : L" | class=" + cls) +
            (mfg.empty() ? std::wstring() : L" | mfg=" + mfg) +
            (loc.empty() ? std::wstring() : L" | " + loc) +
            (fpga ? std::wstring(L" | FPGA=") + fpga : std::wstring());

        ns::PushFinding(
            out.findings,
            L"PCIeDevice",
            desc.empty() ? hwid : desc,
            reason,
            details,
            hwid,
            degree,
            score);
        out.drivers_checked++;
    }

    SetupDiDestroyDeviceInfoList(h);
}

// ---- Network side -------------------------------------------------------

std::wstring ProcessNameForPid(DWORD pid) {
    if (pid == 0) return L"System Idle";
    if (pid == 4) return L"System";
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) return L"pid:" + std::to_wstring(pid);
    wchar_t buf[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    std::wstring name = L"pid:" + std::to_wstring(pid);
    if (QueryFullProcessImageNameW(p, 0, buf, &sz)) {
        std::wstring full(buf);
        const size_t slash = full.find_last_of(L"\\/");
        name = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    }
    CloseHandle(p);
    return name;
}

std::wstring Ipv4ToString(DWORD addrBe) {
    in_addr a{};
    a.S_un.S_addr = addrBe;
    wchar_t buf[INET_ADDRSTRLEN]{};
    InetNtopW(AF_INET, &a, buf, INET_ADDRSTRLEN);
    return std::wstring(buf);
}

bool IsRoutableRemote(DWORD addrBe) {
    const unsigned a = addrBe & 0xFF;          // first octet (network byte order -> low byte)
    const unsigned b = (addrBe >> 8) & 0xFF;
    if (a == 127) return false;                // loopback
    if (a == 0) return false;                  // unspecified
    if (a == 10) return true;                  // private but real peer (LAN radar!)
    if (a == 192 && b == 168) return true;     // LAN
    if (a == 172 && (b >= 16 && b <= 31)) return true; // LAN
    return true;                               // public
}

void EnumerateConnections(const ns::RuleSet& /*rules*/, ns::ModuleOutput& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        out.errors++;
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    int established = 0;
    int lanPeers = 0;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue; // only live connections
        if (!IsRoutableRemote(row.dwRemoteAddr)) continue;

        ++established;
        const std::wstring proc = ProcessNameForPid(row.dwOwningPid);
        const std::wstring remote = Ipv4ToString(row.dwRemoteAddr);
        const USHORT rport = ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFF));

        const unsigned a = row.dwRemoteAddr & 0xFF;
        const unsigned b = (row.dwRemoteAddr >> 8) & 0xFF;
        const bool lan = (a == 10) || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31);
        if (lan) ++lanPeers;

        // A LAN peer is the interesting case for a network radar relay (second
        // device on the same network pulling/receiving data). Public endpoints
        // are almost always the game/CDN/voice — informational.
        const int degree = lan ? NS_SEVERITY_LOW : NS_SEVERITY_INFO;
        const int score = lan ? 35 : 5;

        ns::PushFinding(
            out.findings,
            L"NetConn",
            proc + L" \x2192 " + remote + L":" + std::to_wstring(rport),
            lan ? L"Established connection to a LAN peer (review for radar relay)"
                : L"Established remote connection",
            L"Process=" + proc + L" | Remote=" + remote + L":" + std::to_wstring(rport) +
                (lan ? std::wstring(L" | scope=LAN") : std::wstring(L" | scope=public")),
            L"",
            degree,
            score);
    }

    // Honest summary + the hard limit on client-side radar detection.
    ns::PushFinding(
        out.findings,
        L"NetInfo",
        L"Network radar note",
        L"A true DMA/hardware radar runs on a SEPARATE device and is NOT visible from this PC. "
        L"This list shows only local connections; use it to spot a same-machine relay, "
        L"not an external radar. Reliable radar detection is server-side (behavioral).",
        L"EstablishedRemote=" + std::to_wstring(established) + L" | LANpeers=" + std::to_wstring(lanPeers),
        L"",
        NS_SEVERITY_INFO,
        0);
}

// ---- ARP neighbours (devices on the LAN) -------------------------------

void EnumerateArp(ns::ModuleOutput& out) {
    ULONG size = 0;
    if (GetIpNetTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buffer(size);
    auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buffer.data());
    if (GetIpNetTable(table, &size, FALSE) != NO_ERROR) { out.errors++; return; }

    int neighbours = 0;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwType == MIB_IPNET_TYPE_INVALID) continue;
        if (row.dwPhysAddrLen != 6) continue; // real Ethernet/Wi-Fi neighbour

        // Skip multicast (01:00:5E… / I-G bit set), broadcast and null MACs —
        // those are not actual devices, just noise.
        const bool multicast = (row.bPhysAddr[0] & 0x01) != 0;
        const bool broadcast = row.bPhysAddr[0] == 0xFF && row.bPhysAddr[1] == 0xFF &&
                               row.bPhysAddr[2] == 0xFF && row.bPhysAddr[3] == 0xFF;
        const bool nullMac = (row.bPhysAddr[0] | row.bPhysAddr[1] | row.bPhysAddr[2] |
                              row.bPhysAddr[3] | row.bPhysAddr[4] | row.bPhysAddr[5]) == 0;
        if (multicast || broadcast || nullMac) continue;

        const std::wstring ip = Ipv4ToString(row.dwAddr);
        wchar_t mac[32]{};
        swprintf(mac, 32, L"%02X:%02X:%02X:%02X:%02X:%02X",
                 row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                 row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
        const bool dynamic = (row.dwType == MIB_IPNET_TYPE_DYNAMIC);

        ns::PushFinding(out.findings, L"NetArp",
            ip + L"  (" + mac + L")",
            L"Device present on the local network (ARP neighbour)",
            std::wstring(L"MAC=") + mac + L" | type=" + (dynamic ? L"dynamic" : L"static"),
            L"", NS_SEVERITY_INFO, dynamic ? 8 : 4);
        ++neighbours;
    }

    ns::PushFinding(out.findings, L"NetArp",
        L"LAN neighbour summary",
        L"Other devices seen on the local network. A network radar relay would be one of these.",
        L"Neighbours=" + std::to_wstring(neighbours),
        L"", NS_SEVERITY_INFO, 0);
}

} // namespace

namespace ns {

ModuleOutput RunDmaNetworkInspector(const RuleSet& rules) {
    ModuleOutput out;
    try {
        EnumeratePcie(out);
        EnumerateConnections(rules, out);
        EnumerateArp(out);
    } catch (...) {
        out.errors++;
    }
    return out;
}

} // namespace ns
