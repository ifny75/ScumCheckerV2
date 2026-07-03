#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "SteamScanner.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr unsigned long long kSteamId64Base = 76561197960265728ull;

struct SteamAccountInfo {
    std::string steamId64;
    std::string accountName;
    std::string personaName;
    std::string mostRecent;
    std::string timestamp;
    std::filesystem::path loginUsersPath;
    std::filesystem::path userDataPath;
    std::filesystem::file_time_type userDataWrite{};
    std::filesystem::file_time_type localConfigWrite{};
    bool hasUserDataWrite = false;
    bool hasLocalConfigWrite = false;
    bool seenInUserData = false;
    std::string scumLastPlayed;
    std::string dotaLastPlayed;
    std::string csLastPlayed;
};

std::wstring WidenUtf8Lossy(const std::string& value) {
    if (value.empty()) return {};
    const int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) {
        std::wstring fallback;
        fallback.reserve(value.size());
        for (unsigned char c : value) fallback.push_back(static_cast<wchar_t>(c));
        return fallback;
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed);
    return out;
}

std::string ReadTextFileUtf8(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) return {};
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::wstring FormatFileTime(std::filesystem::file_time_type time) {
    if (time == std::filesystem::file_time_type{}) return L"";
    const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        time - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    std::tm local{};
    localtime_s(&local, &tt);
    wchar_t buf[32]{};
    wcsftime(buf, std::size(buf), L"%Y-%m-%d %H:%M:%S", &local);
    return buf;
}

std::wstring FormatUnixLocal(const std::string& raw) {
    if (raw.empty()) return L"";
    char* end = nullptr;
    const long long seconds = std::strtoll(raw.c_str(), &end, 10);
    if (!end || *end != '\0' || seconds <= 0) return L"";
    std::time_t tt = static_cast<std::time_t>(seconds);
    std::tm local{};
    localtime_s(&local, &tt);
    wchar_t buf[32]{};
    wcsftime(buf, std::size(buf), L"%Y-%m-%d %H:%M:%S", &local);
    return buf;
}

std::string FirstNonEmpty(const std::string& current, const std::string& next) {
    return current.empty() ? next : current;
}

std::string GetVdfValue(const std::string& body, const char* key) {
    const std::regex rx(std::string("\"") + key + "\"\\s*\"([^\"]*)\"", std::regex::icase);
    std::smatch match;
    if (std::regex_search(body, match, rx) && match.size() > 1) {
        return match[1].str();
    }
    return {};
}

std::string ExtractLastPlayed(const std::string& text, const char* appId) {
    const std::regex appRx(std::string("\"") + appId + "\"\\s*\\{([\\s\\S]*?)\\}", std::regex::icase);
    std::smatch appMatch;
    if (!std::regex_search(text, appMatch, appRx) || appMatch.size() < 2) return {};
    return GetVdfValue(appMatch[1].str(), "LastPlayed");
}

std::wstring ReadRegistrySteamPath() {
    HKEY key = nullptr;
    std::wstring path;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (auto p = ns::QueryStringValue(key, L"SteamPath"); p.has_value()) path = *p;
        if (path.empty()) {
            if (auto exe = ns::QueryStringValue(key, L"SteamExe"); exe.has_value()) {
                path = std::filesystem::path(*exe).parent_path().wstring();
            }
        }
        RegCloseKey(key);
    }

    if (path.empty() && RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (auto p = ns::QueryStringValue(key, L"InstallPath"); p.has_value()) path = *p;
        RegCloseKey(key);
    }

    return path;
}

void AddRoot(std::vector<std::filesystem::path>& roots, std::unordered_set<std::wstring>& seen, const std::filesystem::path& root) {
    if (root.empty()) return;
    std::error_code ec;
    const auto normalized = std::filesystem::weakly_canonical(root, ec);
    const auto candidate = ec ? root : normalized;
    if (!std::filesystem::exists(candidate, ec) || ec) return;
    auto lower = ns::ToLowerCopy(candidate.wstring());
    if (seen.insert(lower).second) roots.push_back(candidate);
}

void AddLibrariesFromVdf(std::vector<std::filesystem::path>& roots, std::unordered_set<std::wstring>& seen, const std::filesystem::path& steamRoot) {
    const auto libraryFolders = steamRoot / "steamapps" / "libraryfolders.vdf";
    const auto text = ReadTextFileUtf8(libraryFolders);
    if (text.empty()) return;

    const std::regex pathRx("\"path\"\\s*\"([^\"]+)\"", std::regex::icase);
    for (auto it = std::sregex_iterator(text.begin(), text.end(), pathRx); it != std::sregex_iterator(); ++it) {
        auto path = (*it)[1].str();
        for (auto& ch : path) {
            if (ch == '/') ch = '\\';
        }
        AddRoot(roots, seen, std::filesystem::path(WidenUtf8Lossy(path)));
    }
}

void AddAllUserLocalSteamRoots(std::vector<std::filesystem::path>& roots, std::unordered_set<std::wstring>& seen) {
    const std::filesystem::path users = L"C:\\Users";
    std::error_code ec;
    if (!std::filesystem::exists(users, ec) || ec) return;

    for (const auto& entry : std::filesystem::directory_iterator(users, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!entry.is_directory(ec) || ec) {
            ec.clear();
            continue;
        }
        AddRoot(roots, seen, entry.path() / L"AppData" / L"Local" / L"Steam");
    }
}

std::vector<std::filesystem::path> GetSteamRoots() {
    std::vector<std::filesystem::path> roots;
    std::unordered_set<std::wstring> seen;

    AddRoot(roots, seen, ReadRegistrySteamPath());

    wchar_t pf86[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", pf86, static_cast<DWORD>(std::size(pf86))) > 0) {
        AddRoot(roots, seen, std::filesystem::path(pf86) / L"Steam");
    }

    wchar_t pf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"ProgramFiles", pf, static_cast<DWORD>(std::size(pf))) > 0) {
        AddRoot(roots, seen, std::filesystem::path(pf) / L"Steam");
    }

    wchar_t local[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local))) > 0) {
        AddRoot(roots, seen, std::filesystem::path(local) / L"Steam");
    }

    AddAllUserLocalSteamRoots(roots, seen);

    const auto primaryRoots = roots;
    for (const auto& root : primaryRoots) {
        AddLibrariesFromVdf(roots, seen, root);
    }

    return roots;
}

SteamAccountInfo& AccountById(std::unordered_map<std::string, SteamAccountInfo>& accounts, const std::string& id) {
    auto& info = accounts[id];
    if (info.steamId64.empty()) info.steamId64 = id;
    return info;
}

void ParseLoginUsers(const std::filesystem::path& loginUsers, std::unordered_map<std::string, SteamAccountInfo>& accounts, ns::ModuleOutput& out) {
    const auto text = ReadTextFileUtf8(loginUsers);
    if (text.empty()) return;

    const std::regex accountRx("\"(7656\\d{13,17})\"\\s*\\{([\\s\\S]*?)\\}", std::regex::icase);
    for (auto it = std::sregex_iterator(text.begin(), text.end(), accountRx); it != std::sregex_iterator(); ++it) {
        const auto id = (*it)[1].str();
        const auto body = (*it)[2].str();
        auto& info = AccountById(accounts, id);
        info.accountName = FirstNonEmpty(info.accountName, GetVdfValue(body, "AccountName"));
        info.personaName = FirstNonEmpty(info.personaName, GetVdfValue(body, "PersonaName"));
        info.mostRecent = FirstNonEmpty(info.mostRecent, GetVdfValue(body, "MostRecent"));
        info.timestamp = FirstNonEmpty(info.timestamp, GetVdfValue(body, "Timestamp"));
        if (info.loginUsersPath.empty()) info.loginUsersPath = loginUsers;
        out.steam_accounts_checked++;
    }
}

void ParseUserData(const std::filesystem::path& steamRoot, std::unordered_map<std::string, SteamAccountInfo>& accounts) {
    const auto userdata = steamRoot / "userdata";
    std::error_code ec;
    if (!std::filesystem::exists(userdata, ec) || ec) return;

    for (const auto& entry : std::filesystem::directory_iterator(userdata, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!entry.is_directory(ec) || ec) {
            ec.clear();
            continue;
        }

        const auto folder = entry.path().filename().string();
        char* end = nullptr;
        const unsigned long long account32 = std::strtoull(folder.c_str(), &end, 10);
        if (!end || *end != '\0' || account32 == 0) continue;

        auto& info = AccountById(accounts, std::to_string(kSteamId64Base + account32));
        info.seenInUserData = true;
        if (info.userDataPath.empty()) info.userDataPath = entry.path();

        auto write = std::filesystem::last_write_time(entry.path(), ec);
        if (!ec) {
            info.userDataWrite = write;
            info.hasUserDataWrite = true;
        }
        ec.clear();

        const auto localConfig = entry.path() / "config" / "localconfig.vdf";
        if (!std::filesystem::exists(localConfig, ec) || ec) {
            ec.clear();
            continue;
        }

        auto cfgWrite = std::filesystem::last_write_time(localConfig, ec);
        if (!ec) {
            info.localConfigWrite = cfgWrite;
            info.hasLocalConfigWrite = true;
        }
        ec.clear();

        const auto cfg = ReadTextFileUtf8(localConfig);
        if (!cfg.empty()) {
            info.scumLastPlayed = FirstNonEmpty(info.scumLastPlayed, ExtractLastPlayed(cfg, "513710"));
            info.dotaLastPlayed = FirstNonEmpty(info.dotaLastPlayed, ExtractLastPlayed(cfg, "570"));
            info.csLastPlayed = FirstNonEmpty(info.csLastPlayed, ExtractLastPlayed(cfg, "730"));
        }
    }
}

void EmitAccounts(const std::unordered_map<std::string, SteamAccountInfo>& accounts, ns::ModuleOutput& out) {
    std::vector<SteamAccountInfo> ordered;
    ordered.reserve(accounts.size());
    for (const auto& kv : accounts) ordered.push_back(kv.second);

    std::stable_sort(ordered.begin(), ordered.end(), [](const SteamAccountInfo& a, const SteamAccountInfo& b) {
        const bool ar = a.mostRecent == "1" || ns::ToLowerCopy(WidenUtf8Lossy(a.mostRecent)) == L"true";
        const bool br = b.mostRecent == "1" || ns::ToLowerCopy(WidenUtf8Lossy(b.mostRecent)) == L"true";
        if (ar != br) return ar > br;
        return a.timestamp > b.timestamp;
    });

    for (const auto& x : ordered) {
        const auto account = x.accountName.empty() ? std::string("unknown") : x.accountName;
        const auto persona = x.personaName.empty() ? std::string("Unknown persona") : x.personaName;

        std::wstring details =
            L"SteamID=" + WidenUtf8Lossy(x.steamId64) +
            L" | AccountName=" + WidenUtf8Lossy(account) +
            L" | PersonaName=" + WidenUtf8Lossy(persona) +
            L" | MostRecent=" + WidenUtf8Lossy(x.mostRecent) +
            L" | Timestamp=" + WidenUtf8Lossy(x.timestamp);

        if (const auto loginLocal = FormatUnixLocal(x.timestamp); !loginLocal.empty()) {
            details += L" | LoginTimeLocal=" + loginLocal;
        }
        details += L" | UserDataSeen=" + std::wstring(x.seenInUserData ? L"1" : L"0");
        if (x.hasUserDataWrite) details += L" | UserDataWriteLocal=" + FormatFileTime(x.userDataWrite);
        if (x.hasLocalConfigWrite) details += L" | LocalConfigWriteLocal=" + FormatFileTime(x.localConfigWrite);
        if (!x.scumLastPlayed.empty()) details += L" | ScumLastPlayedLocal=" + FormatUnixLocal(x.scumLastPlayed);
        if (!x.dotaLastPlayed.empty()) details += L" | DotaLastPlayedLocal=" + FormatUnixLocal(x.dotaLastPlayed);
        if (!x.csLastPlayed.empty()) details += L" | CsLastPlayedLocal=" + FormatUnixLocal(x.csLastPlayed);

        ns::PushFinding(
            out.findings,
            L"Steam",
            L"Steam account",
            L"Found in Steam local artifacts (loginusers.vdf / userdata)",
            details,
            x.loginUsersPath.empty() ? x.userDataPath.wstring() : x.loginUsersPath.wstring(),
            NS_SEVERITY_INFO,
            x.mostRecent == "1" ? 18 : 12);

        if (x.seenInUserData || !x.scumLastPlayed.empty() || !x.dotaLastPlayed.empty() || !x.csLastPlayed.empty()) {
            std::wstring history =
                L"SteamID=" + WidenUtf8Lossy(x.steamId64) +
                L" | UserDataPath=" + x.userDataPath.wstring() +
                L" | LocalConfigWrite=" + (x.hasLocalConfigWrite ? FormatFileTime(x.localConfigWrite) : L"-") +
                L" | SCUM LastPlayed=" + (x.scumLastPlayed.empty() ? L"-" : FormatUnixLocal(x.scumLastPlayed)) +
                L" | Dota LastPlayed=" + (x.dotaLastPlayed.empty() ? L"-" : FormatUnixLocal(x.dotaLastPlayed)) +
                L" | CS LastPlayed=" + (x.csLastPlayed.empty() ? L"-" : FormatUnixLocal(x.csLastPlayed));

            ns::PushFinding(
                out.findings,
                L"Steam",
                L"Steam account history",
                L"Additional local account history artifacts found",
                history,
                x.userDataPath.wstring(),
                NS_SEVERITY_INFO,
                8);
        }
    }
}

} // namespace

namespace ns {

ModuleOutput RunSteamScanner(const RuleSet& /*rules*/) {
    ModuleOutput out;
    std::unordered_map<std::string, SteamAccountInfo> accounts;
    auto roots = GetSteamRoots();

    for (const auto& root : roots) {
        try {
            const auto loginUsers = root / "config" / "loginusers.vdf";
            if (std::filesystem::exists(loginUsers)) {
                ParseLoginUsers(loginUsers, accounts, out);
            }
            ParseUserData(root, accounts);
        } catch (...) {
            out.errors++;
        }
    }

    if (!accounts.empty()) {
        EmitAccounts(accounts, out);
        ns::PushFinding(
            out.findings,
            L"Steam",
            L"Steam accounts discovered",
            L"Detected local Steam account history",
            L"Accounts=" + std::to_wstring(accounts.size()) + L" | Roots=" + std::to_wstring(roots.size()),
            L"",
            NS_SEVERITY_INFO,
            10);
    }

    return out;
}

} // namespace ns
